"""Live MAVLink telemetry source for ``IDSPipeline.process_tick``.

Same contract as :class:`~aegisflight.sources.stream.SimulatedTelemetrySource`:
an iterator of :class:`~aegisflight.sources.stream.TelemetryTick`, here built
from real MAVLink bytes. Two entry points share one decode + bucketing core:

* :class:`LiveMavlinkSource` -- **clock-driven**, reads a transport (e.g.
  :class:`UdpMavlinkTransport`). Ticks are emitted by the wall clock even when
  the link is silent, so a drop/DoS shows up as empty ticks instead of a stall.
* :func:`frame_ticks` -- **data-driven**, any iterable of ``(recv_time, bytes)``;
  used for recorded captures and unit tests (no PX4, no sockets).

Frame decoding is *header first*
--------------------------------
sysid / compid / seq / msgid / signed-flag / lengths come from the raw MAVLink
header, never from pymavlink's decoded object: PX4 emits many messages outside
pymavlink's dialects (ids 8, 290, 291, 380, 410, 411, 514 ...) which pymavlink
reports as ``UNKNOWN_n`` with source 0/0 -- that corrupted per-source sequence
accounting (a phantom 'rogue source 0/0' in Stage 1). Unknown ids still become a
:class:`~aegisflight.core.types.MessageEnvelope` (``msgname == "MSG_<id>"``,
``fields == {}``) so link-level rate/sequence statistics stay honest. Fields of
known ids are decoded with pymavlink's ``all`` dialect; ``signed`` is the real
MAVLink-2 incompat flag bit 0. Malformed input is counted in ``bad_frames`` and
skipped; nothing here raises on wire data.

Trust level of what is accepted
-------------------------------
* **Known ids** (in pymavlink's ``all`` dialect): length + CRC are verified (crc_extra).
* **Unknown ids** have no known ``crc_extra``, so their CRC CANNOT be verified. Such a
  frame is accepted only if its header is sane (MAVLink 2, incompat flags in {0, 1},
  compat flags 0, sysid != 0, frame fits the datagram); unknown ids in MAVLink 1 are
  refused (every v1 id is in the dialect). They are counted in ``unverified_frames``
  and are **untrusted link-statistics only**: random bytes can still pass the header
  sanity checks (measured, see ``tests/unit/test_mavlink_live.py``), so never feed
  their (empty) content into a security decision. Pass ``extra_crc={msgid: crc_extra}``
  to :class:`MavlinkFrameParser` for ids whose ``crc_extra`` you can verify; those
  frames are then CRC-checked like known ids and not counted as unverified.
* One datagram yields at most ``max_frames_per_datagram`` (default 64) frame
  attempts; the unparsed remainder is counted as one ``bad_frames`` (a 64 KiB datagram
  of 12-byte frames otherwise expands into >5000 envelopes).

Tick / time semantics
---------------------
* Tick ``k`` (``t = k / sample_rate_hz``) carries every frame received in
  ``((k-1)*dt, k*dt]`` -- identical to ``external.tlog_adapter.tlog_ticks``.
  Integer-microsecond maths, so a frame exactly on a boundary belongs to the
  tick that closes at that boundary.
* **Origin** (``origin="first_frame"``, default): ``recv_time`` and tick 0 are
  rebased to the *arrival of the first received frame* (rel 0.0). This makes a
  live run reproduce ``segments()`` + ``tlog_ticks`` bit-for-bit on the same
  timestamps. Consequence: if the link never comes up, no ticks are emitted.
  ``origin="start"`` instead rebases to the moment ``stream()`` starts, so a link
  that is dead from the beginning yields empty ticks (frames stamped before the
  start are clamped to ``recv_time = 0``).
* Ticks are emitted in order and never skipped. A tick is released once the
  clock passes its end plus ``settle_s`` (absorbs the receive-thread stamp/queue
  race). A slow consumer simply gets the missed ticks back-to-back. ``late_ticks``
  increments only when a tick is emitted at least one FULL period (``dt``) after
  that tick's own close time ``k*dt`` (i.e. the clock is already past ``(k+1)*dt``);
  being late by less than one period (settle time, scheduling jitter) is not
  counted. A frame that
  reaches us after its tick closed is placed in the next open tick
  (``late_frames``); its ``recv_time`` keeps the true arrival.
* Arrival order inside a tick is preserved: no sorting, de-duplication or
  sequence repair (UDP can reorder; observed depth-2 events on PX4 SITL).

Ground truth: ``label`` / ``truth_state`` / ``integrity_truth`` / ``labels`` keep
their defaults. An *externally supplied* label may be injected via ``label_fn``.

Known gap: the Stage-1 extractor maps ``HEARTBEAT.custom_mode`` through
ArduCopter's table, so PX4 flight modes read as ``UNKNOWN`` there. Envelope
``fields`` stay raw; :func:`decode_px4_mode` is provided for calibration (Stage-2
step 4) and for reporting, not applied here.
"""

from __future__ import annotations

import ipaddress
import queue
import select
import socket
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass
from typing import Any, Literal, Protocol

from ..core.enums import AttackType
from ..core.types import MessageEnvelope
from .stream import TelemetryTick

_V1_MAGIC = 0xFE
_V2_MAGIC = 0xFD
_V2_HEADER = 10  # magic, len, incompat, compat, seq, sysid, compid, msgid[3]
_V1_HEADER = 6  # magic, len, seq, sysid, compid, msgid
_CRC = 2
_SIGNATURE = 13
_INCOMPAT_SIGNED = 0x01

# --------------------------------------------------------------------------- #
# PX4 flight modes (px4_custom_mode.h): HEARTBEAT.custom_mode bytes 2 / 3
# --------------------------------------------------------------------------- #

PX4_MAIN_MODES = {1: "MANUAL", 2: "ALTCTL", 3: "POSCTL", 4: "AUTO", 5: "ACRO", 6: "OFFBOARD",
                  7: "STABILIZED", 8: "RATTITUDE"}
PX4_AUTO_SUBMODES = {1: "READY", 2: "TAKEOFF", 3: "LOITER", 4: "MISSION", 5: "RTL", 6: "LAND",
                     7: "RTGS", 8: "FOLLOW_TARGET", 9: "PRECLAND", 10: "VTOL_TAKEOFF"}


def decode_px4_mode(custom_mode: int) -> str:
    """PX4 ``custom_mode`` (``main<<16 | sub<<24``) -> e.g. ``"POSCTL"``, ``"AUTO/LOITER"``."""
    main = (custom_mode >> 16) & 0xFF
    sub = (custom_mode >> 24) & 0xFF
    name = PX4_MAIN_MODES.get(main, f"MAIN_{main}")
    return f"{name}/{PX4_AUTO_SUBMODES.get(sub, sub)}" if main == 4 else name


# --------------------------------------------------------------------------- #
# stats
# --------------------------------------------------------------------------- #


@dataclass
class LiveStats:
    datagrams_received: int = 0  # datagrams / buffers handed to the parser
    frames_received: int = 0  # frames that became an envelope
    # truncated / garbage / header-insane / CRC-failed (known ids and ids covered by
    # ``extra_crc`` only) / per-datagram frame cap exceeded (skipped)
    bad_frames: int = 0
    # cryptographic signature outcome -- ONLY incremented when the parser is constructed
    # with ``secret_key`` (see ``MavlinkFrameParser``); both stay 0 otherwise, including for
    # every frame that merely carries the MAVLink2 "signed" incompat bit with no key
    # configured (that bit alone is NOT verified and is tracked separately as
    # ``MessageEnvelope.signed`` -- a frozen field kept at its existing, bit-only meaning).
    sig_valid: int = 0  # claimed-signed frame whose HMAC checked out against the key
    sig_invalid: int = 0  # a signing-policy violation: wrong/missing HMAC, a stale/replayed
    # timestamp, or an unsigned frame not on the unsigned-allowed list (each counted as a bad
    # frame too -- fail closed, same convention as a CRC failure)
    # frames of ids unknown to the dialect accepted on header sanity ALONE: their CRC was
    # NOT verified (no crc_extra), so they are untrusted link statistics (see module doc)
    unverified_frames: int = 0
    ticks_emitted: int = 0
    # ticks emitted >= one full period (dt) after their own close time k*dt; lateness of
    # less than one period is not counted
    late_ticks: int = 0
    late_frames: int = 0  # frames that reached us after their tick closed
    dropped_overflow: int = 0  # datagrams dropped by the bounded transport queue
    dropped_overflow_bytes: int = 0  # ... and their total size

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# header-first frame parser
# --------------------------------------------------------------------------- #


def _x25(data: bytes, crc: int = 0xFFFF) -> int:
    """MAVLink X.25 / MCRF4XX CRC; chain calls to append ``crc_extra``."""
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def _load_dialect() -> Any:
    try:
        from pymavlink.dialects.v20 import all as dialect
    except Exception:  # noqa: BLE001 - fall back to the smaller dialect
        from pymavlink.dialects.v20 import common as dialect
    return dialect


#: Message ids PX4's own ``MavlinkSignControl::accept_unsigned`` lets through unsigned even once
#: signing is active (``mavlink_sign_control.cpp``, read-only scoping) -- mirrored here so a
#: verifying parser's notion of "should be signed" matches what PX4 itself actually enforces.
PX4_UNSIGNED_ALLOWED_MSGIDS: frozenset[int] = frozenset({0, 109, 246, 247})  # HEARTBEAT, RADIO_STATUS,
# ADSB_VEHICLE, COLLISION


class MavlinkFrameParser:
    """Raw bytes -> ``MessageEnvelope`` list, header-first (see module docstring).

    ``secret_key``: optional, default ``None`` -- with no key, behaviour is byte-for-byte
    identical to before this parameter existed (``MessageEnvelope.signed`` keeps its existing,
    bit-only meaning; ``LiveStats.sig_valid``/``sig_invalid`` stay 0). Supplying a 32-byte
    MAVLink-2 signing secret turns on REAL cryptographic verification (HMAC-SHA256 over the
    frame, truncated to 6 bytes, exactly the algorithm `pymavlink`'s own
    ``MAVLink.check_signature`` implements and PX4 uses) of every claimed-signed frame via
    `pymavlink`'s own `decode()` signing path, rather than trusting the incompat bit alone. A
    frame id in ``unsigned_allowed_msgids`` (default :data:`PX4_UNSIGNED_ALLOWED_MSGIDS`) is
    accepted even if unsigned, matching PX4's own allowlist, so this changes nothing about
    which frames are *parseable* -- only whether a signature claim is actually checked. A
    claimed signature that fails verification is counted (``sig_invalid``) and the frame is
    dropped (``bad_frames``), the same fail-closed treatment as a CRC failure; this parser
    never raises either way.
    """

    def __init__(self, stats: LiveStats | None = None, *,
                 extra_crc: dict[int, int] | None = None,
                 max_frames_per_datagram: int = 64,
                 secret_key: bytes | None = None,
                 unsigned_allowed_msgids: frozenset[int] = PX4_UNSIGNED_ALLOWED_MSGIDS) -> None:
        if max_frames_per_datagram < 1:
            raise ValueError("max_frames_per_datagram must be >= 1")
        if secret_key is not None and len(secret_key) != 32:
            raise ValueError("secret_key must be exactly 32 bytes (MAVLink 2 signing key length)")
        self.stats = stats if stats is not None else LiveStats()
        self.max_frames_per_datagram = max_frames_per_datagram
        dialect = _load_dialect()
        self._map = dialect.mavlink_map
        # crc_extra for ids the dialect does not know (never overrides a known id)
        self._extra_crc = {k: v & 0xFF for k, v in (extra_crc or {}).items()
                           if k not in self._map}
        self._mav = dialect.MAVLink(None)
        self._mav.robust_parsing = True
        self._mav_error = dialect.MAVError
        self._verify = secret_key is not None
        if self._verify:
            self._mav.signing.secret_key = secret_key
            self._mav.signing.allow_unsigned_callback = (
                lambda _mav, msgid: msgid in unsigned_allowed_msgids
            )

    def parse(self, data: bytes, recv_time: float) -> list[MessageEnvelope]:
        """Parse the frames in ``data`` (one datagram may hold several). Never raises.

        At most ``max_frames_per_datagram`` frame attempts are made; the remainder is
        counted as one bad frame.
        """
        st = self.stats
        st.datagrams_received += 1
        out: list[MessageEnvelope] = []
        n = len(data)
        i = 0
        attempts = 0
        while i < n:
            if attempts >= self.max_frames_per_datagram:
                st.bad_frames += 1  # frame cap: refuse to expand one datagram without bound
                break
            attempts += 1
            magic = data[i]
            if magic == _V2_MAGIC:
                if n - i < _V2_HEADER:
                    st.bad_frames += 1  # truncated header
                    break
                ln, inc = data[i + 1], data[i + 2]
                if inc & ~_INCOMPAT_SIGNED & 0xFF:
                    st.bad_frames += 1  # unknown incompat flags: spec says drop
                    i += 1
                    continue
                total = _V2_HEADER + ln + _CRC + (_SIGNATURE if inc & _INCOMPAT_SIGNED else 0)
                if i + total > n:
                    st.bad_frames += 1  # truncated body
                    break
                seq, sysid, compid = data[i + 4], data[i + 5], data[i + 6]
                msgid = data[i + 7] | data[i + 8] << 8 | data[i + 9] << 16
                signed = bool(inc & _INCOMPAT_SIGNED)
                v2, compat, hdr = True, data[i + 3], _V2_HEADER
            elif magic == _V1_MAGIC:
                if n - i < _V1_HEADER:
                    st.bad_frames += 1
                    break
                total = _V1_HEADER + data[i + 1] + _CRC
                if i + total > n:
                    st.bad_frames += 1
                    break
                seq, sysid, compid, msgid = data[i + 2], data[i + 3], data[i + 4], data[i + 5]
                signed = False
                v2, compat, hdr = False, 0, _V1_HEADER
            else:
                j = i + 1  # garbage: resync on the next magic byte, count one bad run
                while j < n and data[j] not in (_V1_MAGIC, _V2_MAGIC):
                    j += 1
                st.bad_frames += 1
                i = j
                continue

            frame = data[i : i + total]
            i += total
            cls = self._map.get(msgid)
            if cls is None:
                extra = self._extra_crc.get(msgid)
                if extra is not None:
                    # crc_extra supplied by the caller: verify like a known id
                    body_end = hdr + frame[1]
                    if _x25(bytes([extra]), _x25(frame[1:body_end])) != int.from_bytes(
                            frame[body_end : body_end + _CRC], "little"):
                        st.bad_frames += 1
                        continue
                elif v2 and compat == 0 and sysid != 0:
                    st.unverified_frames += 1  # header sanity only: CRC NOT verified
                else:
                    st.bad_frames += 1  # v1 unknown id / compat flags set / sysid 0
                    continue
                name, fields = f"MSG_{msgid}", {}
            else:
                try:
                    msg = self._mav.decode(bytearray(frame))
                    fields = msg.to_dict()
                    fields.pop("mavpackettype", None)
                    name = getattr(cls, "msgname", None) or msg.get_type()
                    if self._verify and signed:
                        st.sig_valid += 1  # decode() above already raised if the HMAC did not match
                except self._mav_error as exc:
                    if self._verify and str(exc) == "Invalid signature":
                        st.sig_invalid += 1
                    st.bad_frames += 1  # CRC/length mismatch, or (with a key) a bad/rejected signature
                    continue
                except Exception:  # noqa: BLE001 - any other decode failure on a known id
                    st.bad_frames += 1
                    continue
            st.frames_received += 1
            out.append(MessageEnvelope(recv_time=recv_time, sysid=sysid, compid=compid,
                                       msgid=msgid, msgname=name, seq=seq, signed=signed,
                                       byte_len=total, fields=fields))
        return out


# --------------------------------------------------------------------------- #
# tick assembly (shared by the clock-driven and data-driven paths)
# --------------------------------------------------------------------------- #


class _TickAssembler:
    def __init__(self, sample_rate_hz: float, label_fn: Callable[[float], AttackType] | None,
                 stats: LiveStats, origin_us: int | None = None) -> None:
        if sample_rate_hz <= 0:
            raise ValueError("sample_rate_hz must be > 0")
        self.dt = 1.0 / sample_rate_hz
        self.dt_us = max(1, round(1e6 / sample_rate_hz))
        self.label_fn = label_fn or (lambda _t: AttackType.BENIGN)
        self.stats = stats
        self.parser = MavlinkFrameParser(stats)
        self.origin_us = origin_us
        self.next_k = 0
        self._pending: dict[int, list[MessageEnvelope]] = {}
        self.max_k = -1

    def ingest(self, recv_us: int, data: bytes) -> int | None:
        """Parse and bucket one datagram; return the tick index it landed in."""
        if self.origin_us is None:
            self.origin_us = recv_us
        rel_us = max(0, recv_us - self.origin_us)  # frames stamped before the origin clamp to 0
        envs = self.parser.parse(data, rel_us / 1e6)
        if not envs:
            return None
        k = -(-rel_us // self.dt_us)  # ceil: (k-1)dt < rel <= k*dt
        if k < self.next_k:
            k = self.next_k
            self.stats.late_frames += len(envs)
        self._pending.setdefault(k, []).extend(envs)
        self.max_k = max(self.max_k, k)
        return k

    def pop_next(self, k_limit: int, now_rel_us: int | None = None) -> TelemetryTick | None:
        """Emit tick ``next_k`` if ``next_k <= k_limit``."""
        k = self.next_k
        if k > k_limit:
            return None
        self.next_k = k + 1
        self.stats.ticks_emitted += 1
        if now_rel_us is not None and now_rel_us >= (k + 1) * self.dt_us:
            self.stats.late_ticks += 1
        t = k * self.dt
        return TelemetryTick(t=t, tick=k, messages=self._pending.pop(k, []), label=self.label_fn(t))


def frame_ticks(
    frames: Iterable[tuple[float, bytes]],
    sample_rate_hz: float = 10.0,
    label_fn: Callable[[float], AttackType] | None = None,
    origin_s: float | None = None,
    stats: LiveStats | None = None,
) -> Iterator[TelemetryTick]:
    """Data-driven ticks from ``(recv_time_s, datagram_bytes)`` pairs (arrival order).

    ``origin_s`` None -> rebase to the first frame. Gaps in the timestamps produce
    empty ticks; the final tick is the one holding the last frame.
    """
    asm = _TickAssembler(sample_rate_hz, label_fn, stats if stats is not None else LiveStats(),
                         None if origin_s is None else round(origin_s * 1e6))
    for recv_s, data in frames:
        k = asm.ingest(round(recv_s * 1e6), data)
        if k is not None:
            while (tick := asm.pop_next(k - 1)) is not None:
                yield tick
    while (tick := asm.pop_next(asm.max_k)) is not None:
        yield tick


# --------------------------------------------------------------------------- #
# transports
# --------------------------------------------------------------------------- #


class FrameTransport(Protocol):
    """Anything that hands over ``(recv_ns, datagram)`` pairs, stamped on arrival."""

    def poll(self) -> list[tuple[int, bytes]]: ...

    def close(self) -> None: ...


def _loopback_only(host: str | None, allow_wildcard: bool) -> str:
    """Validate a *bind* host: loopback only unless ``allow_wildcard`` (= allow non-loopback).

    Accepts None (-> 127.0.0.1), ``localhost`` (-> 127.0.0.1) and any literal loopback
    address (127.0.0.0/8, ``::1``). Everything else -- wildcards, LAN / WSL-NAT
    addresses, hostnames -- needs ``allow_wildcard=True`` (explicit user approval).
    """
    if host is None:
        return "127.0.0.1"
    if allow_wildcard:
        return host
    if host.lower() == "localhost":
        return "127.0.0.1"
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise ValueError(f"refusing to bind to non-loopback address {host!r}; bind mode is "
                         "loopback-only unless allow_wildcard=True (needs explicit approval)")
    return host


def _family(host: str) -> socket.AddressFamily:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


class UdpMavlinkTransport:
    """Non-blocking UDP socket + receive thread + bounded queue.

    ``connect=(host, port)``: GCS role. The socket is *connected* (kernel binds the
    right local interface and drops datagrams from other peers) and a GCS HEARTBEAT
    (sysid 255, compid 190, ``MAV_TYPE_GCS``) is sent immediately and at
    ``heartbeat_hz`` -- PX4 learns our address from the first datagram and only
    then streams / accepts commands. The target is deliberately **unrestricted**:
    it is how we reach PX4 inside WSL over its NAT address (never hard-code it).

    ``bind=(host, port)``: listen. Only loopback addresses are accepted (``host`` None
    -> 127.0.0.1; see :func:`_loopback_only`) unless ``allow_wildcard=True``, which
    now means "allow a non-loopback bind" and needs explicit user approval.
    Heartbeats are off by default in this mode (``gcs_heartbeat=True`` sends them to
    the peer). With ``pin_peer=True`` (default) the peer is the FIRST sender; later
    senders cannot steer our replies and their datagrams are dropped
    (``dropped_foreign``), mirroring the kernel filter of connect mode. With
    ``pin_peer=False`` the peer follows the last sender (only use on a trusted link).

    The queue is bounded by datagram count (``queue_size``) AND by total bytes
    (``max_queue_bytes``, default 8 MiB); both overflows are counted in
    ``dropped_overflow`` / ``dropped_overflow_bytes``.

    Datagrams are stamped with ``clock_ns()`` the moment ``recvfrom`` returns.
    """

    def __init__(
        self,
        *,
        connect: tuple[str, int] | None = None,
        bind: tuple[str | None, int] | None = None,
        queue_size: int = 16384,
        rcvbuf_bytes: int = 4 * 1024 * 1024,
        gcs_heartbeat: bool | None = None,
        heartbeat_hz: float = 1.0,
        gcs_sysid: int = 255,
        gcs_compid: int = 190,
        allow_wildcard: bool = False,
        pin_peer: bool = True,
        max_queue_bytes: int = 8 * 1024 * 1024,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        sign_secret_key: bytes | None = None,
        sign_link_id: int = 0,
        sign_initial_timestamp: int = 0,
    ) -> None:
        if (connect is None) == (bind is None):
            raise ValueError("give exactly one of connect=(host, port) or bind=(host, port)")
        if max_queue_bytes < 1:
            raise ValueError("max_queue_bytes must be >= 1")
        if sign_secret_key is not None and len(sign_secret_key) != 32:
            raise ValueError("sign_secret_key must be exactly 32 bytes (MAVLink 2 signing key length)")
        # outgoing signing (opt-in; None = every message this transport sends is unsigned, the
        # existing, unchanged default). Persisted here, not on a per-call MAVLink encoder object,
        # because the MAVLink-2 signing timestamp must strictly advance across this transport's
        # whole lifetime (pymavlink's own ``sign_packet`` auto-increments it by 1 per signed
        # message -- see ``send_gcs_message``) for a verifier's anti-replay check to accept it.
        self._sign_key = sign_secret_key
        self._sign_link_id = sign_link_id
        self._sign_timestamp = sign_initial_timestamp
        self._clock_ns = clock_ns
        self._q: queue.Queue[tuple[int, bytes]] = queue.Queue(maxsize=queue_size)
        self._max_bytes = max_queue_bytes
        self._queued_bytes = 0
        self._bytes_lock = threading.Lock()
        self._pin_peer = pin_peer
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._closed = False
        self._peer: tuple[str, int] | None = None
        self._lock = threading.Lock()
        self.datagrams_received = 0
        self.dropped_overflow = 0
        self.dropped_overflow_bytes = 0
        self.dropped_foreign = 0
        self.heartbeats_sent = 0
        self.recv_errors = 0
        self.last_error: str | None = None
        self._hb_enabled = gcs_heartbeat if gcs_heartbeat is not None else connect is not None
        self._hb_period = 1.0 / heartbeat_hz if heartbeat_hz > 0 else 0.0
        self._hb_seq = 0
        self._gcs = (gcs_sysid, gcs_compid)

        bind_host = ""
        if bind is not None:
            bind_host = _loopback_only(bind[0], allow_wildcard)  # refuse BEFORE any socket
        sock = socket.socket(_family(connect[0] if connect is not None else bind_host),
                             socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf_bytes)
            if connect is not None:
                sock.connect(connect)
                self._target: tuple[str, int] | None = connect
            else:
                assert bind is not None
                sock.bind((bind_host, bind[1]))
                self._target = None
            sock.setblocking(False)
        except BaseException:
            sock.close()
            raise
        self._sock = sock

    # -- lifecycle ---------------------------------------------------------- #

    @property
    def local_address(self) -> tuple[str, int]:
        return self._sock.getsockname()

    def start(self) -> None:
        if self._threads or self._closed:
            return
        self._threads.append(threading.Thread(target=self._rx_loop, name="mavlink-rx", daemon=True))
        if self._hb_enabled and self._hb_period > 0:
            self._threads.append(threading.Thread(target=self._hb_loop, name="mavlink-hb",
                                                  daemon=True))
        for th in self._threads:
            th.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        for th in self._threads:
            th.join(timeout=2.0)
        try:
            self._sock.close()
        except OSError:
            pass
        self.poll()  # drain (and release the byte budget)

    def __enter__(self) -> UdpMavlinkTransport:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- data path ---------------------------------------------------------- #

    @property
    def peer_address(self) -> tuple[str, int] | None:
        """Where :meth:`send` goes: connect target, or the bind-mode peer (pinned/last)."""
        return self._target or self._peer

    def poll(self) -> list[tuple[int, bytes]]:
        out: list[tuple[int, bytes]] = []
        while True:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        if out:
            with self._bytes_lock:
                self._queued_bytes -= sum(len(d) for _, d in out)
        return out

    def _enqueue(self, stamp: int, data: bytes) -> None:
        with self._bytes_lock:
            if self._queued_bytes + len(data) <= self._max_bytes:
                try:
                    self._q.put_nowait((stamp, data))
                    self._queued_bytes += len(data)
                    return
                except queue.Full:
                    pass
            self.dropped_overflow += 1
            self.dropped_overflow_bytes += len(data)

    def send(self, data: bytes) -> bool:
        """Send to the peer (connect target, or the pinned / last peer in bind mode)."""
        target = self._target or self._peer
        if target is None or self._closed:
            return False
        try:
            if self._target is not None:
                self._sock.send(data)
            else:
                self._sock.sendto(data, target)
            return True
        except OSError as exc:  # includes BlockingIOError (send buffer full)
            self.last_error = repr(exc)
            return False

    def send_gcs_message(self, encode: Callable[[Any], Any]) -> tuple[bool, int]:
        """Pack and send one GCS-originated message, stamped with this transport's own running
        MAVLink sequence counter (the one its heartbeats use), so a scripted command is
        indistinguishable on the wire from a real GCS's: ``encode`` receives a
        ``pymavlink`` ``MAVLink`` object and returns the encoded message (e.g.
        ``lambda m: m.command_long_encode(...)``). Returns ``(sent, seq_used)``.

        If this transport was constructed with ``sign_secret_key``, the message is signed
        (MAVLink 2 signing, real HMAC-SHA256 -- see ``MavlinkFrameParser``'s verification side)
        with a timestamp that strictly advances across every call this transport ever makes;
        otherwise behaviour is unchanged (unsigned, as before this parameter existed)."""
        from pymavlink.dialects.v20 import common as mav

        with self._lock:
            m = mav.MAVLink(None, srcSystem=self._gcs[0], srcComponent=self._gcs[1])
            seq = self._hb_seq
            m.seq = seq
            self._hb_seq = (seq + 1) % 256
            if self._sign_key is not None:
                m.signing.secret_key = self._sign_key
                m.signing.sign_outgoing = True
                m.signing.link_id = self._sign_link_id
                m.signing.timestamp = self._sign_timestamp
            packed = bytes(encode(m).pack(m))
            if self._sign_key is not None:
                self._sign_timestamp = m.signing.timestamp  # advanced by one inside pack()/sign_packet()
            return self.send(packed), seq

    def enable_signing(self, secret_key: bytes, *, link_id: int = 0, initial_timestamp: int = 0) -> None:
        """Turn on signing for every message this transport sends from now on (see
        ``send_gcs_message``). Meant to be called AFTER a bootstrap ``SETUP_SIGNING`` message
        has been sent unsigned (see :func:`send_setup_signing`) -- this method only changes
        what THIS transport does when sending; it does not talk to the peer."""
        if len(secret_key) != 32:
            raise ValueError("secret_key must be exactly 32 bytes (MAVLink 2 signing key length)")
        with self._lock:
            self._sign_key = secret_key
            self._sign_link_id = link_id
            self._sign_timestamp = initial_timestamp

    def send_heartbeat(self) -> bool:
        from pymavlink.dialects.v20 import common as mav

        ok, _ = self.send_gcs_message(lambda m: m.heartbeat_encode(
            mav.MAV_TYPE_GCS, mav.MAV_AUTOPILOT_INVALID, 0, 0, mav.MAV_STATE_ACTIVE))
        self.heartbeats_sent += ok
        return ok

    def _hb_loop(self) -> None:
        while not self._stop.is_set():
            self.send_heartbeat()
            self._stop.wait(self._hb_period)

    def _rx_loop(self) -> None:
        sock = self._sock
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([sock], [], [], 0.1)
            except (OSError, ValueError):
                return  # socket closed under us
            if not ready:
                continue
            for _ in range(512):
                try:
                    data, addr = sock.recvfrom(65535)
                except BlockingIOError:
                    break
                except (ConnectionResetError, ConnectionRefusedError):
                    self.recv_errors += 1  # ICMP port-unreachable from an earlier send
                    continue
                except OSError as exc:
                    self.recv_errors += 1
                    self.last_error = repr(exc)
                    self._stop.wait(0.01)
                    break
                stamp = self._clock_ns()
                self.datagrams_received += 1
                if self._target is None:
                    if self._peer is None or not self._pin_peer:
                        self._peer = addr
                    elif addr != self._peer:
                        self.dropped_foreign += 1  # pinned: a later sender cannot steer us
                        continue
                self._enqueue(stamp, data)


def send_setup_signing(transport: UdpMavlinkTransport, target_sysid: int, target_compid: int,
                       secret_key: bytes, *, initial_timestamp: int = 0) -> tuple[bool, int]:
    """Bootstrap MAVLink 2 signing on a link: send ONE unsigned ``SETUP_SIGNING`` command to
    ``(target_sysid, target_compid)`` (PX4's own ``MavlinkSignControl::check_for_signing``,
    scoped read-only from ``mavlink_sign_control.cpp``) carrying ``secret_key`` and
    ``initial_timestamp``. Sent unsigned because, before this call, no key exists yet for
    either side to sign with -- PX4 accepts the FIRST ``SETUP_SIGNING`` it receives for a
    non-blank key unconditionally (it does not need to already be signed; only a later
    *disable* -- a blank key -- must be signed with the key being disabled). This is a
    "trust on first contact" bootstrap, not a hardened handshake: whichever client reaches
    PX4 first with this message wins control of the key. Does NOT call
    ``transport.enable_signing`` itself -- the caller does that afterwards, once, so the
    order (and hence which messages go out signed) is explicit at the call site. PX4 also
    rejects any ``SETUP_SIGNING`` while the vehicle is armed (``mavlink_main.cpp``).
    Returns ``(sent, seq_used)`` exactly like :meth:`UdpMavlinkTransport.send_gcs_message`."""
    return transport.send_gcs_message(lambda m: m.setup_signing_encode(
        target_sysid, target_compid, secret_key, initial_timestamp))


# --------------------------------------------------------------------------- #
# clock-driven source
# --------------------------------------------------------------------------- #


class LiveMavlinkSource:
    """Clock-driven ``TelemetryTick`` stream over a :class:`FrameTransport`.

    ``clock_ns`` must be the same clock the transport stamps with (default
    ``time.monotonic_ns`` for both). ``sleep`` / ``clock_ns`` are injectable so
    tests run without real time.
    """

    def __init__(
        self,
        transport: FrameTransport,
        sample_rate_hz: float = 10.0,
        label_fn: Callable[[float], AttackType] | None = None,
        *,
        origin: Literal["first_frame", "start"] = "first_frame",
        settle_s: float = 0.005,
        max_ticks: int | None = None,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        sleep: Callable[[float], None] = time.sleep,
        max_sleep_s: float = 0.05,
    ) -> None:
        if origin not in ("first_frame", "start"):
            raise ValueError("origin must be 'first_frame' or 'start'")
        self.transport = transport
        self._stats = LiveStats()
        self._asm = _TickAssembler(sample_rate_hz, label_fn, self._stats)
        self._origin_mode = origin
        self._settle_us = round(settle_s * 1e6)
        self._max_ticks = max_ticks
        self._clock_ns = clock_ns
        self._sleep = sleep
        self._max_sleep = max_sleep_s
        self._stop = threading.Event()

    @property
    def stats(self) -> dict[str, int]:
        d = self._stats.as_dict()
        d["dropped_overflow"] = int(getattr(self.transport, "dropped_overflow", 0))
        d["dropped_overflow_bytes"] = int(getattr(self.transport, "dropped_overflow_bytes", 0))
        return d

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        self.stop()
        self.transport.close()

    def stream(self) -> Iterator[TelemetryTick]:
        asm, dt_us = self._asm, self._asm.dt_us
        start = getattr(self.transport, "start", None)
        if callable(start):
            start()
        if self._origin_mode == "start" and asm.origin_us is None:
            asm.origin_us = self._clock_ns() // 1000
        while not self._stop.is_set():
            if self._max_ticks is not None and self._stats.ticks_emitted >= self._max_ticks:
                return
            now_us = self._clock_ns() // 1000  # read BEFORE draining (see settle_s)
            for recv_ns, data in self.transport.poll():
                asm.ingest(recv_ns // 1000, data)
            if asm.origin_us is None:
                self._sleep(min(0.005, self._max_sleep))  # link not up yet
                continue
            now_rel = now_us - asm.origin_us
            k_done = (now_rel - self._settle_us) // dt_us
            tick = asm.pop_next(k_done, now_rel)
            if tick is not None:
                yield tick
                continue
            wait_us = asm.next_k * dt_us + self._settle_us - now_rel
            self._sleep(min(self._max_sleep, max(wait_us, 1000) / 1e6))
