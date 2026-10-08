"""Bidirectional UDP MAVLink relay (transport only) for the live attack proxy.

::

    PX4 SITL  <--UDP-->  [upstream leg]  MavlinkRelay  [downstream leg]  <--UDP-->  clients
              (connect, GCS role)         down_hook / up_hook          (loopback bind)  IDS, driver

This module owns sockets, framing, forwarding order and timestamps. It knows
nothing about attacks: per-frame behaviour is plugged in through two hooks of the
FIXED interface in :mod:`aegisflight.proxy.hooks` (``FrameHook``; default
``passthrough``). Ownership: transport = aegis-px4-mavlink; attack logic =
aegis-security (see ``docs/ATTACK_PROXY.md`` s5/s7).

Behaviour
---------
* **Upstream** (``UdpMavlinkTransport(connect=(px4_host, px4_port), gcs_heartbeat=True)``).
  PX4 locks its GCS link to the FIRST sender and never re-learns, so :meth:`MavlinkRelay.start`
  sends the proxy's own GCS heartbeat synchronously *before* the receive thread, the
  periodic heartbeat thread or the downstream socket exist (fail closed: it raises if that
  first heartbeat cannot be sent). Client frames then leave through the same connected
  socket, i.e. from the same source address PX4 locked to. The upstream address is an
  explicit argument -- no discovery, no hard-coded host.
  :meth:`MavlinkRelay.wait_upstream_alive` blocks until a valid frame from PX4 arrived.
* **Downstream**: a loopback-only UDP bind (default 127.0.0.1; never ``0.0.0.0``). A client
  is learned from its first datagram that contains at least one well-framed MAVLink
  frame; at most ``max_clients`` (default 4) are kept, only loopback sources are accepted,
  and an idle client (``client_timeout_s``, default 30 s) is evicted to make room.
  Downlink frames are FANNED OUT to every learned client; every client datagram goes
  upstream. The down hook runs ONCE per downlink frame (not once per client).
* **Uplink mirroring** (``mirror_uplink_to_clients``, default ``False``): a plain network
  relay correctly never echoes a client's own traffic back to other clients, and that
  stays the default. But a live SITL trial found that with the default behaviour a
  downstream IDS tap has ZERO visibility into uplink traffic -- including anything an
  ``up_hook`` injects toward PX4 (e.g. a rogue ``COMMAND_LONG``) -- because ``_handle_up``
  only ever sends the hook's output to ``self.upstream``. Setting this flag makes the
  relay behave like a real bump-in-the-wire tap on a single physical link: the SAME
  frames the up hook decided to send upstream are ALSO fanned out to the learned clients,
  counted separately in ``mirrored_up``: an UNMODIFIED original frame goes to every client
  except its sender (no self-echo); a frame the hook created or modified (e.g. an injected
  ``COMMAND_LONG`` riding on a client's heartbeat) goes to EVERY client, the carrier's
  sender included, since the sender did not author it as it appears on the wire. This is opt-in and purely additive: it changes nothing when left at
  its default, so the already-reviewed downlink-attack results stay byte-for-byte
  reproducible.
* **Framing**: each datagram is split header-first into single frames (v1 ``0xFE`` /
  v2 ``0xFD``, signed v2 = +13 B). One :class:`FrameContext` per frame goes through the hook;
  the frames the hook returns are forwarded IN ORDER, one datagram per frame (no
  re-batching, so a hook can reorder/duplicate/inject deterministically). CRC is not
  verified (transparent relay); a hook that rewrites a frame must recompute it.
  Bytes that cannot be framed (garbage, truncated tail, unknown incompat flags) are DROPPED
  and counted in ``bad_segments`` -- nothing bypasses the hooks. At most
  ``max_frames_per_datagram`` (default 64) frames are taken from one datagram.
* **Pass-through is byte-identical and order-preserving** (tested).
* **Hook failure never kills the relay**: a hook that raises (or returns something that
  is not ``list[bytes]``) -> the original frame is forwarded, ``hook_errors`` is incremented
  and the first error per direction is logged with its traceback.
* Everything is polled by one pump thread (daemon). :meth:`MavlinkRelay.pump_once` runs one
  non-blocking cycle so tests can drive the relay with fake links, no sockets or threads.

Out of scope here (propose, don't build): a fixed upstream local port so a restarted proxy
keeps PX4's lock (needs a bind option on the upstream transport), signing, injection API.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import queue
import select
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from ..sources.mavlink_live import UdpMavlinkTransport, _family, _loopback_only
from .hooks import Direction, FrameContext, FrameHook, passthrough

log = logging.getLogger(__name__)

_V2, _V1 = 0xFD, 0xFE
_MAX_DATAGRAM = 65507
_MAX_HOOK_FRAMES = 64

Address = tuple[Any, ...]  # (host, port) for IPv4; longer for IPv6


# --------------------------------------------------------------------------- #
# framing
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Frame:
    raw: bytes
    sysid: int
    compid: int
    seq: int
    msgid: int
    signed: bool


def _resync(data: bytes, start: int) -> int:
    n = len(data)
    while start < n and data[start] not in (_V1, _V2):
        start += 1
    return start


def split_frames(data: bytes, max_frames: int = 64) -> tuple[list[_Frame], int]:
    """Split one datagram into whole frames. Returns ``(frames, bad_segments)``.

    Header-first (length from the header, signature included); never raises. Garbage is
    skipped up to the next magic byte (one bad segment per run); a truncated tail or the
    frames beyond ``max_frames`` count as one bad segment each and end the scan.
    """
    frames: list[_Frame] = []
    bad = 0
    n = len(data)
    i = 0
    while i < n:
        if len(frames) >= max_frames:
            bad += 1
            break
        magic = data[i]
        if magic == _V2:
            if n - i < 10:
                bad += 1
                break
            ln, inc = data[i + 1], data[i + 2]
            if inc & 0xFE:  # unknown incompat flags: the spec says drop
                bad += 1
                i = _resync(data, i + 1)
                continue
            total = 12 + ln + (13 if inc & 1 else 0)
            if i + total > n:
                bad += 1
                break
            frames.append(_Frame(bytes(data[i : i + total]), data[i + 5], data[i + 6], data[i + 4],
                                 data[i + 7] | data[i + 8] << 8 | data[i + 9] << 16,
                                 bool(inc & 1)))
        elif magic == _V1:
            if n - i < 6:
                bad += 1
                break
            total = 8 + data[i + 1]
            if i + total > n:
                bad += 1
                break
            frames.append(_Frame(bytes(data[i : i + total]), data[i + 3], data[i + 4], data[i + 2],
                                 data[i + 5], False))
        else:
            bad += 1
            i = _resync(data, i + 1)
            continue
        i += total
    return frames, bad


# --------------------------------------------------------------------------- #
# link seams
# --------------------------------------------------------------------------- #


class UpstreamLink(Protocol):
    """PX4 side. ``UdpMavlinkTransport(connect=..., gcs_heartbeat=True)`` satisfies it."""

    dropped_overflow: int

    def start(self) -> None: ...

    def poll(self) -> list[tuple[int, bytes]]: ...

    def send(self, data: bytes) -> bool: ...

    def send_heartbeat(self) -> bool: ...

    def close(self) -> None: ...


class DownstreamLink(Protocol):
    """Client side: datagrams carry their sender address."""

    dropped_overflow: int

    def start(self) -> None: ...

    def poll(self) -> list[tuple[int, Address, bytes]]: ...

    def sendto(self, data: bytes, addr: Address) -> bool: ...

    def close(self) -> None: ...


class UdpDownstream:
    """Loopback UDP bind + receive thread + queue bounded by count and bytes."""

    def __init__(
        self,
        bind: tuple[str | None, int] = (None, 0),
        *,
        queue_size: int = 4096,
        max_queue_bytes: int = 4 * 1024 * 1024,
        rcvbuf_bytes: int = 1024 * 1024,
        allow_wildcard: bool = False,
        clock_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        host = _loopback_only(bind[0], allow_wildcard)  # raises before any socket exists
        self._clock_ns = clock_ns
        self._q: queue.Queue[tuple[int, Address, bytes]] = queue.Queue(maxsize=queue_size)
        self._max_bytes = max_queue_bytes
        self._queued_bytes = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False
        self.dropped_overflow = 0
        self.dropped_overflow_bytes = 0
        self.recv_errors = 0
        sock = socket.socket(_family(host), socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf_bytes)
            sock.bind((host, bind[1]))
            sock.setblocking(False)
        except BaseException:
            sock.close()
            raise
        self._sock = sock

    @property
    def local_address(self) -> tuple[str, int]:
        return self._sock.getsockname()[:2]

    def start(self) -> None:
        if self._thread is not None or self._closed:
            return
        self._thread = threading.Thread(target=self._rx_loop, name="relay-down-rx", daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        try:
            self._sock.close()
        except OSError:
            pass
        self.poll()

    def poll(self) -> list[tuple[int, Address, bytes]]:
        out: list[tuple[int, Address, bytes]] = []
        while True:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        if out:
            with self._lock:
                self._queued_bytes -= sum(len(d) for _, _, d in out)
        return out

    def sendto(self, data: bytes, addr: Address) -> bool:
        if self._closed:
            return False
        try:
            self._sock.sendto(data, addr)
            return True
        except OSError:  # includes BlockingIOError (send buffer full)
            return False

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
                    self.recv_errors += 1  # ICMP unreachable from an earlier send to a dead client
                    continue
                except OSError:
                    self.recv_errors += 1
                    self._stop.wait(0.01)
                    break
                stamp = self._clock_ns()
                with self._lock:
                    if self._queued_bytes + len(data) <= self._max_bytes:
                        try:
                            self._q.put_nowait((stamp, addr, data))
                            self._queued_bytes += len(data)
                            continue
                        except queue.Full:
                            pass
                    self.dropped_overflow += 1
                    self.dropped_overflow_bytes += len(data)


# --------------------------------------------------------------------------- #
# relay
# --------------------------------------------------------------------------- #


@dataclass
class RelayStats:
    datagrams_down: int = 0  # datagrams received from PX4
    datagrams_up: int = 0  # datagrams received from clients
    frames_down: int = 0  # well-framed frames seen on the downlink (PX4 -> clients)
    frames_up: int = 0  # ... and on the uplink (clients -> PX4)
    forwarded: int = 0  # frames the hooks released (forwarded_down + forwarded_up)
    forwarded_down: int = 0
    forwarded_up: int = 0
    mirrored_up: int = 0  # up_hook output frames also fanned out to OTHER clients (opt-in)
    dropped_by_hook: int = 0  # input frames for which a hook returned []
    hook_errors: int = 0  # hook raised / returned a non-list[bytes]; original forwarded
    bad_segments: int = 0  # unframeable bytes dropped (garbage, truncated, frame cap)
    send_failures: int = 0  # a send() / sendto() returned False
    down_no_client: int = 0  # released downlink frames with nobody to send them to
    clients: int = 0  # currently learned clients
    clients_seen: int = 0  # distinct clients ever learned
    rejected_clients: int = 0  # datagrams refused: non-loopback source or table full
    overflow: int = 0  # datagrams dropped by the bounded receive queues (both legs)
    pump_errors: int = 0  # unexpected exceptions in the pump loop (loop continues)

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


class MavlinkRelay:
    """Fan-out relay between one upstream (PX4) link and loopback clients."""

    def __init__(
        self,
        upstream: UpstreamLink,
        downstream: DownstreamLink,
        *,
        down_hook: FrameHook = passthrough,
        up_hook: FrameHook = passthrough,
        max_clients: int = 4,
        client_timeout_s: float = 30.0,
        max_frames_per_datagram: int = 64,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        sleep: Callable[[float], None] = time.sleep,
        idle_sleep_s: float = 0.001,
        mirror_uplink_to_clients: bool = False,
    ) -> None:
        if max_clients < 1:
            raise ValueError("max_clients must be >= 1")
        self.upstream = upstream
        self.downstream = downstream
        self.down_hook = down_hook
        self.up_hook = up_hook
        self.mirror_uplink_to_clients = mirror_uplink_to_clients
        self.max_clients = max_clients
        self.max_frames_per_datagram = max_frames_per_datagram
        self._timeout_ns = round(client_timeout_s * 1e9)
        self._clock_ns = clock_ns
        self._sleep = sleep
        self._idle_sleep = idle_sleep_s
        self._clients: dict[Address, int] = {}  # addr -> last-seen (clock_ns)
        self._stats = RelayStats()
        self._alive = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False
        self._closed = False
        self._hook_error_logged: set[str] = set()
        self.first_heartbeat_sent = False

    # -- lifecycle ---------------------------------------------------------- #

    def start(self) -> MavlinkRelay:
        """Start the relay. ORDER MATTERS (PX4 locks to the first sender):

        1. send the proxy's own GCS heartbeat upstream (synchronously; raises
           ``RuntimeError`` if it cannot be sent -> fail closed);
        2. start the upstream receive/heartbeat threads;
        3. only then open the downstream leg (clients cannot reach PX4 before step 1);
        4. start the pump thread.
        """
        if self._closed:
            raise RuntimeError("relay is closed")
        if self._started:
            return self
        if not self.upstream.send_heartbeat():
            raise RuntimeError("could not send the first GCS heartbeat upstream; refusing to "
                               "start (PX4 would lock to a different sender)")
        self.first_heartbeat_sent = True
        self._started = True
        self.upstream.start()
        self.downstream.start()
        self._thread = threading.Thread(target=self._run, name="relay-pump", daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        """Idempotent. Stops the pump, then closes both legs."""
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        self.downstream.close()
        self.upstream.close()

    def __enter__(self) -> MavlinkRelay:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def wait_upstream_alive(self, timeout: float) -> bool:
        """Block until a well-framed MAVLink frame has arrived from PX4 (or ``timeout`` s)."""
        deadline = self._clock_ns() + round(timeout * 1e9)
        while not self._alive.is_set():
            if self._clock_ns() >= deadline or self._closed:
                return self._alive.is_set()
            self._sleep(0.01)
        return True

    @property
    def upstream_alive(self) -> bool:
        return self._alive.is_set()

    @property
    def stats(self) -> dict[str, int]:
        st = self._stats
        st.clients = len(self._clients)
        st.overflow = int(getattr(self.upstream, "dropped_overflow", 0)) + int(
            getattr(self.downstream, "dropped_overflow", 0))
        return st.as_dict()

    @property
    def client_addresses(self) -> list[Address]:
        return list(self._clients)

    # -- pump --------------------------------------------------------------- #

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                busy = self.pump_once()
            except Exception:  # noqa: BLE001 - the relay must outlive any single bad cycle
                self._stats.pump_errors += 1
                if self._stats.pump_errors == 1:
                    log.exception("relay pump error (further ones only counted)")
                busy = 0
            if not busy:
                self._sleep(self._idle_sleep)

    def pump_once(self) -> int:
        """One non-blocking cycle: drain PX4 -> clients, then clients -> PX4.

        Returns the number of datagrams handled. Safe to call without ``start()`` (tests).
        """
        n = 0
        for ns, data in self.upstream.poll():
            n += 1
            self._handle_down(ns, data)
        for ns, addr, data in self.downstream.poll():
            n += 1
            self._handle_up(ns, addr, data)
        return n

    # -- per-datagram ------------------------------------------------------- #

    def _handle_down(self, ns: int, data: bytes) -> None:
        st = self._stats
        st.datagrams_down += 1
        frames, bad = split_frames(data, self.max_frames_per_datagram)
        st.bad_segments += bad
        if frames:
            self._alive.set()
        for fr in frames:
            st.frames_down += 1
            out = self._run_hook(self.down_hook, "down", fr, ns)
            if not out:
                st.dropped_by_hook += 1
                continue
            st.forwarded += len(out)
            st.forwarded_down += len(out)
            if not self._clients:
                st.down_no_client += len(out)
                continue
            for raw in out:
                for addr in list(self._clients):
                    if not self.downstream.sendto(raw, addr):
                        st.send_failures += 1

    def _handle_up(self, ns: int, addr: Address, data: bytes) -> None:
        st = self._stats
        st.datagrams_up += 1
        frames, bad = split_frames(data, self.max_frames_per_datagram)
        st.bad_segments += bad
        if not frames or not self._learn(addr):  # junk never takes a client slot
            return
        for fr in frames:
            st.frames_up += 1
            out = self._run_hook(self.up_hook, "up", fr, ns)
            if not out:
                st.dropped_by_hook += 1
                continue
            st.forwarded += len(out)
            st.forwarded_up += len(out)
            for raw in out:
                if not self.upstream.send(raw):
                    st.send_failures += 1
            if self.mirror_uplink_to_clients:
                others = [a for a in self._clients if a != addr]
                for raw in out:
                    # The sender must not see an echo of its OWN frame. A frame the hook created or
                    # modified (raw != the original) was not authored by the sender as it went on the
                    # wire, so every client -- the sender included -- must see it: otherwise an
                    # injection that rides on the IDS tap's own heartbeat is invisible to the IDS.
                    targets = others if raw == fr.raw else list(self._clients)
                    if targets:
                        st.mirrored_up += 1
                        for other in targets:
                            if not self.downstream.sendto(raw, other):
                                st.send_failures += 1

    def _learn(self, addr: Address) -> bool:
        now = self._clock_ns()
        if addr in self._clients:
            self._clients[addr] = now
            return True
        try:
            loopback = ipaddress.ip_address(addr[0]).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            self._stats.rejected_clients += 1
            return False
        if len(self._clients) >= self.max_clients:
            for a in [a for a, seen in self._clients.items() if now - seen > self._timeout_ns]:
                del self._clients[a]  # idle clients make room
        if len(self._clients) >= self.max_clients:
            self._stats.rejected_clients += 1
            return False
        self._clients[addr] = now
        self._stats.clients_seen += 1
        log.info("relay: learned client %s", addr)
        return True

    def _run_hook(self, hook: FrameHook, direction: Direction, fr: _Frame, ns: int) -> list[bytes]:
        ctx = FrameContext(direction=direction, raw=fr.raw, recv_ns=ns, sysid=fr.sysid,
                           compid=fr.compid, seq=fr.seq, msgid=fr.msgid, signed=fr.signed)
        try:
            return _validated(hook(ctx))
        except Exception as exc:  # noqa: BLE001 - a broken hook must not take the relay down
            self._stats.hook_errors += 1
            if direction not in self._hook_error_logged:
                self._hook_error_logged.add(direction)
                log.error("relay: %s hook failed (%r); forwarding the original frame; further "
                          "errors in this direction are only counted", direction, exc,
                          exc_info=True)
            return [fr.raw]


def _validated(out: object) -> list[bytes]:
    if not isinstance(out, (list, tuple)) or len(out) > _MAX_HOOK_FRAMES:
        raise TypeError(f"a hook must return a list of at most {_MAX_HOOK_FRAMES} frames")
    frames: list[bytes] = []
    for item in out:
        if not isinstance(item, (bytes, bytearray, memoryview)):
            raise TypeError(f"hook returned a non-bytes frame: {type(item).__name__}")
        b = bytes(item)
        if not 0 < len(b) <= _MAX_DATAGRAM:
            raise ValueError(f"hook returned a frame of {len(b)} bytes")
        frames.append(b)
    return frames


def make_udp_relay(
    px4_host: str,
    px4_port: int,
    listen_port: int,
    *,
    listen_host: str | None = None,
    down_hook: FrameHook = passthrough,
    up_hook: FrameHook = passthrough,
    mirror_uplink_to_clients: bool = False,
    **relay_kwargs: Any,
) -> MavlinkRelay:
    """Real-socket relay: connect to ``px4_host:px4_port`` (explicit), bind loopback ``listen_port``.

    ``mirror_uplink_to_clients`` is opt-in and defaults to ``False`` (unchanged relay
    behaviour); see :class:`MavlinkRelay` / the module docstring for why it exists.
    """
    upstream = UdpMavlinkTransport(connect=(px4_host, px4_port), gcs_heartbeat=True)
    try:
        downstream = UdpDownstream((listen_host, listen_port))
    except BaseException:
        upstream.close()
        raise
    return MavlinkRelay(upstream, downstream, down_hook=down_hook, up_hook=up_hook,
                         mirror_uplink_to_clients=mirror_uplink_to_clients, **relay_kwargs)


# --------------------------------------------------------------------------- #
# CLI (pass-through only)
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m aegisflight.proxy.transport",
        description="Pass-through MAVLink UDP relay to PX4 SITL (loopback clients only).")
    ap.add_argument("--px4-host", required=True, help="PX4 address (explicit; no discovery)")
    ap.add_argument("--px4-port", type=int, required=True)
    ap.add_argument("--listen-port", type=int, required=True)
    ap.add_argument("--listen-host", default=None, help="loopback address (default 127.0.0.1)")
    ap.add_argument("--seconds", type=float, default=None, help="run time (default: until Ctrl-C)")
    ap.add_argument("--alive-timeout", type=float, default=10.0)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

    relay = make_udp_relay(args.px4_host, args.px4_port, args.listen_port,
                           listen_host=args.listen_host)
    code = 0
    try:
        relay.start()
        print(f"relay: PX4 {args.px4_host}:{args.px4_port} <-> clients "
              f"{relay.downstream.local_address}", flush=True)  # type: ignore[attr-defined]
        if not relay.wait_upstream_alive(args.alive_timeout):
            print(f"relay: no MAVLink from PX4 within {args.alive_timeout:g}s", flush=True)
            code = 2
        end = None if args.seconds is None else time.monotonic() + args.seconds
        while code == 0 and (end is None or time.monotonic() < end):
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        relay.close()
        print(json.dumps(relay.stats), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
