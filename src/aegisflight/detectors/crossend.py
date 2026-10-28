"""Cross-end check: was the telemetry altered AFTER the inline bridge (radio link, GCS-side injection)?

The inline bridge (``aegis ips-bridge``) sees the real vehicle frames. Once per ``--crossend-interval`` it
sends the GCS one standard MAVLink 2 ``MEMORY_VECT`` (msgid 249, sender sysid 1 / compid 191) under a fixed
marker, carrying the exact integer fields of the latest GLOBAL_POSITION_INT it forwarded. An IDS running at
the GCS (``aegis serve --source serial|udp``) keeps the GLOBAL_POSITION_INT frames it received; when a summary
names a ``time_boot_ms`` it also holds, every field must be identical. The link is lossless for a frame that
arrives, so any difference means the frame was altered in transit.

Honest limits
-------------
* Sampled: one frame per interval (default 1 Hz). A forged frame with a different ``time_boot_ms`` than
  the bridge's sampled one is not compared at all, and between samples nothing is checked.
* The summary itself can be forged by whoever can inject on the link. Without a key that is undetectable.
  With a key the bridge signs the MAVLink frame AND appends a truncated HMAC-SHA256 tag (8 bytes) inside
  the payload; the GCS monitor verifies the tag (``MessageEnvelope`` does not carry the raw frame, so the
  frame signature itself cannot be re-verified here). An attacker without the key can still block the
  summaries; that shows up only as the "summaries went silent" evidence.
* It only works when the GCS-side IDS sees the bridge summary on the same link as the telemetry.
* Completely inert (``assess`` returns None) until a summary has been seen.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from collections import OrderedDict
from dataclasses import dataclass, field

from ..core.enums import AttackType
from ..core.types import MessageEnvelope

GPI_MSGID = 33
MEMORY_VECT_MSGID = 249
#: marker carried in MEMORY_VECT.address / ver / type
MARKER_ADDRESS = 0xAE15
MARKER_VER = 1
MARKER_TYPE = 0
_BODY = struct.Struct("<Iiiiihh")  # time_boot_ms lat lon alt relative_alt vx vy  (24 bytes)
_TAG_LEN = 8
_TAG_CTX = b"AEGX1"
FIELDS = ("time_boot_ms", "lat", "lon", "alt", "relative_alt", "vx", "vy")
_GPI_STRUCT = struct.Struct("<IiiiihhhH")  # full GLOBAL_POSITION_INT payload (28 bytes)

MISMATCH_HOLD_S = 3.0
SILENCE_S = 5.0
_KEEP = 60


def load_signing_key(path: str) -> bytes:
    """32-byte key file, raw or 64 hex chars (same format as ``aegis ips-bridge --signing-key-file``)."""
    with open(path, "rb") as fh:
        raw = fh.read()
    key = raw if len(raw) == 32 else bytes.fromhex(raw.decode("ascii").strip())
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    return key


def _tag(key: bytes | None, body: bytes) -> bytes:
    if key is None:
        return bytes(_TAG_LEN)
    return hmac.new(key, _TAG_CTX + body, hashlib.sha256).digest()[:_TAG_LEN]


def pack_summary(values: tuple[int, ...], key: bytes | None = None) -> list[int]:
    """The 32 signed bytes for ``MEMORY_VECT.value``: 24 body bytes + 8 tag bytes."""
    body = _BODY.pack(*values)
    return [b - 256 if b > 127 else b for b in body + _tag(key, body)]


def unpack_summary(value: list[int], key: bytes | None) -> tuple[tuple[int, ...], bool]:
    """-> (field values, tag_ok). ``tag_ok`` is meaningful only when ``key`` is given."""
    raw = bytes(int(v) & 0xFF for v in value[:32])
    raw = raw.ljust(32, b"\x00")
    body, tag = raw[:_BODY.size], raw[_BODY.size:_BODY.size + _TAG_LEN]
    ok = key is None or hmac.compare_digest(tag, _tag(key, body))
    return _BODY.unpack(body), ok


def gpi_from_frame(raw: bytes) -> tuple[int, ...] | None:
    """Exact (time_boot_ms, lat, lon, alt, relative_alt, vx, vy) of a raw GLOBAL_POSITION_INT frame."""
    try:
        if raw[0] == 0xFD:
            if (raw[7] | raw[8] << 8 | raw[9] << 16) != GPI_MSGID:
                return None
            payload = raw[10:10 + raw[1]]
        elif raw[0] == 0xFE:
            if raw[5] != GPI_MSGID:
                return None
            payload = raw[6:6 + raw[1]]
        else:
            return None
        vals = _GPI_STRUCT.unpack(payload.ljust(_GPI_STRUCT.size, b"\x00")[:_GPI_STRUCT.size])
    except (IndexError, struct.error):
        return None
    return vals[:7]


@dataclass
class CrossEndResult:
    score: float
    votes: dict[AttackType, float] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)


class CrossEndMonitor:
    def __init__(self, key: bytes | None = None) -> None:
        if key is not None and len(key) != 32:
            raise ValueError("signing key must be 32 bytes")
        self.key = key
        self.reset()

    def reset(self) -> None:
        self._gpi: OrderedDict[int, list[tuple[int, ...]]] = OrderedDict()
        self._pending: OrderedDict[int, tuple[int, ...]] = OrderedDict()
        self._now = 0.0
        self._last_summary_t: float | None = None
        self._mismatch: tuple[float, str] | None = None
        self._bad_auth: tuple[float, str] | None = None
        self.summaries = 0
        self.compared = 0
        self.mismatches = 0
        self.unmatched = 0
        self.bad_auth = 0

    # -- ingest --------------------------------------------------------------- #

    def update(self, msg: MessageEnvelope) -> None:
        self._now = max(self._now, msg.recv_time)
        if msg.msgid == GPI_MSGID:
            f = msg.fields
            try:
                vals = tuple(int(f[k]) for k in FIELDS)
            except (KeyError, TypeError, ValueError):
                return
            lst = self._gpi.setdefault(vals[0], [])
            if vals not in lst and len(lst) < 4:
                lst.append(vals)
            self._gpi.move_to_end(vals[0])
            while len(self._gpi) > _KEEP:
                self._gpi.popitem(last=False)
            pend = self._pending.pop(vals[0], None)
            if pend is not None:
                self._compare(pend, msg.recv_time)
        elif msg.msgid == MEMORY_VECT_MSGID:
            f = msg.fields
            if (f.get("address") != MARKER_ADDRESS or f.get("ver") != MARKER_VER
                    or f.get("type") != MARKER_TYPE or not isinstance(f.get("value"), (list, tuple))):
                return
            self._summary(msg)

    def _summary(self, msg: MessageEnvelope) -> None:
        vals, tag_ok = unpack_summary(list(msg.fields["value"]), self.key)
        self.summaries += 1
        self._last_summary_t = msg.recv_time
        if self.key is not None and not (tag_ok and msg.signed):
            self.bad_auth += 1
            why = "bad tag" if not tag_ok else "frame not signed"
            self._bad_auth = (msg.recv_time, f"bridge cross-end summary not authentic ({why})")
            return  # never compare against an unauthenticated summary
        tbm = vals[0]
        if tbm in self._gpi:
            self._compare(vals, msg.recv_time)
        else:
            self._pending[tbm] = vals
            while len(self._pending) > _KEEP:
                self._pending.popitem(last=False)
                self.unmatched += 1

    def _compare(self, summary: tuple[int, ...], t: float) -> None:
        self.compared += 1
        for seen in self._gpi.get(summary[0], []):
            for name, a, b in zip(FIELDS, summary, seen, strict=True):
                if a != b:
                    self.mismatches += 1
                    self._mismatch = (t, f"downlink position differs from what the bridge forwarded "
                                         f"(field {name}: bridge {a}, GCS {b})")
                    return

    # -- verdict -------------------------------------------------------------- #

    def assess(self, t: float = 0.0) -> CrossEndResult | None:  # noqa: ARG002 - envelope time base is used
        if self._last_summary_t is None:
            return None
        score = 0.0
        votes: dict[AttackType, float] = {}
        ev: list[str] = []
        if self._mismatch and self._now - self._mismatch[0] <= MISMATCH_HOLD_S:
            score = 0.9
            votes[AttackType.TELEMETRY_MANIPULATION] = 0.9
            ev.append(self._mismatch[1])
        if self._bad_auth and self._now - self._bad_auth[0] <= MISMATCH_HOLD_S:
            score = max(score, 0.3)
            votes[AttackType.MAVLINK_ANOMALY] = max(votes.get(AttackType.MAVLINK_ANOMALY, 0.0), 0.3)
            ev.append(self._bad_auth[1])
        if self._now - self._last_summary_t > SILENCE_S:
            score = max(score, 0.3)
            votes[AttackType.MAVLINK_ANOMALY] = max(votes.get(AttackType.MAVLINK_ANOMALY, 0.0), 0.3)
            ev.append(f"bridge cross-end summaries silent for {self._now - self._last_summary_t:.0f} s")
        return CrossEndResult(score, votes, ev)
