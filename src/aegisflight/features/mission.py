"""Mission-path tracker (ADDITIVE, 2026-10-28).

Reconstructs the mission the operator commanded from the MAVLink mission protocol, seen on either
link direction (upload GCS->FC or download FC->GCS), and measures how far a reported position is
from the current mission leg. Pure software; says nothing unless a COMPLETE mission was observed.

Messages: MISSION_COUNT (44), MISSION_ITEM_INT (73), MISSION_ITEM (39), MISSION_CURRENT (42),
MISSION_ITEM_REACHED (46). Field semantics (pymavlink dialect): MISSION_ITEM x/y are float degrees,
MISSION_ITEM_INT x/y are int32 degE7. Only the main mission (mission_type 0) is used. Only
NAV_WAYPOINT (command 16) items in a global frame (0, 3, 5, 6) become path waypoints; loiter,
spline, DO_JUMP etc. are ignored, so such missions are only approximated.
"""

from __future__ import annotations

import math

from ..core.geo import EARTH_RADIUS_M, haversine_m
from ..core.types import MessageEnvelope

NAV_WAYPOINT = 16
_GLOBAL_FRAMES = frozenset({0, 3, 5, 6})
_MISSION_MSGS = frozenset(
    {"MISSION_COUNT", "MISSION_ITEM_INT", "MISSION_ITEM", "MISSION_CURRENT", "MISSION_ITEM_REACHED"}
)


def segment_xtrack_m(lat: float, lon: float, a: tuple[float, float], b: tuple[float, float]) -> float:
    """Horizontal distance (m) from (lat, lon) to the SEGMENT a-b (not the infinite line)."""
    ky = math.radians(1.0) * EARTH_RADIUS_M
    kx = ky * math.cos(math.radians(a[0]))
    bx, by = (b[1] - a[1]) * kx, (b[0] - a[0]) * ky
    px, py = (lon - a[1]) * kx, (lat - a[0]) * ky
    seg2 = bx * bx + by * by
    if seg2 < 1e-6:
        return haversine_m(lat, lon, a[0], a[1])
    u = max(0.0, min(1.0, (px * bx + py * by) / seg2))
    return math.hypot(px - u * bx, py - u * by)


class MissionTracker:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._count: int | None = None
        self._items: dict[int, tuple[float, float] | None] = {}  # seq -> (lat, lon), None = not a path wp
        self._current_seq: int | None = None
        self._current_t = -1e9
        self._origin: tuple[float, float] | None = None

    @property
    def complete(self) -> bool:
        n = self._count
        return n is not None and n > 0 and all(i in self._items for i in range(n))

    @property
    def current_seq(self) -> int | None:
        return self._current_seq

    @property
    def current_t(self) -> float:
        return self._current_t

    def waypoints(self) -> list[tuple[int, float, float]]:
        """(seq, lat, lon) of the path waypoints of the complete mission, else []."""
        if not self.complete:
            return []
        out = []
        for s in sorted(self._items):
            p = self._items[s]
            if p is not None:
                out.append((s, p[0], p[1]))
        return out

    def update(self, msg: MessageEnvelope) -> None:
        name, f = msg.msgname, msg.fields
        if name not in _MISSION_MSGS:
            return
        if name == "MISSION_CURRENT":
            seq = int(f.get("seq", -1))
            if seq != self._current_seq:
                self._origin = None
            self._current_seq = seq
            self._current_t = msg.recv_time
            return
        if name == "MISSION_ITEM_REACHED":
            return  # leg advance is taken from MISSION_CURRENT; REACHED adds no geometry
        if int(f.get("mission_type", 0)) != 0:
            return
        if name == "MISSION_COUNT":
            self._count = int(f.get("count", 0))
            self._items = {}
            self._origin = None
            return
        if self._count is None:
            return
        seq = int(f.get("seq", -1))
        if not 0 <= seq < self._count:
            return
        pos: tuple[float, float] | None = None
        if int(f.get("command", 0)) == NAV_WAYPOINT and int(f.get("frame", -1)) in _GLOBAL_FRAMES:
            scale = 1e7 if name == "MISSION_ITEM_INT" else 1.0
            lat, lon = float(f.get("x", 0.0)) / scale, float(f.get("y", 0.0)) / scale
            if abs(lat) <= 90.0 and abs(lon) <= 180.0 and (lat or lon):
                pos = (lat, lon)
        self._items[seq] = pos

    def leg(self, lat: float, lon: float) -> tuple[tuple[float, float], tuple[float, float], int] | None:
        """(from, to, target waypoint seq) for the current MISSION_CURRENT, or None. The first
        leg starts at the first position evaluated after it became current."""
        if not self.complete or self._current_seq is None:
            return None
        wps = self.waypoints()
        tgt_i = next((i for i, w in enumerate(wps) if w[0] >= self._current_seq), None)
        if tgt_i is None:
            return None
        tgt = wps[tgt_i]
        if tgt_i > 0:
            frm = (wps[tgt_i - 1][1], wps[tgt_i - 1][2])
        else:
            if self._origin is None:
                self._origin = (lat, lon)
            frm = self._origin
        return frm, (tgt[1], tgt[2]), tgt[0]

    def evaluate(self, lat: float, lon: float) -> tuple[float, float, int] | None:
        """(cross-track m to the leg segment, distance m to the target waypoint, target seq)."""
        leg = self.leg(lat, lon)
        if leg is None:
            return None
        frm, to, seq = leg
        return segment_xtrack_m(lat, lon, frm, to), haversine_m(lat, lon, to[0], to[1]), seq
