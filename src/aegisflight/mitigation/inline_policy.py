"""Inline enforcement policy for a bump-in-the-wire IPS (Topology B).

``InlinePolicy`` supplies the two ``FrameHook`` callables (uplink GCS -> FC, downlink FC -> GCS) that an
inline bridge runs on every frame. It has two layers:

* **Static rules** (uplink, need no detector): when enforcement is on, hostile control traffic is dropped
  before the autopilot sees it, whatever the IDS has concluded so far:

  - a control message (``SET_MODE``, ``COMMAND_LONG``/``COMMAND_INT`` with a sensitive command, mission /
    parameter writes, position-target and RC-override messages) from a sysid that is not a trusted
    ground station is dropped;
  - a *non-forced* disarm in flight is dropped for everyone (the autopilot refuses it anyway); a forced
    disarm (magic 21196) is dropped unless it comes from a trusted ground station, so the pilot's
    emergency kill is never blocked;
  - a byte-identical sensitive command repeated within ``cadence_s`` is dropped (burst / replay of one frame).

  The pilot is never blocked: every frame from a trusted sysid passes (except the burst rule and the
  non-forced in-flight disarm, which the autopilot would not honour either).

* **Dynamic rules** (downlink, driven by the mitigation controller's ``FrameSanitizer``): quarantine of a
  rogue sysid, QoS shedding in a flood, GPS / altitude rewrite. They apply only while the controller keeps
  them fresh (``touch`` within ``dynamic_ttl_s``); a stalled analyser therefore degrades to transparent
  forwarding, never to a stale rewrite. Signed frames are never modified (a rewrite would break the MAC).

Limits that no software rule removes: on an unsigned link a sysid is only a claim, so an attacker who
uses the real GCS sysid (255) is indistinguishable from the pilot (``gcs_replay``); MAVLink-2 signing is the fix.
Any exception in a rule forwards the original frame (fail-open).
"""

from __future__ import annotations

import struct
import threading
import time
from collections.abc import Callable, Iterable

from ..proxy.hooks import FrameContext
from .sanitizer import FrameSanitizer

_MSG_HEARTBEAT = 0
_MSG_SET_MODE = 11
_MSG_PARAM_SET = 23
_MSG_GLOBAL_POSITION_INT = 33
_MSG_MISSION_ITEM = 39
_MSG_MISSION_COUNT = 44
_MSG_MISSION_CLEAR_ALL = 45
_MSG_RC_CHANNELS_OVERRIDE = 70
_MSG_MISSION_ITEM_INT = 73
_MSG_COMMAND_INT = 75
_MSG_COMMAND_LONG = 76
_MSG_SET_POSITION_TARGET_LOCAL_NED = 84
_MSG_SET_POSITION_TARGET_GLOBAL_INT = 86
_MSG_SET_ATTITUDE_TARGET = 82

#: control messages that only a trusted ground station may send to the vehicle
CONTROL_MSGIDS = frozenset({
    _MSG_SET_MODE, _MSG_PARAM_SET, _MSG_MISSION_ITEM, _MSG_MISSION_COUNT, _MSG_MISSION_CLEAR_ALL,
    _MSG_RC_CHANNELS_OVERRIDE, _MSG_MISSION_ITEM_INT, _MSG_SET_POSITION_TARGET_LOCAL_NED,
    _MSG_SET_POSITION_TARGET_GLOBAL_INT, _MSG_SET_ATTITUDE_TARGET,
})
_COMMAND_MSGIDS = frozenset({_MSG_COMMAND_LONG, _MSG_COMMAND_INT})

MAV_CMD_NAV_RETURN_TO_LAUNCH = 20
MAV_CMD_NAV_LAND = 21
MAV_CMD_NAV_TAKEOFF = 22
MAV_CMD_DO_SET_MODE = 176
MAV_CMD_DO_PARAMETER = 180
MAV_CMD_DO_FLIGHTTERMINATION = 185
MAV_CMD_DO_REPOSITION = 192
MAV_CMD_MISSION_START = 300
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN = 246
FORCE_MAGIC = 21196.0

#: commands a non-trusted sysid may not send, and the commands covered by the burst rule
SENSITIVE_COMMANDS = frozenset({
    MAV_CMD_NAV_RETURN_TO_LAUNCH, MAV_CMD_NAV_LAND, MAV_CMD_NAV_TAKEOFF, MAV_CMD_DO_SET_MODE,
    MAV_CMD_DO_PARAMETER, MAV_CMD_DO_FLIGHTTERMINATION, MAV_CMD_DO_REPOSITION, MAV_CMD_MISSION_START,
    MAV_CMD_COMPONENT_ARM_DISARM, MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN,
})

_V2, _V1 = 0xFD, 0xFE


def _payload(raw: bytes, signed_len: int = 0) -> bytes | None:
    """Payload of one unsigned-or-signed frame, zero-padded (MAVLink 2 trims trailing zeros)."""
    if not raw:
        return None
    if raw[0] == _V2 and len(raw) >= 12:
        return raw[10:10 + raw[1]] + bytes(40)
    if raw[0] == _V1 and len(raw) >= 8:
        return raw[6:6 + raw[1]] + bytes(40)
    return None


def _command(raw: bytes, msgid: int) -> tuple[int, float, float] | None:
    """``(command, param1, param2)`` of a COMMAND_LONG / COMMAND_INT frame."""
    p = _payload(raw)
    if p is None:
        return None
    if msgid == _MSG_COMMAND_LONG:
        p1, p2 = struct.unpack_from("<2f", p, 0)
        return struct.unpack_from("<H", p, 28)[0], p1, p2
    if msgid == _MSG_COMMAND_INT:
        p1, p2 = struct.unpack_from("<2f", p, 0)
        return struct.unpack_from("<H", p, 28)[0], p1, p2
    return None


class InlinePolicy:
    """Thread-safe uplink/downlink filter for an inline bridge. See the module docstring."""

    def __init__(
        self,
        sanitizer: FrameSanitizer | None = None,
        *,
        trusted_sysids: Iterable[int] = (255, 254),
        vehicle_sysids: Iterable[int] = (1,),
        cadence_s: float = 0.05,
        dynamic_ttl_s: float = 3.0,
        in_flight_alt_m: float = 2.0,
        in_flight_speed_ms: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.sanitizer = sanitizer or FrameSanitizer()
        self.trusted_sysids = frozenset(int(s) for s in trusted_sysids)
        self.vehicle_sysids = frozenset(int(s) for s in vehicle_sysids)
        self.cadence_s = float(cadence_s)
        self.dynamic_ttl_s = float(dynamic_ttl_s)
        self.in_flight_alt_m = float(in_flight_alt_m)
        self.in_flight_speed_ms = float(in_flight_speed_ms)
        self._clock = clock
        self._lock = threading.Lock()
        self.enforce = False                # static uplink rules + dynamic rewrites; off = byte-identical forwarding
        self._last_touch: float | None = None
        # vehicle state learnt from the frames the policy itself forwards (no detector involved)
        self.armed: bool | None = None
        self.rel_alt_m: float | None = None
        self.groundspeed_ms: float | None = None
        self._last_cmd: dict[tuple[int, int, int], tuple[float, bytes]] = {}
        # counters
        self.dropped_untrusted_control = 0
        self.dropped_inflight_disarm = 0
        self.dropped_burst = 0
        self.dropped_dynamic = 0
        self.rewritten = 0
        self.hook_errors = 0

    # -- control ------------------------------------------------------------- #

    def set_enforce(self, enforce: bool) -> None:
        with self._lock:
            self.enforce = bool(enforce)
            if not enforce:
                self._last_cmd.clear()

    def touch(self) -> None:
        """The analyser calls this after every controller step; it keeps the dynamic rules fresh."""
        self._last_touch = self._clock()

    @property
    def dynamic_fresh(self) -> bool:
        t = self._last_touch
        return t is not None and (self._clock() - t) <= self.dynamic_ttl_s

    @property
    def protected_sysids(self) -> frozenset[int]:
        """Never quarantined: the vehicle and the trusted ground stations."""
        return self.trusted_sysids | self.vehicle_sysids

    @property
    def in_flight(self) -> bool:
        if not self.armed:
            return False
        return bool((self.rel_alt_m or 0.0) > self.in_flight_alt_m
                    or (self.groundspeed_ms or 0.0) > self.in_flight_speed_ms)

    def stats(self) -> dict[str, int | bool | None]:
        return {"enforce": self.enforce, "dynamic_fresh": self.dynamic_fresh, "armed": self.armed,
                "in_flight": self.in_flight, "dropped_untrusted_control": self.dropped_untrusted_control,
                "dropped_inflight_disarm": self.dropped_inflight_disarm, "dropped_burst": self.dropped_burst,
                "dropped_dynamic": self.dropped_dynamic, "rewritten": self.rewritten,
                "hook_errors": self.hook_errors}

    # -- hooks --------------------------------------------------------------- #

    def down(self, ctx: FrameContext) -> list[bytes]:
        """FC -> GCS."""
        try:
            self._learn_state(ctx)
            if not self.enforce or not self.dynamic_fresh or not self.sanitizer.active:
                return [ctx.raw]
            san = self.sanitizer
            if ctx.sysid in self.protected_sysids:
                # the vehicle's own telemetry may be rewritten (GPS / altitude) but a protected sysid is never
                # quarantined
                saved, san.quarantined_sysids = san.quarantined_sysids, set()
                try:
                    out = san(ctx)
                finally:
                    san.quarantined_sysids = saved
            else:
                out = san(ctx)
            if not out:
                self.dropped_dynamic += 1
            elif out != [ctx.raw]:
                self.rewritten += 1
            return out
        except Exception:  # noqa: BLE001 - fail open
            self.hook_errors += 1
            return [ctx.raw]

    def up(self, ctx: FrameContext) -> list[bytes]:
        """GCS -> FC."""
        try:
            if not self.enforce:
                return [ctx.raw]
            trusted = ctx.sysid in self.trusted_sysids
            msgid = ctx.msgid
            if msgid in CONTROL_MSGIDS and not trusted:
                self.dropped_untrusted_control += 1
                return []
            if msgid in _COMMAND_MSGIDS:
                cmd = _command(ctx.raw, msgid)
                if cmd is not None and cmd[0] in SENSITIVE_COMMANDS:
                    return self._command_rule(ctx, trusted, *cmd)
            if self.dynamic_fresh and self.sanitizer.active and not trusted:
                # quarantined / flooding sender on the uplink (the sanitizer drops both directions)
                if ctx.sysid in self.sanitizer.quarantined_sysids and ctx.sysid not in self.protected_sysids:
                    self.dropped_dynamic += 1
                    return []
            return [ctx.raw]
        except Exception:  # noqa: BLE001 - fail open
            self.hook_errors += 1
            return [ctx.raw]

    # -- internals ----------------------------------------------------------- #

    def _command_rule(self, ctx: FrameContext, trusted: bool, command: int, p1: float, p2: float) -> list[bytes]:
        if not trusted:
            self.dropped_untrusted_control += 1
            return []
        if command == MAV_CMD_COMPONENT_ARM_DISARM and p1 == 0.0 and self.in_flight and p2 != FORCE_MAGIC:
            # a plain disarm in flight is refused by the autopilot anyway; a forced one is the pilot's kill switch
            self.dropped_inflight_disarm += 1
            return []
        key = (ctx.sysid, ctx.compid, command)
        body = ctx.raw[10:-2] if ctx.raw[0] == _V2 and not ctx.signed else ctx.raw
        now = self._clock()
        with self._lock:
            prev = self._last_cmd.get(key)
            self._last_cmd[key] = (now, body)
            if len(self._last_cmd) > 256:
                self._last_cmd.pop(next(iter(self._last_cmd)))
        if prev is not None and (now - prev[0]) < self.cadence_s and prev[1] == body:
            self.dropped_burst += 1
            return []
        return [ctx.raw]

    def _learn_state(self, ctx: FrameContext) -> None:
        if ctx.sysid not in self.vehicle_sysids:
            return
        if ctx.msgid == _MSG_HEARTBEAT:
            p = _payload(ctx.raw)
            if p is not None and len(ctx.raw) >= 12:
                self.armed = bool(p[6] & 0x80)  # base_mode SAFETY_ARMED
        elif ctx.msgid == _MSG_GLOBAL_POSITION_INT:
            p = _payload(ctx.raw)
            if p is not None:
                _, _, _, _, rel_alt, vx, vy, _, _ = struct.unpack_from("<IiiiihhhH", p, 0)
                self.rel_alt_m = rel_alt / 1000.0
                self.groundspeed_ms = ((vx / 100.0) ** 2 + (vy / 100.0) ** 2) ** 0.5
