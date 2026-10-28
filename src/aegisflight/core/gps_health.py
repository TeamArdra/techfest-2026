"""Passive GPS / estimator health observer.

Status only. Nothing here is read by a detector, raises an alert, is persisted in the event store or
changes a decision; it exists so an operator can see what the VEHICLE reports about its own position
solution next to the receiver's fix. It reports vehicle-stated conditions only and is not evidence
that a position is authentic (a spoofer can report a clean fix, and ``EKF_STATUS_REPORT`` is
unauthenticated).

Two conditions are flagged, both stated by the autopilot itself:

* ``ekf_no_horizontal_solution``: the latest, fresh ``EKF_STATUS_REPORT`` has no horizontal position
  bit, or is in constant-position mode (the same test as ``features.extractor.ekf_has_horizontal_solution``;
  a unit test pins the two together);
* ``gps_sensor_unhealthy``: ``SYS_STATUS`` declares the GPS sensor present but its health bit is clear.

Receiver quality (``fix_type``, satellites, HDOP) is passed through unjudged: no threshold is
invented here. Unknown is ``None``, never ``False``. ``core/`` imports nothing internal, so the bit
values are local constants, checked against the installed pymavlink dialects in the tests.
"""

from __future__ import annotations

from typing import Any

SENSOR_GPS = 0x20  # common MAV_SYS_STATUS_SENSOR_GPS
EKF_POS_HORIZ_REL = 8  # ardupilotmega EKF_STATUS_FLAGS
EKF_POS_HORIZ_ABS = 16
EKF_CONST_POS_MODE = 128
_EPH_UNKNOWN = 65535  # MAVLink: UINT16_MAX = unknown

FLAG_NO_SOLUTION = "ekf_no_horizontal_solution"
FLAG_GPS_UNHEALTHY = "gps_sensor_unhealthy"
FLAGS = (FLAG_NO_SOLUTION, FLAG_GPS_UNHEALTHY)


def _int(v: Any) -> int | None:
    """A real int (not bool) or None: malformed payloads are ignored, never raised."""
    return v if isinstance(v, int) and not isinstance(v, bool) else None


class GpsHealthObserver:
    def __init__(self, stale_after_s: float = 2.0) -> None:
        self.stale_after_s = stale_after_s
        self._ekf_flags: int | None = None
        self._ekf_t: float | None = None
        self._gps_healthy: bool | None = None
        self._fix: int | None = None
        self._sats: int | None = None
        self._hdop: float | None = None
        self.decisions = 0
        self.flagged: dict[str, int] = dict.fromkeys(FLAGS, 0)

    def observe(self, msgname: str, fields: dict[str, Any], t: float) -> None:
        if msgname == "EKF_STATUS_REPORT":
            flags = _int(fields.get("flags"))
            if flags is not None:
                self._ekf_flags, self._ekf_t = flags, t
        elif msgname == "SYS_STATUS":
            present = _int(fields.get("onboard_control_sensors_present"))
            health = _int(fields.get("onboard_control_sensors_health"))
            if present is not None and health is not None:
                self._gps_healthy = bool(health & SENSOR_GPS) if present & SENSOR_GPS else None
        elif msgname == "GPS_RAW_INT":
            self._fix = _int(fields.get("fix_type"))
            self._sats = _int(fields.get("satellites_visible"))
            eph = _int(fields.get("eph"))
            self._hdop = None if eph is None or eph == _EPH_UNKNOWN else round(eph / 100.0, 2)

    def _solution(self, now: float) -> bool | None:
        if self._ekf_flags is None or self._ekf_t is None or now - self._ekf_t > self.stale_after_s:
            return None
        f = self._ekf_flags
        return bool(f & (EKF_POS_HORIZ_REL | EKF_POS_HORIZ_ABS)) and not f & EKF_CONST_POS_MODE

    def snapshot(self, now: float) -> dict[str, Any]:
        solution = self._solution(now)
        flags = []
        if solution is False:
            flags.append(FLAG_NO_SOLUTION)
        if self._gps_healthy is False:
            flags.append(FLAG_GPS_UNHEALTHY)
        return {
            "fix_type": self._fix, "satellites": self._sats, "hdop": self._hdop,
            "ekf_flags": self._ekf_flags,
            "ekf_age_s": None if self._ekf_t is None else round(now - self._ekf_t, 2),
            "horizontal_solution": solution, "gps_healthy": self._gps_healthy,
            "quality_flags": flags,
        }

    def tally(self, now: float) -> None:
        """Count one IDS decision against the conditions that hold at ``now`` (runner use)."""
        self.decisions += 1
        for flag in self.snapshot(now)["quality_flags"]:
            self.flagged[flag] += 1
