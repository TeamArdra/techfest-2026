"""Passive GPS / estimator health observer (``core/gps_health.py``) and its two consumers.

Status only: nothing here is read by a detector, raises an alert or changes a decision. The
observer reports what the VEHICLE says about its own position solution; it is not evidence that a
position is authentic. All inputs are SYNTHETIC unless a test says otherwise.
"""

from __future__ import annotations

from pymavlink.dialects.v20 import ardupilotmega as apm
from pymavlink.dialects.v20 import common

from aegisflight.backend.engine import LinkMonitor
from aegisflight.core.gps_health import GpsHealthObserver
from aegisflight.core.types import MessageEnvelope
from aegisflight.features.extractor import ekf_has_horizontal_solution
from aegisflight.sources.stream import TelemetryTick

GPS_BIT = 0x20  # MAV_SYS_STATUS_SENSOR_GPS
CONST_POS_FLAGS = 0xA7  # what the powered-on vehicle reported in 180 of 180 reports (BENCH, 2026-10-28)
SOLUTION_FLAGS = 0x1F  # attitude + horizontal velocity + vertical velocity + both horizontal-position bits


def _obs() -> GpsHealthObserver:
    return GpsHealthObserver(stale_after_s=2.0)


def test_constants_match_the_installed_dialects():
    from aegisflight.core import gps_health as g

    assert GPS_BIT == common.MAV_SYS_STATUS_SENSOR_GPS
    assert g.SENSOR_GPS == common.MAV_SYS_STATUS_SENSOR_GPS
    assert g.EKF_POS_HORIZ_REL == apm.EKF_POS_HORIZ_REL
    assert g.EKF_POS_HORIZ_ABS == apm.EKF_POS_HORIZ_ABS
    assert g.EKF_CONST_POS_MODE == apm.EKF_CONST_POS_MODE


def test_horizontal_solution_agrees_with_the_extractor_for_every_flag_byte():
    """One definition of 'horizontal solution' in the repo: the observer must agree with the extractor's."""
    for flags in range(256):
        o = _obs()
        o.observe("EKF_STATUS_REPORT", {"flags": flags}, 0.0)
        assert o.snapshot(0.0)["horizontal_solution"] is ekf_has_horizontal_solution(flags), hex(flags)


def test_nothing_received_is_unknown_never_false():
    snap = _obs().snapshot(5.0)
    assert snap["horizontal_solution"] is None and snap["gps_healthy"] is None
    assert snap["ekf_flags"] is None and snap["fix_type"] is None and snap["hdop"] is None
    assert snap["quality_flags"] == []


def test_const_pos_mode_report_is_flagged():
    o = _obs()
    o.observe("EKF_STATUS_REPORT", {"flags": CONST_POS_FLAGS}, 1.0)
    snap = o.snapshot(1.2)
    assert snap["horizontal_solution"] is False and snap["ekf_flags"] == CONST_POS_FLAGS
    assert snap["quality_flags"] == ["ekf_no_horizontal_solution"]


def test_horizontal_solution_report_is_not_flagged():
    o = _obs()
    o.observe("EKF_STATUS_REPORT", {"flags": SOLUTION_FLAGS}, 1.0)
    snap = o.snapshot(1.2)
    assert snap["horizontal_solution"] is True and snap["quality_flags"] == []


def test_a_stale_estimator_report_is_unknown_not_a_flag():
    """A link that stopped sending EKF_STATUS_REPORT must not keep asserting the last state forever."""
    o = _obs()
    o.observe("EKF_STATUS_REPORT", {"flags": CONST_POS_FLAGS}, 1.0)
    snap = o.snapshot(1.0 + 2.5)
    assert snap["horizontal_solution"] is None and snap["quality_flags"] == []
    assert snap["ekf_age_s"] == 2.5


def test_gps_unhealthy_bit_is_flagged_only_when_the_sensor_is_present():
    o = _obs()
    o.observe("SYS_STATUS", {"onboard_control_sensors_present": GPS_BIT | 1,
                             "onboard_control_sensors_health": 1}, 1.0)  # present, health bit clear
    assert o.snapshot(1.0)["gps_healthy"] is False
    assert o.snapshot(1.0)["quality_flags"] == ["gps_sensor_unhealthy"]

    o.observe("SYS_STATUS", {"onboard_control_sensors_present": GPS_BIT | 1,
                             "onboard_control_sensors_health": GPS_BIT | 1}, 2.0)
    assert o.snapshot(2.0)["gps_healthy"] is True and o.snapshot(2.0)["quality_flags"] == []

    o.observe("SYS_STATUS", {"onboard_control_sensors_present": 1, "onboard_control_sensors_health": 1}, 3.0)
    assert o.snapshot(3.0)["gps_healthy"] is None  # no GPS sensor declared: unknown, not unhealthy


def test_gps_raw_int_quality_is_passed_through_without_a_threshold():
    o = _obs()
    o.observe("GPS_RAW_INT", {"fix_type": 3, "satellites_visible": 7, "eph": 809}, 1.0)
    snap = o.snapshot(1.0)
    assert snap["fix_type"] == 3 and snap["satellites"] == 7 and snap["hdop"] == 8.09
    assert snap["quality_flags"] == []  # a poor HDOP alone is reported, not judged
    o.observe("GPS_RAW_INT", {"fix_type": 3, "satellites_visible": 7, "eph": 65535}, 2.0)
    assert o.snapshot(2.0)["hdop"] is None  # 65535 = unknown in MAVLink


def test_both_vehicle_reported_conditions_together():
    o = _obs()
    o.observe("SYS_STATUS", {"onboard_control_sensors_present": GPS_BIT, "onboard_control_sensors_health": 0}, 1.0)
    o.observe("EKF_STATUS_REPORT", {"flags": CONST_POS_FLAGS}, 1.0)
    assert o.snapshot(1.1)["quality_flags"] == ["ekf_no_horizontal_solution", "gps_sensor_unhealthy"]


def test_tally_counts_each_flagged_decision():
    o = _obs()
    o.observe("EKF_STATUS_REPORT", {"flags": CONST_POS_FLAGS}, 0.0)
    for t in (0.2, 0.4, 0.6):
        o.tally(t)
    o.observe("EKF_STATUS_REPORT", {"flags": SOLUTION_FLAGS}, 0.7)
    o.tally(0.8)
    assert o.decisions == 4
    assert o.flagged == {"ekf_no_horizontal_solution": 3, "gps_sensor_unhealthy": 0}


def test_malformed_fields_never_raise():
    o = _obs()
    o.observe("EKF_STATUS_REPORT", {}, 1.0)
    o.observe("EKF_STATUS_REPORT", {"flags": "x"}, 1.0)
    o.observe("SYS_STATUS", {"onboard_control_sensors_present": None}, 1.0)
    o.observe("GPS_RAW_INT", {"eph": "bad"}, 1.0)
    assert o.snapshot(1.0)["quality_flags"] == []


# --- consumer 1: the dashboard's link.gps block ------------------------------------------------- #

def _env(name: str, t: float, **fields) -> MessageEnvelope:
    return MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=0, msgname=name, seq=0, signed=False,
                           byte_len=0, fields=fields)


def test_link_monitor_gps_block_carries_the_health_keys_additively():
    lm = LinkMonitor(stale_after_s=3.0, min_fix=3, min_sats=5)
    lm.observe(TelemetryTick(t=1.0, tick=0, messages=[
        _env("GPS_RAW_INT", 1.0, fix_type=3, satellites_visible=7, eph=809),
        _env("SYS_STATUS", 1.0, onboard_control_sensors_present=GPS_BIT, onboard_control_sensors_health=0),
        _env("EKF_STATUS_REPORT", 1.0, flags=CONST_POS_FLAGS)]))
    gps = lm.snapshot()["gps"]
    # the pre-existing keys keep their meaning: a 3D fix with 7 satellites is still 'valid_fix' ...
    assert gps["fix_type"] == 3 and gps["satellites"] == 7 and gps["valid_fix"] is True
    # ... and the new keys say what the vehicle itself reports about that position
    assert gps["horizontal_solution"] is False and gps["gps_healthy"] is False and gps["hdop"] == 8.09
    assert gps["quality_flags"] == ["ekf_no_horizontal_solution", "gps_sensor_unhealthy"]
    assert gps["ekf_flags"] == CONST_POS_FLAGS


def test_link_monitor_without_estimator_messages_reports_unknown():
    lm = LinkMonitor(stale_after_s=3.0, min_fix=3, min_sats=5)
    lm.observe(TelemetryTick(t=1.0, tick=0, messages=[_env("GPS_RAW_INT", 1.0, fix_type=3, satellites_visible=10, eph=100)]))
    gps = lm.snapshot()["gps"]
    assert gps["horizontal_solution"] is None and gps["gps_healthy"] is None and gps["quality_flags"] == []
