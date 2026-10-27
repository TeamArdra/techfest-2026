"""Fused-level GPS scenario tests: discontinuity, velocity mismatch, drift, recovery, wander.

``test_missing_telemetry_fused.py`` covers GPS *availability* (never received, fix never acquired /
lost, dropout while other telemetry continues) on a stationary vehicle. These tests cover GPS
*content* on a MOVING vehicle: they run the REAL ``IDSPipeline`` (ML off, no firmware verifier:
what ``scripts/hardware/run_serial_ids.py`` and ``aegis serve --source serial`` build) on synthetic
MAVLink envelopes and assert on the fused ``ThreatAssessment``. No hardware, no sockets. One test
turns the ML detector on (stated in its docstring).

Environment: SIM (synthetic envelopes), except the two REPLAY-of-BENCH tests at the end. A positive
result shows the rule fires on the fixture; it is not evidence of real-world spoofing detection. Every
adversarial case below is SIM. Two kinds of test:

* ``GENUINE`` -- an expectation that follows from the documented rule (``docs/DETECTION.md``).
* ``KNOWN LIMITATION`` -- pins the CURRENT outcome of a case the rules cannot distinguish (a missed
  drift, a false alarm). It documents behaviour; it is not a requirement. Changing it is a detector
  policy decision (``docs/GPS_WORKSTREAM_PLAN.md``), not a test fix.

Thresholds are read from the loaded config, never hard-coded.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pymavlink.dialects.v20 import ardupilotmega as apm

from aegisflight.config import AegisConfig, load_config
from aegisflight.core.enums import AttackType, DetectorName, IntegrityStatus, Severity
from aegisflight.core.types import DetectorResult, MessageEnvelope, ThreatAssessment
from aegisflight.features.extractor import (
    _LINK_GAP_S,
    _RESID_CLAMP_M,
    _RESID_WINDOW,
    FeatureExtractor,
    FeatureFrame,
)
from aegisflight.fusion.engine import FusionEngine
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.mavlink_live import frame_ticks
from aegisflight.sources.stream import TelemetryTick

TICK_HZ = 10  # simulation.sample_rate_hz; decisions at 5 Hz
GPI_HZ = 5  # GLOBAL_POSITION_INT rate in this fixture
LAT0, LON0 = 12.9, 77.5  # synthetic origin
M_PER_DEG = 111_320.0
SPEED = 10.0  # m/s east, the nominal track
ONSET = 20.0  # s; every scenario is clean before this
_PHYS = load_config().detector["physics"]
RESID_M = _PHYS["gps_pos_residual_m"]
RESID_HARD_M = _PHYS["gps_pos_residual_hard_m"]
SPEED_CONS_MS = _PHYS["gps_speed_consistency_ms"]
RESID_WINDOW_S = _RESID_WINDOW / GPI_HZ  # the residual sums the last _RESID_WINDOW position increments
EKF_HZ = 2  # EKF_STATUS_REPORT rate in this fixture (the bench and ALFA stream it at ~2 Hz)
# EKF_STATUS_REPORT.flags built from the installed dialect; the two values observed on real data:
EKF_SOLUTION = (apm.EKF_ATTITUDE | apm.EKF_VELOCITY_HORIZ | apm.EKF_VELOCITY_VERT | apm.EKF_POS_HORIZ_REL
                | apm.EKF_POS_HORIZ_ABS | apm.EKF_POS_VERT_ABS | apm.EKF_PRED_POS_HORIZ_REL
                | apm.EKF_PRED_POS_HORIZ_ABS)  # 0x033f: ALFA in flight
EKF_CONST_POS = (apm.EKF_ATTITUDE | apm.EKF_VELOCITY_HORIZ | apm.EKF_VELOCITY_VERT | apm.EKF_POS_VERT_ABS
                 | apm.EKF_CONST_POS_MODE)  # 0x00a7: the bench Pixhawk 6X (telemetry_radio_008/009)
NAV_NOTE = "navigation: estimator reports no horizontal position solution"
VEL_IMPLIES = "estimator reports no horizontal solution but its velocity implies"
DISCONTINUITY = "position discontinuity"
PHYSICS = DetectorName.PHYSICS.value
_REPO = Path(__file__).resolve().parents[2]

State = dict[str, Any]


class _Link:
    """One autopilot (1/1) with ONE running sequence counter, as a real flight controller has."""

    def __init__(self) -> None:
        self._seq = -1

    def env(self, t: float, name: str, msgid: int, **fields) -> MessageEnvelope:
        self._seq = (self._seq + 1) % 256
        return MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=msgid, msgname=name,
                               seq=self._seq, signed=False, byte_len=28, fields=fields)


def _messages(link: _Link, k: int, t: float, s: State) -> list[MessageEnvelope]:
    """Tick ``k``: HEARTBEAT/SYS_STATUS/GPS_RAW_INT 1 Hz, GLOBAL_POSITION_INT 5 Hz, ATTITUDE/VFR_HUD
    10 Hz, EKF_STATUS_REPORT 2 Hz when ``s["ekf"]`` holds flags (absent/None = not sent; it is sent
    BEFORE the same tick's GLOBAL_POSITION_INT). Reported position (north/east, m) and GPS velocity
    (vn/ve) come from ``s``; yaw follows the GPS course, VFR groundspeed = GPS speed unless
    ``s["vfr_gs"]`` is set; ``s["raw"]`` = (fix_type, satellites), default a healthy (3, 10), None =
    no GPS_RAW_INT."""
    vn, ve = s["vn"], s["ve"]
    speed = math.hypot(vn, ve)
    yaw = math.atan2(ve, vn) if speed > 0.1 else 0.5
    out: list[MessageEnvelope] = []
    raw = s.get("raw", (3, 10))
    if k % TICK_HZ == 0:
        out.append(link.env(t, "HEARTBEAT", 0, base_mode=81 | 128, custom_mode=3))
        out.append(link.env(t, "SYS_STATUS", 1, voltage_battery=16000, battery_remaining=90))
        if raw is not None:
            out.append(link.env(t, "GPS_RAW_INT", 24, satellites_visible=raw[1], fix_type=raw[0],
                                eph=s.get("eph", 100)))
    if s.get("ekf") is not None and k % (TICK_HZ // EKF_HZ) == 0:
        out.append(link.env(t, "EKF_STATUS_REPORT", 193, flags=s["ekf"], velocity_variance=0.0,
                            pos_horiz_variance=0.0, pos_vert_variance=0.0, compass_variance=0.0,
                            terrain_alt_variance=0.0, airspeed_variance=0.0))
    if k % 2 == 0:
        lat = LAT0 + s["north"] / M_PER_DEG
        lon = LON0 + s["east"] / (M_PER_DEG * math.cos(math.radians(LAT0)))
        out.append(link.env(t, "GLOBAL_POSITION_INT", 33, lat=int(round(lat * 1e7)),
                            lon=int(round(lon * 1e7)), alt=960000, relative_alt=60000,
                            vx=int(round(vn * 100)), vy=int(round(ve * 100)), vz=0,
                            hdg=int(math.degrees(yaw) % 360 * 100)))
    out.append(link.env(t, "ATTITUDE", 30, roll=0.0, pitch=0.0, yaw=yaw, rollspeed=0.0,
                        pitchspeed=0.0, yawspeed=0.0))
    out.append(link.env(t, "VFR_HUD", 74, groundspeed=s.get("vfr_gs", speed),
                        heading=int(math.degrees(yaw) % 360), throttle=50, alt=960.0, climb=0.0))
    return out


def _run(traj: Callable[[float], State], seconds: float = 60.0, cfg: AegisConfig | None = None,
         model_path: str | None = None, frames: list[FeatureFrame] | None = None) -> list[ThreatAssessment]:
    """Run the pipeline on ``traj``; ``frames`` (if given) receives the FeatureFrame of each decision."""
    pipe = IDSPipeline(cfg if cfg is not None else load_config(), model_path=model_path, firmware_dir=None)
    link = _Link()
    out: list[ThreatAssessment] = []
    for k in range(int(round(seconds * TICK_HZ))):
        t = k / TICK_HZ
        a = pipe.process_tick(TelemetryTick(t=t, tick=k, messages=_messages(link, k, t, traj(t))))
        if a is not None:
            out.append(a)
            if frames is not None:
                assert pipe.last_frame is not None
                frames.append(pipe.last_frame)
    return out


def _gate_off() -> AegisConfig:
    cfg = load_config()
    cfg.detector["physics"]["estimator_gate"] = False
    return cfg


def _verdicts(rows: list[ThreatAssessment]) -> list[tuple]:
    """Everything a decision reports except wall-clock time and measured latency."""
    return [(a.t, a.threat, a.is_alert, a.attack_type, a.severity, a.threat_score, a.confidence,
             tuple(a.secondary_indicators), tuple(a.evidence), tuple(sorted(a.detector_scores.items())),
             tuple(a.contributing_detectors)) for a in rows]


def _alerts(rows: list[ThreatAssessment], attack: AttackType | None = None) -> list[ThreatAssessment]:
    return [a for a in rows if a.is_alert and (attack is None or a.attack_type == attack)]


def _quiet_before_onset(rows: list[ThreatAssessment]) -> None:
    assert not any(a.threat for a in rows if a.t < ONSET), "scenario is not clean before onset"


def _east(t: float, **over: float) -> State:
    """The nominal track: east at SPEED, GPS velocity truthful."""
    return {"north": 0.0, "east": SPEED * t, "vn": 0.0, "ve": SPEED, **over}


def _still(t: float, **over: float) -> State:
    """Stationary at the origin, GPS velocity 0."""
    return {"north": 0.0, "east": 0.0, "vn": 0.0, "ve": 0.0, **over}


# --------------------------------------------------------------------------- #
# healthy movement must not alarm (scenario 9)
# --------------------------------------------------------------------------- #


def _turn(t: float) -> State:
    """Straight east, then a constant-speed 90 deg left turn (radius 100 m), then north."""
    r = 100.0
    if t < ONSET:
        return _east(t)
    th = (t - ONSET) * SPEED / r
    if th <= math.pi / 2:
        return {"north": r * (1 - math.cos(th)), "east": SPEED * ONSET + r * math.sin(th),
                "vn": SPEED * math.sin(th), "ve": SPEED * math.cos(th)}
    t2 = t - ONSET - (math.pi / 2) * r / SPEED
    return {"north": r + SPEED * t2, "east": SPEED * ONSET + r, "vn": SPEED, "ve": 0.0}


@pytest.mark.parametrize("traj", [_east, _turn, lambda t: _east(t, east=0.0, ve=0.0)],
                         ids=["straight", "turn", "stationary"])
def test_healthy_movement_is_quiet(traj):
    """GENUINE. A coherent track (position, GPS velocity, heading and groundspeed agree) gives no
    threat at all: every alert below is caused by its scenario, not by the generator."""
    rows = _run(traj)
    assert rows and not any(a.threat for a in rows)


# --------------------------------------------------------------------------- #
# position discontinuity (scenario 5) and recovery (scenario 8)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("jump_m", "severity"), [(50.0, Severity.CRITICAL), (20.0, Severity.SUSPICIOUS)])
def test_position_jump_alerts_gps_spoofing_at_onset(jump_m, severity):
    """GENUINE. A sudden position jump with a truthful velocity is a position residual: CRITICAL at
    or above the hard threshold, SUSPICIOUS between the soft and hard thresholds, within one decision."""
    assert RESID_M < 20.0 < RESID_HARD_M <= 50.0
    rows = _run(lambda t: _east(t, north=jump_m if t >= ONSET else 0.0))
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET <= first.t <= ONSET + 0.2
    assert first.severity == severity
    assert any("position residual" in e for e in first.evidence)


def test_jump_residual_is_reported_clipped_not_at_the_true_offset():
    """KNOWN LIMITATION. The extractor clamps each GPS increment's residual at _RESID_CLAMP_M, so a
    single 200 m jump is reported as the clamp value, not as 200 m. The verdict is right; the
    evidence understates the size. (Several increments in one window can still sum above it.)"""
    rows = _run(lambda t: _east(t, north=200.0 if t >= ONSET else 0.0))
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert first.severity == Severity.CRITICAL
    assert any(f"position residual {_RESID_CLAMP_M:.1f} m" in e for e in first.evidence)


def test_constant_offset_after_a_jump_is_forgotten_within_the_residual_window():
    """KNOWN LIMITATION (constant-offset caveat, ``docs/REPORT_ALIGNMENT.md``). After the jump the
    track is coherent again, so the threat clears once the jump leaves the residual window and the
    offset position is never re-alerted. Only the jump is detected, not the falsified position."""
    rows = _run(lambda t: _east(t, north=50.0 if t >= ONSET else 0.0))
    assert len(_alerts(rows)) == 1
    assert not any(a.threat for a in rows if a.t > ONSET + RESID_WINDOW_S)


def test_recovery_from_an_offset_alerts_on_the_return_jump_then_clears():
    """GENUINE (recovery). A 200 m offset during 10 s and then the true track: the return is
    itself a discontinuity (a second alert), after which the assessment goes quiet within the
    residual window and stays quiet."""
    end = ONSET + 10.0
    rows = _run(lambda t: _east(t, north=200.0 if ONSET <= t < end else 0.0))
    _quiet_before_onset(rows)
    starts = [a.t for a in _alerts(rows, AttackType.GPS_SPOOFING)]
    assert len(starts) == 2 and starts[0] < end <= starts[1] <= end + 0.2
    assert not any(a.threat for a in rows if a.t > end + RESID_WINDOW_S)


# --------------------------------------------------------------------------- #
# position-derived vs reported velocity (scenario 6)
# --------------------------------------------------------------------------- #


def test_position_moving_while_reported_velocity_is_zero_alerts_gps_spoofing():
    """GENUINE. The position advances at SPEED while the reported GPS velocity says 0: the
    dead-reckoned residual grows by SPEED x dt and crosses the soft threshold within ~1.6 s."""
    rows = _run(lambda t: {"north": 0.0, "east": SPEED * max(0.0, t - ONSET), "vn": 0.0, "ve": 0.0})
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + RESID_M / SPEED + 0.6


def test_gps_speed_vs_groundspeed_mismatch_alerts_telemetry_manipulation():
    """GENUINE. GPS velocity says SPEED, VFR groundspeed says 0 (> gps_speed_consistency_ms):
    TELEMETRY_MANIPULATION, not GPS_SPOOFING (the position track itself is coherent)."""
    assert SPEED > SPEED_CONS_MS
    rows = _run(lambda t: _east(t, **({"vfr_gs": 0.0} if t >= ONSET else {})))
    _quiet_before_onset(rows)
    first = _alerts(rows)[0]
    assert first.attack_type == AttackType.TELEMETRY_MANIPULATION
    assert ONSET <= first.t <= ONSET + 0.2
    assert not _alerts(rows, AttackType.GPS_SPOOFING)


# --------------------------------------------------------------------------- #
# gradual drift (scenario 7): what the evidence can and cannot show
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("rate_ms", [0.5, 2.0])
def test_slow_lat_lon_drift_with_truthful_velocity_is_not_detected(rate_ms):
    """KNOWN LIMITATION. The residual is a sum over a ~3 s window, so a lat/lon drift is visible
    only above RESID_M / window (~4 m/s at Stage-1 settings). Slower drift is never flagged."""
    assert rate_ms * RESID_WINDOW_S < RESID_M
    rows = _run(lambda t: _east(t, north=rate_ms * max(0.0, t - ONSET)))
    assert not any(a.threat for a in rows)


@pytest.mark.parametrize("rate_ms", [5.0, 8.0])
def test_fast_lat_lon_drift_with_truthful_velocity_alerts_gps_spoofing(rate_ms):
    """GENUINE. Above the window floor the drift is a sustained residual: GPS_SPOOFING within
    ~3 s and threats for the rest of the drift."""
    assert rate_ms * RESID_WINDOW_S > RESID_M
    rows = _run(lambda t: _east(t, north=rate_ms * max(0.0, t - ONSET)))
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + RESID_WINDOW_S
    assert all(a.threat for a in rows if a.t > ONSET + RESID_WINDOW_S)


@pytest.mark.parametrize("rate_ms", [5.0, 8.0])
def test_velocity_consistent_drift_is_not_detected(rate_ms):
    """KNOWN LIMITATION (``docs/GPS_WORKSTREAM_PLAN.md`` section 7, missing scenario 1). When the
    reported velocity and heading follow the falsified track, every cross-check agrees and nothing
    fires, even at rates the residual catches with a truthful velocity (the test above). Without an
    independent position reference this case is indistinguishable from a manoeuvre."""
    assert rate_ms * RESID_WINDOW_S > RESID_M
    rows = _run(lambda t: _east(t, north=rate_ms * max(0.0, t - ONSET),
                                vn=rate_ms if t >= ONSET else 0.0))
    assert not any(a.threat for a in rows)


# --------------------------------------------------------------------------- #
# stationary GNSS position wander (BENCH observation, telemetry_radio_008 / serve session)
# --------------------------------------------------------------------------- #


def _wander(t: float) -> State:
    """Stationary, GPS velocity 0, a valid fix, reported position wandering ~10-15 m (deterministic):
    the shape seen on the physical bench under poor sky view (ArduCopter EKF in constant-position
    mode reports the receiver's position with zero velocity)."""
    k = int(t / 0.5)
    return {"north": 15.0 * math.sin(0.7 * k) * math.sin(0.13 * k),
            "east": 12.0 * math.sin(0.41 * k + 1.0), "vn": 0.0, "ve": 0.0}


def test_stationary_gnss_wander_with_a_valid_fix_raises_false_gps_spoofing_alerts():
    """KNOWN LIMITATION (false positive) on a link WITHOUT estimator status. The residual rule
    assumes position and velocity are one coherent navigation solution and is not gated on GNSS
    quality. Position wander with zero velocity therefore reads as a diverging track: GPS_SPOOFING
    alerts on a vehicle that is not moving and not attacked. Once EKF_STATUS_REPORT has reported no
    horizontal solution continuously for _LINK_GAP_S, the estimator gate applies (section "estimator
    state" below); a link that never sends EKF_STATUS_REPORT (PX4 / ArduPilot SITL as captured,
    Stage-1 SIM) keeps this behaviour."""
    rows = _run(_wander)
    spoof = _alerts(rows, AttackType.GPS_SPOOFING)
    assert len(spoof) >= 10
    assert {a.attack_type for a in _alerts(rows)} == {AttackType.GPS_SPOOFING}


# --------------------------------------------------------------------------- #
# estimator state (EKF_STATUS_REPORT): benign cases
# --------------------------------------------------------------------------- #


def _with(traj: Callable[[float], State], **over: Any) -> Callable[[float], State]:
    """``traj`` with extra per-tick state (``ekf``, ``raw``, ...); a callable value is evaluated at t."""
    return lambda t: {**traj(t), **{k: (v(t) if callable(v) else v) for k, v in over.items()}}


def _nav_notes(rows: list[ThreatAssessment]) -> int:
    return sum(any(e.startswith(NAV_NOTE) for e in a.evidence) for a in rows)


def _has(a: ThreatAssessment, text: str) -> bool:
    return any(text in e for e in a.evidence)


def test_ekf_flag_values_come_from_the_dialect_and_match_the_observed_streams():
    """GENUINE. The fixture's flags are built from pymavlink's ardupilotmega EKF_STATUS_FLAGS and
    equal the values seen on real streams (ALFA in flight 0x033f; the bench 0x00a7)."""
    from aegisflight.features.extractor import ekf_has_horizontal_solution as solution

    assert (EKF_SOLUTION, EKF_CONST_POS) == (0x033F, 0x00A7)
    assert solution(EKF_SOLUTION)
    assert not solution(EKF_CONST_POS)
    assert not solution(0)  # an empty report: no solution
    assert not solution(EKF_SOLUTION | apm.EKF_CONST_POS_MODE)  # contradictory: CONST_POS wins
    assert solution(apm.EKF_POS_HORIZ_REL) and solution(apm.EKF_POS_HORIZ_ABS)


@pytest.mark.parametrize("amp_m", [2.0, 1.0], ids=["low", "very-low"])
@pytest.mark.parametrize("ekf", [None, EKF_CONST_POS], ids=["no-ekf", "const-pos"])
def test_stationary_low_amplitude_wander_is_quiet(amp_m, ekf):
    """GENUINE (benign 1). Wander of a few metres stays below the soft threshold with and without
    CONST_POS status: the gate is not what keeps a good receiver quiet."""
    rows = _run(_with(lambda t: {k: v * amp_m / 15.0 if k in ("north", "east") else v
                                 for k, v in _wander(t).items()}, ekf=ekf))
    assert not any(a.threat for a in rows)


def test_stationary_large_wander_with_const_pos_estimator_is_degraded_navigation_not_spoofing():
    """GENUINE (benign 2; the bench mechanism, telemetry_radio_008/009). The same wander that raises
    false GPS_SPOOFING alerts without estimator status is quiet when EKF_STATUS_REPORT says
    CONST_POS_MODE from the first report (t = 0) on. Fixes are gated from t = _LINK_GAP_S (the
    debounce); from then on every decision carries the score-0 degraded-navigation line. Before it
    the Stage-1 rule applies, and in this fixture the wander has not built a residual above the soft
    threshold by then."""
    rows = _run(_with(_wander, ekf=EKF_CONST_POS))
    assert not any(a.threat for a in rows)
    assert _nav_notes(rows) == sum(a.t >= _LINK_GAP_S for a in rows)


def test_estimator_gate_false_restores_the_stage1_rule():
    """GENUINE. ``physics.estimator_gate: false`` ignores estimator state: the wander alerts again."""
    rows = _run(_with(_wander, ekf=EKF_CONST_POS), cfg=_gate_off())
    assert len(_alerts(rows, AttackType.GPS_SPOOFING)) >= 10
    assert _nav_notes(rows) == 0


def _accelerate(t: float) -> State:
    """East from rest, 2 m/s^2 up to 15 m/s, then constant."""
    a, vmax = 2.0, 15.0
    tc = vmax / a
    if t < tc:
        return {"north": 0.0, "east": 0.5 * a * t * t, "vn": 0.0, "ve": a * t}
    return {"north": 0.0, "east": 0.5 * a * tc * tc + vmax * (t - tc), "vn": 0.0, "ve": vmax}


@pytest.mark.parametrize("traj", [_east, _turn, _accelerate], ids=["straight", "turn", "accelerate"])
def test_healthy_movement_with_a_healthy_estimator_is_quiet(traj):
    """GENUINE (benign 3, 4). A coherent track with EKF_STATUS_REPORT reporting a solution."""
    rows = _run(_with(traj, ekf=EKF_SOLUTION))
    assert rows and not any(a.threat for a in rows)
    assert _nav_notes(rows) == 0


def _fix_lost_and_recovered(t: float) -> State:
    """Stationary. 0-20 s healthy fix + solution; 20-40 s the fix degrades (2D, 3 sats) and the EKF
    drops to CONST_POS_MODE while the position wanders; from 40 s fix + solution again, with the
    estimator snapping 15 m (a reset; above the soft threshold) at the moment the solution returns."""
    base = {"north": 0.0, "east": 0.0, "vn": 0.0, "ve": 0.0}
    if t < ONSET:
        return {**base, "ekf": EKF_SOLUTION}
    if t < ONSET + 20.0:
        return {**_wander(t), "raw": (2, 3), "ekf": EKF_CONST_POS}
    return {**base, "north": 15.0, "ekf": EKF_SOLUTION}


def test_fix_degradation_loss_and_recovery_alerts_only_the_gnss_rule_after_the_debounce():
    """GENUINE (benign 5) after the debounce; KNOWN LIMITATION (debounce cost) inside it.

    Expected outcome changed for v2 (2026-10-26). The estimator's no-solution state gates fixes only
    after it has been reported continuously for _LINK_GAP_S. In this fixture the wander starts at the
    same instant as the first CONST_POS report, so the first _LINK_GAP_S of wander is judged by the
    Stage-1 rule, exactly as on a link without estimator status, and here raises GPS_SPOOFING (v1 had
    no debounce and stayed quiet, but a single forged report could then gate a fix). After the
    debounce: fix loss is the GNSS rule's DOS alert, as designed; the wander is degraded navigation
    (physics scores 0); the 15 m estimator reset when the solution returns falls on the transition
    fix, is left out of the residual and is below the hard jump threshold; afterwards all quiet."""
    rows = _run(_fix_lost_and_recovered)
    _quiet_before_onset(rows)
    assert _alerts(rows, AttackType.DOS), "the GNSS fix-loss rule should alert"
    debounce_end = ONSET + _LINK_GAP_S
    assert all(a.t < debounce_end for a in _alerts(rows, AttackType.GPS_SPOOFING))
    assert not any(a.threat and a.attack_type == AttackType.GPS_SPOOFING for a in rows if a.t >= debounce_end)
    assert all(a.detector_scores.get(PHYSICS, 0.0) == 0.0 for a in rows if a.t >= debounce_end)
    assert _nav_notes(rows) > 0
    assert not any(a.threat for a in rows if a.t > ONSET + 20.0 + 1.0)


def _ekf_until(stop: float, flags: int) -> Callable[[float], int | None]:
    return lambda t: flags if t < stop else None


def test_estimator_status_that_stops_is_stale_after_the_link_gap_and_the_rule_resumes():
    """GENUINE (benign 6). CONST_POS reports stop at ONSET (last one at ONSET - 1/EKF_HZ) while the
    wander continues. Fixes stay gated while that last report is at most _LINK_GAP_S old; the first
    fix after that is not gated (a stale report never gates) and is the transition fix, and the
    Stage-1 rule rebuilds on the following increments (here: the wander alerts). So a stale status
    silences the residual for at most _LINK_GAP_S after its last report, not indefinitely."""
    rows = _run(_with(_wander, ekf=_ekf_until(ONSET, EKF_CONST_POS)))
    assert not any(a.threat for a in rows if a.t < ONSET)
    spoof = _alerts(rows, AttackType.GPS_SPOOFING)
    assert spoof and spoof[0].t > ONSET + _LINK_GAP_S
    assert not any(any(e.startswith(NAV_NOTE) for e in a.evidence) for a in rows
                   if a.t > ONSET + _LINK_GAP_S + 0.4)


def test_estimator_status_never_received_leaves_the_frame_fields_at_their_defaults():
    """GENUINE (benign 6). Without EKF_STATUS_REPORT the new frame fields keep their defaults (None /
    False / 0.0) and the physics rule reads ``pos_residual_m`` (see the next test for decisions)."""
    frames: list[FeatureFrame] = []
    _run(_east, seconds=5.0, frames=frames)
    f = frames[-1]
    assert (f.ekf_flags, f.ekf_age_s, f.nav_solution, f.nav_gated, f.pos_residual_nav_m,
            f.pos_step_max_m, f.pos_vel_shortfall_gated_m) == (None, None, None, False, None, 0.0, 0.0)


@pytest.mark.parametrize("traj", [
    _wander,
    lambda t: _east(t, north=50.0 if t >= ONSET else 0.0),
    lambda t: _east(t, north=5.0 * max(0.0, t - ONSET)),
    lambda t: _still(t, east=SPEED * max(0.0, t - ONSET)),
], ids=["wander", "jump-50m", "drift-5ms", "zero-velocity-walk"])
def test_without_estimator_status_the_gate_changes_no_decision(traj):
    """GENUINE. On a link that never sends EKF_STATUS_REPORT, the decisions with the gate on (the
    default) and off are identical in every reported field (wall-clock time and latency excluded),
    on fixtures that alert. This is the in-test form of "inert while no report is received"."""
    on = _run(traj)
    assert any(a.threat for a in on)
    assert _verdicts(on) == _verdicts(_run(traj, cfg=_gate_off()))


def test_nav_residual_equals_the_stage1_residual_whenever_the_window_holds_no_gated_fix():
    """GENUINE (property). ``pos_residual_nav_m`` is exactly ``pos_residual_m`` (float equality)
    whenever no fix in the residual window was gated or transitional: with a solution reported, and
    during the debounce, and again once the transition fix has left the window. It differs while the
    window holds gated increments (so the check is not vacuous). Fixture: truthful velocity, 3 m/s
    north drift (non-zero residual); CONST_POS reports from ONSET to ONSET + 10 s."""
    end = ONSET + 10.0
    frames: list[FeatureFrame] = []
    _run(_with(lambda t: _east(t, north=3.0 * t),
               ekf=lambda t: EKF_CONST_POS if ONSET <= t < end else EKF_SOLUTION), frames=frames)
    clean = [f for f in frames if f.t < ONSET + _LINK_GAP_S or f.t >= end + RESID_WINDOW_S + 0.2]
    assert clean and all(f.pos_residual_m > 1.0 for f in clean if f.t > RESID_WINDOW_S)
    assert all(f.pos_residual_nav_m == f.pos_residual_m for f in clean)
    assert all(f.pos_step_max_m == 0.0 and f.pos_vel_shortfall_gated_m == 0.0 for f in clean)
    gated = [f for f in frames if f.nav_gated]
    assert gated and all(ONSET + _LINK_GAP_S <= f.t < end for f in gated)
    assert any(f.pos_residual_nav_m != f.pos_residual_m for f in frames if f.t >= ONSET + _LINK_GAP_S)


def test_contradictory_status_claiming_a_solution_does_not_hide_wander():
    """GENUINE (benign 7, contradictory). EKF says it has a solution, yet the velocity is zero while
    the position wanders: the estimator's claim is not trusted to override the cross-check, so the
    residual rule applies (and alerts). Only a sustained report of NO solution changes the rule."""
    rows = _run(_with(_wander, ekf=EKF_SOLUTION))
    assert len(_alerts(rows, AttackType.GPS_SPOOFING)) >= 10


def test_status_reports_within_one_tick_are_applied_in_arrival_order():
    """GENUINE (benign 7, same-tick burst; this is arrival order within one tick, not a reordering
    test). When a SOLUTION and then a CONST_POS report arrive in the same tick, the one received last
    is the current state. The SOLUTION report restarts the no-solution run each time, so the burst
    never gates a fix."""
    cfg = load_config()
    pipe = IDSPipeline(cfg, model_path=None, firmware_dir=None)
    link = _Link()
    for k in range(40):
        t = k / TICK_HZ
        msgs = _messages(link, k, t, _east(t))
        if k % 5 == 0:
            for flags in (EKF_SOLUTION, EKF_CONST_POS):
                msgs.append(link.env(t, "EKF_STATUS_REPORT", 193, flags=flags))
        pipe.process_tick(TelemetryTick(t=t, tick=k, messages=msgs))
    f = pipe.last_frame
    assert f is not None and f.ekf_flags == EKF_CONST_POS
    assert f.nav_solution is False and f.nav_gated is False


def test_estimator_reset_jump_one_fix_after_the_solution_returns_still_alerts():
    """KNOWN LIMITATION (benign 8). If the estimator's reset jump reaches GLOBAL_POSITION_INT one fix
    AFTER the flags report the solution, the jump falls on an ordinary fix (not gated, not the
    transition fix), and the Stage-1 rule reads it as a 20 m residual (GPS_SPOOFING); only a jump on
    the transition fix itself is left out. Whether ArduPilot's ordering puts the two together was not
    measured."""
    lag = 1.0 / GPI_HZ

    def traj(t: float) -> State:
        if t < ONSET:
            return {**_wander(t), "ekf": EKF_CONST_POS}
        return {"north": 20.0 if t >= ONSET + lag else 0.0, "east": 0.0, "vn": 0.0, "ve": 0.0,
                "ekf": EKF_SOLUTION}

    rows = _run(traj)
    assert not any(a.threat for a in rows if a.t < ONSET)
    assert _alerts(rows, AttackType.GPS_SPOOFING)


def test_temporary_discontinuity_with_a_healthy_estimator_recovers():
    """GENUINE (benign 8). A 20 m glitch for 1 s under a healthy estimator alerts at the jump and at
    the return (it is a discontinuity either way) and is quiet again within the residual window."""
    rows = _run(_with(lambda t: _east(t, north=20.0 if ONSET <= t < ONSET + 1.0 else 0.0), ekf=EKF_SOLUTION))
    assert _alerts(rows, AttackType.GPS_SPOOFING)
    assert not any(a.threat for a in rows if a.t > ONSET + 1.0 + RESID_WINDOW_S)


@pytest.mark.parametrize("reset_m", [20.0, 25.0])
def test_estimator_reset_below_the_hard_threshold_at_the_transition_fix_is_quiet(reset_m):
    """GENUINE (transition). Stationary under sustained CONST_POS; at ONSET the solution returns and
    the position snaps by ``reset_m`` (< hard) on that same fix. That fix is the gated -> ungated
    transition fix: its increment is left out of the residual and (velocity 0) its residual
    increment is below the hard jump threshold, so nothing fires (the Stage-1 rule would read
    20-25 m as SUSPICIOUS)."""
    assert RESID_M < reset_m < RESID_HARD_M
    rows = _run(lambda t: _still(t, north=reset_m if t >= ONSET else 0.0,
                                 ekf=EKF_CONST_POS if t < ONSET else EKF_SOLUTION))
    assert not any(a.threat for a in rows)


def test_estimator_reset_at_or_above_the_hard_threshold_at_the_transition_fix_alerts():
    """GENUINE (transition, rule 3). As above with a 50 m snap: an unclamped residual increment
    >= hard on the transition fix alerts CRITICAL GPS_SPOOFING ("position discontinuity") within
    one decision, and the alert clears once the step leaves the residual window."""
    rows = _run(lambda t: _still(t, north=50.0 if t >= ONSET else 0.0,
                                 ekf=EKF_CONST_POS if t < ONSET else EKF_SOLUTION))
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET <= first.t <= ONSET + 0.2 and first.severity == Severity.CRITICAL
    assert _has(first, DISCONTINUITY)
    assert not any(a.threat for a in rows if a.t > ONSET + RESID_WINDOW_S + 0.2)


def test_debounce_counts_reports_exactly_link_gap_apart_despite_float_error():
    """GENUINE (debounce tolerance). CONST_POS reports at 0.3 s and 2.3 s are meant to be exactly
    _LINK_GAP_S apart, but 2.3 - 0.3 is 1.9999999999999998 in floating point. The debounce compares
    with a 1e-9 s tolerance, so the fix right after the second report is gated."""
    assert 2.3 - 0.3 < _LINK_GAP_S
    ext = FeatureExtractor()
    link = _Link()
    for t in (0.3, 0.8, 1.3, 1.8, 2.3):
        ext.update(link.env(t, "EKF_STATUS_REPORT", 193, flags=EKF_CONST_POS))
    for t in (2.3, 2.5):
        for m in _messages(link, 0, t, _still(t)):
            if m.msgname == "GLOBAL_POSITION_INT":
                ext.update(m)
    assert ext.extract(2.5).nav_gated


def test_extractor_reset_clears_the_estimator_state():
    """GENUINE. ``FeatureExtractor.reset()`` reinitialises every estimator field, and the debounce
    starts over: one CONST_POS report after a reset does not gate a fix."""
    ext = FeatureExtractor()
    link = _Link()
    gated = _with(_wander, ekf=EKF_CONST_POS)
    for k in range(60):
        for m in _messages(link, k, k / TICK_HZ, gated(k / TICK_HZ)):
            ext.update(m)
    before = ext.extract(5.9)
    assert before.nav_gated and before.ekf_flags == EKF_CONST_POS and before.pos_step_max_m > 0.0
    ext.reset()
    f = ext.extract(0.0)
    assert (f.ekf_flags, f.ekf_age_s, f.nav_solution, f.nav_gated, f.pos_residual_nav_m,
            f.pos_step_max_m, f.pos_vel_shortfall_gated_m) == (None, None, None, False, None, 0.0, 0.0)
    link = _Link()
    for k in range(10):  # 1 s: two CONST_POS reports, 0.5 s apart
        for m in _messages(link, k, k / TICK_HZ, gated(k / TICK_HZ)):
            ext.update(m)
    f = ext.extract(0.9)
    assert f.ekf_flags == EKF_CONST_POS and f.nav_solution is False and f.nav_gated is False


# --------------------------------------------------------------------------- #
# estimator state: adversarial synthetic cases (SIM)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("ekf", [None, EKF_SOLUTION, EKF_CONST_POS], ids=["no-ekf", "solution", "const-pos"])
def test_large_jump_alerts_critical_with_and_without_an_estimator_solution(ekf):
    """GENUINE (adversarial 9). A 50 m jump on a stationary vehicle alerts CRITICAL GPS_SPOOFING
    within one decision with no status, with a solution (Stage-1 residual rule) and under sustained
    CONST_POS (rule 3, single-fix discontinuity). The debounce and transition cases are P2 / P2b and
    the transition tests."""
    rows = _run(_with(lambda t: _still(t, north=50.0 if t >= ONSET else 0.0), ekf=ekf))
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET <= first.t <= ONSET + 0.2 and first.severity == Severity.CRITICAL


def test_jump_below_the_hard_threshold_is_not_detected_under_sustained_no_solution():
    """KNOWN LIMITATION (adversarial 9). At gated fixes only a single-fix residual increment at or
    above the hard threshold alerts (with velocity 0 that is the jump itself): a 20 m jump
    (SUSPICIOUS with a solution) is reported only as degraded navigation. The thresholds were not
    re-derived for this state. The only benign no-solution data are the bench captures 008/009
    (in-sample, n = 2); their largest gated single-fix residual increments are 8.85 m and 0.70 m
    (pinned by the REPLAY test at the end of this file)."""
    assert 20.0 < RESID_HARD_M
    rows = _run(_with(lambda t: _still(t, north=20.0 if t >= ONSET else 0.0), ekf=EKF_CONST_POS))
    assert not _alerts(rows, AttackType.GPS_SPOOFING)


def _moves_with_zero_velocity(t: float) -> State:
    return {"north": 0.0, "east": SPEED * max(0.0, t - ONSET), "vn": 0.0, "ve": 0.0}


@pytest.mark.parametrize("ekf", [None, EKF_SOLUTION], ids=["no-ekf", "solution"])
def test_position_moving_with_zero_velocity_alerts_when_the_estimator_claims_a_solution(ekf):
    """GENUINE (adversarial 10). Without status, or with status claiming a solution, the divergence
    alerts within the documented window, exactly as before."""
    rows = _run(_with(_moves_with_zero_velocity, ekf=ekf))
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + RESID_M / SPEED + 0.6


@pytest.mark.parametrize("walk_ms", [SPEED, 140.0], ids=["10ms-2m-per-fix", "140ms-28m-per-fix"])
def test_p1_sustained_forged_no_solution_hides_a_zero_velocity_walk_below_the_hard_step(walk_ms):
    """KNOWN LIMITATION (reviewer probe P1; forged status). EKF_STATUS_REPORT is unauthenticated. An
    in-path attacker who sustains a forged CONST_POS (here from t = 0, so the debounce has long
    passed) and reports zero velocity can walk the reported position by less than the hard threshold
    per fix (< 30 m per fix: < 150 m/s at this fixture's 5 Hz) without any alert: at gated fixes the
    position-vs-velocity residual is not used, rule 4 sees nothing (the velocity is 0, and the
    shortfall is bounded by the velocity-implied movement) and no single step reaches the hard
    threshold. This is a capability the gate adds over the Stage-1 rule (which
    alerts on the 10 m/s case: see the no-ekf test above). With no solution and no velocity, the walk
    is indistinguishable from GNSS wander. Closed only by authenticating the status (MAVLink-2
    signing)."""
    assert walk_ms / GPI_HZ < RESID_HARD_M
    rows = _run(_with(_still, east=lambda t: walk_ms * max(0.0, t - ONSET), ekf=EKF_CONST_POS))
    assert not any(a.threat for a in rows)
    assert _nav_notes(rows) > 0


def test_zero_velocity_walk_of_at_least_the_hard_step_per_fix_alerts_under_sustained_no_solution():
    """GENUINE (rule 3; complement of P1). The same forged state with a walk of 160 m/s (32 m per
    fix, >= hard) alerts CRITICAL GPS_SPOOFING on the first step ("position discontinuity")."""
    walk_ms = 160.0
    assert walk_ms / GPI_HZ >= RESID_HARD_M
    rows = _run(_with(_still, east=lambda t: walk_ms * max(0.0, t - ONSET), ekf=EKF_CONST_POS))
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + 0.4 and first.severity == Severity.CRITICAL
    assert _has(first, DISCONTINUITY)


def test_p1b_frozen_position_on_a_moving_vehicle_with_forged_no_solution_alerts():
    """GENUINE (reviewer probe P1b, its timing). Moving east at SPEED with a truthful velocity; at
    ONSET the attacker freezes the reported position and starts forging CONST_POS. During the
    debounce the Stage-1 rule sees position vs velocity diverge and alerts; once fixes are gated,
    rule 4 (velocity-implied movement the frozen position does not show) keeps the threat up for the
    rest of the run."""
    rows = _run(_with(lambda t: _east(t, east=SPEED * min(t, ONSET)),
                      ekf=lambda t: EKF_SOLUTION if t < ONSET else EKF_CONST_POS))
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + RESID_M / SPEED + 0.6
    late = [a for a in rows if a.t >= ONSET + _LINK_GAP_S + RESID_WINDOW_S]
    assert late and all(a.threat and a.attack_type == AttackType.GPS_SPOOFING and _has(a, VEL_IMPLIES)
                        for a in late)


def test_p1b_vehicle_that_starts_moving_under_an_established_forged_no_solution_alerts():
    """GENUINE (rule 4; P1b with the gate established in advance). Forged CONST_POS from t = 0 on a
    stationary vehicle; from ONSET it accelerates east at 2 m/s^2 (truthful velocity; below the
    acceleration limit) while the reported position stays frozen. The velocity-implied movement the
    position does not show (here all of it) crosses the soft threshold over the gated fixes and
    alerts GPS_SPOOFING."""
    def traj(t: float) -> State:
        v = min(2.0 * max(0.0, t - ONSET), 15.0)
        return _still(t, ve=v, ekf=EKF_CONST_POS)

    rows = _run(traj)
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + 5.0
    assert _has(first, VEL_IMPLIES)


def test_coherent_moving_vehicle_under_sustained_no_solution_status_is_quiet():
    """GENUINE (rule 4, quiet). Position and velocity agree at SPEED, but the status says no
    horizontal solution (forged here, from t = 0). Rule 4 measures only the velocity-implied movement
    the position does NOT show; here the position shows all of it, so the shortfall stays ~0 and
    nothing fires, as with the Stage-1 rule on the same coherent track. (The first v2 draft measured
    |sum v*dt| alone and alerted here, a false-positive class the Stage-1 rule does not have;
    corrected 2026-10-26.) Every decision from the first gated fix carries the navigation line."""
    frames: list[FeatureFrame] = []
    rows = _run(_with(_east, ekf=EKF_CONST_POS), frames=frames)
    assert not any(a.threat for a in rows)
    assert _nav_notes(rows) == sum(a.t >= _LINK_GAP_S for a in rows)
    assert max(f.pos_vel_shortfall_gated_m for f in frames) < 1.0


def test_position_moving_against_the_velocity_under_sustained_no_solution_alerts():
    """GENUINE (rule 4). Moving east at SPEED with a coherent track under sustained CONST_POS (quiet,
    test above); from ONSET the reported position runs west at SPEED while the velocity still says
    east (no velocity change, so the acceleration check stays silent; 4 m per fix, so rule 3 stays
    silent). The measured displacement over the gated fixes turns against the velocity, the
    shortfall grows to the full velocity-implied movement, and GPS_SPOOFING alerts."""
    def traj(t: float) -> State:
        east = SPEED * t if t < ONSET else SPEED * (2.0 * ONSET - t)
        return _east(t, east=east, ekf=EKF_CONST_POS)

    rows = _run(traj)
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + RESID_WINDOW_S
    assert _has(first, VEL_IMPLIES)
    assert any(a.severity == Severity.CRITICAL for a in rows if a.t > ONSET)


@pytest.mark.parametrize(("north_ms", "extra_east_ms"), [(5.0, 0.0), (0.0, 5.0)],
                         ids=["perpendicular", "ahead-of-velocity"])
def test_position_offset_rule4_does_not_measure_is_not_detected_under_sustained_no_solution(
        north_ms, extra_east_ms):
    """KNOWN LIMITATION (P1 class). Moving east at SPEED under sustained CONST_POS; from ONSET the
    reported position also drifts 5 m/s north (perpendicular to the velocity) or runs 5 m/s ahead of
    it. Rule 4 measures only the velocity-implied movement the position does not show, i.e. the
    part along the velocity that is missing, so displacement perpendicular to the velocity or beyond
    it is not measured; no step reaches the hard threshold. Nothing fires, whereas the Stage-1 rule
    alerts on a 5 m/s drift (``test_fast_lat_lon_drift_with_truthful_velocity_alerts_gps_spoofing``)."""
    assert (north_ms + extra_east_ms) * RESID_WINDOW_S > RESID_M
    frames: list[FeatureFrame] = []
    rows = _run(lambda t: _east(t, north=north_ms * max(0.0, t - ONSET),
                                east=SPEED * t + extra_east_ms * max(0.0, t - ONSET), ekf=EKF_CONST_POS),
                frames=frames)
    assert not any(a.threat for a in rows)
    assert all(0.0 <= f.pos_vel_shortfall_gated_m < 1.0 for f in frames)  # never negative, ~0 here


def test_p2_single_forged_no_solution_report_at_a_500m_jump_changes_nothing():
    """GENUINE (reviewer probe P2). One forged CONST_POS report replaces the solution report at
    ONSET, the fix in the same tick jumps 500 m. One report never gates (debounce), so the Stage-1
    rule alerts CRITICAL within one decision, and every decision equals the gate-off run."""
    traj = _with(lambda t: _east(t, north=500.0 if t >= ONSET else 0.0),
                 ekf=lambda t: EKF_CONST_POS if abs(t - ONSET) < 1e-9 else EKF_SOLUTION)
    rows = _run(traj)
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET <= first.t <= ONSET + 0.2 and first.severity == Severity.CRITICAL
    assert _verdicts(rows) == _verdicts(_run(traj, cfg=_gate_off()))


@pytest.mark.parametrize("ekf", [EKF_SOLUTION, EKF_CONST_POS], ids=["solution", "const-pos"])
def test_p2b_500m_jump_right_after_status_reports_stop_alerts(ekf):
    """GENUINE (reviewer probe P2b; nothing forged). Status reports stop at ONSET and a 500 m jump
    lands on the first fix at which the last report is older than _LINK_GAP_S. With solution
    reports nothing was ever gated: Stage-1 rule. With CONST_POS reports that fix is the transition
    fix: rule 3 (unclamped single-fix residual increment). Either way CRITICAL GPS_SPOOFING within
    one decision."""
    t_stale = ONSET - 1.0 / EKF_HZ + _LINK_GAP_S  # the last report's age exceeds the gap after this
    rows = _run(_with(lambda t: _still(t, north=500.0 if t > t_stale else 0.0), ekf=_ekf_until(ONSET, ekf)))
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert t_stale < first.t <= t_stale + 0.2 and first.severity == Severity.CRITICAL


def test_p3_flags_flipping_every_report_never_gates():
    """GENUINE (reviewer probe P3). The status alternates SOLUTION / CONST_POS on every report while
    the position moves at SPEED with zero velocity. Every SOLUTION report restarts the no-solution
    run, so no fix is gated: the divergence alerts within the documented window and every decision
    equals the gate-off run."""
    traj = _with(_moves_with_zero_velocity,
                 ekf=lambda t: EKF_CONST_POS if round(t * EKF_HZ) % 2 else EKF_SOLUTION)
    rows = _run(traj)
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + RESID_M / SPEED + 0.6
    assert _nav_notes(rows) == 0
    assert _verdicts(rows) == _verdicts(_run(traj, cfg=_gate_off()))


@pytest.mark.parametrize("rate_ms", [5.0, 6.0])
def test_p3b_sparse_solution_reports_leave_the_drift_floor_unchanged(rate_ms):
    """GENUINE (reviewer probe P3b). Only one status report in five is delivered (every 2.5 s, so it
    goes stale between reports), all SOLUTION, while the position drifts north at ``rate_ms`` with a
    truthful velocity. Nothing is gated, so the decisions equal the gate-off run (the Stage-1 rule on
    the same stream) and the drift alerts within the window, as without status."""
    traj = _with(lambda t: _east(t, north=rate_ms * max(0.0, t - ONSET)),
                 ekf=lambda t: EKF_SOLUTION if round(t * TICK_HZ) % 25 == 0 else None)
    rows = _run(traj)
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + RESID_WINDOW_S
    assert _verdicts(rows) == _verdicts(_run(traj, cfg=_gate_off()))


def test_p4_jump_split_into_steps_below_the_hard_threshold_is_not_detected_under_sustained_no_solution():
    """KNOWN LIMITATION (reviewer probe P4; forged or genuine status). Under sustained CONST_POS a
    50 m jump delivered as two 25 m steps (each < hard) with zero velocity raises nothing: rule 3
    sees single steps only, and rule 4 sees nothing (the velocity is 0). Same root cause as P1."""
    rows = _run(_with(lambda t: _still(t, north=0.0 if t < ONSET else 25.0 if t < ONSET + 0.2 else 50.0),
                      ekf=EKF_CONST_POS))
    assert not any(a.threat for a in rows)


def test_injected_no_solution_status_on_a_link_that_never_sent_any_activates_the_gate():
    """KNOWN LIMITATION (injection). A link that never sends EKF_STATUS_REPORT (PX4 / ArduPilot SITL
    as captured, Stage-1 SIM) gets the Stage-1 rule. An in-path attacker who injects CONST_POS
    reports (here with the autopilot's own sysid/compid and sequence, from ONSET) activates the gate
    after _LINK_GAP_S of sustained reports. What is lost from then on: the position-vs-velocity
    residual, so a zero-velocity walk of < 30 m per fix is not detected (here 10 m/s starting 1 s
    after the gate is established); what remains: rule 3 (single residual increments >= hard),
    rule 4 (velocity-implied movement the position does not show), the other physics checks and
    every protocol rule. Controls: without injection the same walk alerts (Stage-1 rule), and a walk
    that starts together with the injection alerts during the debounce."""
    walk_start = ONSET + _LINK_GAP_S + 1.0

    def walk(start: float) -> Callable[[float], State]:
        return lambda t: _still(t, east=SPEED * max(0.0, t - start))

    injected = _run(_with(walk(walk_start), ekf=lambda t: EKF_CONST_POS if t >= ONSET else None))
    assert not any(a.threat for a in injected)
    assert _alerts(_run(walk(walk_start)), AttackType.GPS_SPOOFING)
    assert _alerts(_run(_with(walk(ONSET), ekf=lambda t: EKF_CONST_POS if t >= ONSET else None)),
                   AttackType.GPS_SPOOFING)


def test_stripped_status_during_an_attack_falls_back_to_the_full_rule():
    """GENUINE (adversarial 17, missing status). CONST_POS reports until ONSET, then dropped while
    the position diverges from the velocity. Fixes stay gated until the last report is _LINK_GAP_S
    old; the next fix is the transition fix (left out), after which the Stage-1 rule rebuilds and
    alerts. Stripping EKF_STATUS_REPORT hides the attack for at most the gap plus the residual
    build-up (rule 4 sees nothing here: the velocity is 0)."""
    rows = _run(_with(_moves_with_zero_velocity, ekf=_ekf_until(ONSET, EKF_CONST_POS)))
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET + _LINK_GAP_S < first.t <= ONSET + _LINK_GAP_S + RESID_M / SPEED + 1.0


def test_gps_vs_groundspeed_check_is_not_gated_by_estimator_state():
    """GENUINE (adversarial 11). The GPS/VFR speed cross-check is independent of the estimator gate:
    it alerts TELEMETRY_MANIPULATION with CONST_POS_MODE reported. (Original moving fixture; between
    the first v2 draft and the rule-4 correction it had to be replaced by a stationary one, because
    rule 4 then alerted on the coherent moving track. It no longer does.)"""
    rows = _run(_with(lambda t: _east(t, **({"vfr_gs": 0.0} if t >= ONSET else {})), ekf=EKF_CONST_POS))
    _quiet_before_onset(rows)
    assert any(a.attack_type == AttackType.TELEMETRY_MANIPULATION for a in _alerts(rows))
    assert not _alerts(rows, AttackType.GPS_SPOOFING)
    # the navigation line is emitted only when physics scored 0 (never among scored physics evidence)
    scored = [a for a in rows if a.detector_scores.get(PHYSICS, 0.0) > 0.0]
    assert scored and not any(_has(a, NAV_NOTE) for a in scored)
    assert all(_has(a, NAV_NOTE) for a in rows if _LINK_GAP_S <= a.t < ONSET)


@pytest.mark.parametrize("rate_ms", [5.0, 8.0])
def test_fast_drift_with_a_healthy_estimator_and_plausible_gnss_quality_alerts(rate_ms):
    """GENUINE (adversarial 12, 16). Lat/lon drift above the window floor while every quality field
    looks good (DGPS, 12 satellites, HDOP 0.7, EKF solution) alerts GPS_SPOOFING within the window;
    the GNSS fix rule stays silent: plausible quality says nothing about authenticity."""
    rows = _run(_with(lambda t: _east(t, north=rate_ms * max(0.0, t - ONSET)),
                      ekf=EKF_SOLUTION, raw=(4, 12), eph=70))
    _quiet_before_onset(rows)
    first = _alerts(rows, AttackType.GPS_SPOOFING)[0]
    assert ONSET < first.t <= ONSET + RESID_WINDOW_S
    assert not _alerts(rows, AttackType.DOS)


@pytest.mark.parametrize("rate_ms", [2.0, 4.0], ids=["below-floor", "at-floor"])
def test_slow_drift_at_and_below_the_floor_is_not_detected_with_a_healthy_estimator(rate_ms):
    """KNOWN LIMITATION (adversarial 13). At or below RESID_M / window the residual never exceeds the
    soft threshold; a solution report does not change that."""
    assert rate_ms * RESID_WINDOW_S <= RESID_M
    rows = _run(_with(lambda t: _east(t, north=rate_ms * max(0.0, t - ONSET)), ekf=EKF_SOLUTION))
    assert not any(a.threat for a in rows)


def test_velocity_consistent_drift_with_a_healthy_estimator_is_not_detected():
    """KNOWN LIMITATION (adversarial 14). As without status: every cross-check agrees."""
    rows = _run(_with(lambda t: _east(t, north=8.0 * max(0.0, t - ONSET), vn=8.0 if t >= ONSET else 0.0),
                      ekf=EKF_SOLUTION))
    assert not any(a.threat for a in rows)


def test_constant_offset_with_a_healthy_estimator_is_alerted_only_at_the_jump():
    """KNOWN LIMITATION (adversarial 15). As without status."""
    rows = _run(_with(lambda t: _east(t, north=50.0 if t >= ONSET else 0.0), ekf=EKF_SOLUTION))
    assert len(_alerts(rows)) == 1
    assert not any(a.threat for a in rows if a.t > ONSET + RESID_WINDOW_S)


# --------------------------------------------------------------------------- #
# the gate covers the physics rule only (ML detector; git-ignored model)
# --------------------------------------------------------------------------- #

_MODEL = _REPO / "models" / "isoforest.joblib"


def test_ml_detector_is_not_gated_and_still_flags_wander_under_sustained_no_solution():
    """KNOWN LIMITATION (ML on; skipped where the git-ignored ``models/isoforest.joblib`` is absent).
    The gate covers the physics rule only. The Isolation Forest still sees the ungated
    ``pos_residual_m`` (an ML_FEATURES member, frozen) and maps it to GPS_SPOOFING, so stationary
    wander under sustained CONST_POS still raises GPS_SPOOFING threats via ``ml_anomaly`` while the
    physics detector scores 0 throughout. ML is off by default for every non-SIM live source
    (``backend/sources.py`` ``ml_enabled``), in ``run_serial_ids.py`` and in the bench replays
    (``--no-ml``)."""
    if not _MODEL.exists():
        pytest.skip("models/isoforest.joblib not present (git-ignored)")
    rows = _run(_with(_wander, ekf=EKF_CONST_POS), model_path=str(_MODEL))
    ml = [a for a in rows if a.threat and a.attack_type == AttackType.GPS_SPOOFING
          and DetectorName.ANOMALY.value in a.contributing_detectors]
    assert ml
    assert all(a.detector_scores.get(PHYSICS, 0.0) == 0.0 for a in rows)


# --------------------------------------------------------------------------- #
# fusion: evidence order with the degraded-navigation line
# --------------------------------------------------------------------------- #


def test_only_score0_physics_evidence_is_moved_after_the_other_detectors():
    """GENUINE. Fusion keeps the Stage-1 evidence order (physics, protocol, integrity, anomaly)
    except that evidence from a physics result with score 0 (only the degraded-navigation line) is
    moved last. A score-0 protocol line (e.g. the coverage line) is NOT moved."""
    def res(det: DetectorName, score: float, text: str) -> DetectorResult:
        return DetectorResult(detector=det, score=score, triggered=score >= 0.5, evidence=[text])

    eng = FusionEngine(load_config().detector["fusion"])
    a = eng.fuse(0.0, 0.0, [res(DetectorName.PHYSICS, 0.0, "nav"), res(DetectorName.PROTOCOL, 0.0, "cov"),
                            res(DetectorName.ANOMALY, 0.6, "ml")], IntegrityStatus.UNKNOWN)
    assert a.evidence == ["cov", "ml", "nav"]
    b = eng.fuse(0.2, 0.0, [res(DetectorName.PHYSICS, 0.6, "phys"), res(DetectorName.PROTOCOL, 0.0, "cov"),
                            res(DetectorName.ANOMALY, 0.6, "ml")], IntegrityStatus.UNKNOWN)
    assert b.evidence == ["phys", "cov", "ml"]


# --------------------------------------------------------------------------- #
# saved physical bench telemetry (REPLAY of BENCH; git-ignored tlogs, so local only)
# --------------------------------------------------------------------------- #

_BENCH = _REPO / "data" / "hardware" / "raw"


def _replay_tlog(path: Path) -> tuple[list[ThreatAssessment], list[FeatureFrame]]:
    from pymavlink import mavutil

    conn = mavutil.mavlink_connection(str(path))
    frames: list[tuple[float, bytes]] = []
    while (m := conn.recv_match(blocking=False)) is not None:
        if m.get_type() != "BAD_DATA":
            frames.append((m._timestamp, bytes(m.get_msgbuf())))
    pipe = IDSPipeline(load_config(), model_path=None, firmware_dir=None)
    rows: list[ThreatAssessment] = []
    feats: list[FeatureFrame] = []
    for tick in frame_ticks(frames, sample_rate_hz=TICK_HZ):
        if (a := pipe.process_tick(tick)) is not None:
            rows.append(a)
            assert pipe.last_frame is not None
            feats.append(pipe.last_frame)
    return rows, feats


@pytest.mark.parametrize(("name", "max_step_m", "max_shortfall_m"),
                         [("telemetry_radio_008.tlog", 8.85, 0.11), ("telemetry_radio_009.tlog", 0.70, 0.11)])
def test_bench_captures_raise_no_gps_spoofing_under_the_estimator_gate(name, max_step_m, max_shortfall_m):
    """GENUINE (REPLAY of BENCH, captures 008/009; skipped where the git-ignored tlog is absent).
    IN-SAMPLE: these two captures are the data the gate was designed from, so this is a regression
    pin, not a held-out evaluation. The stationary Pixhawk 6X reports CONST_POS_MODE throughout:
    from the first gated fix on, every decision on which physics scored 0 carries the
    degraded-navigation line (since 2026-10-26 the line is omitted when physics scored, e.g. 008's
    GPS/baro decisions, so it never sits among scored physics evidence), there is no GPS_SPOOFING,
    and the largest gated single-fix residual increment (``max_step_m``) and the largest rule-4
    shortfall (``max_shortfall_m``, velocity-implied movement the position does not show) stay below
    the soft threshold. 008's genuine fix loss still raises the GNSS rule's DOS."""
    path = _BENCH / name
    if not path.exists():
        pytest.skip(f"local bench capture {name} not present (git-ignored)")
    rows, feats = _replay_tlog(path)
    assert rows and not _alerts(rows, AttackType.GPS_SPOOFING)
    first = next(i for i, f in enumerate(feats) if f.nav_gated)
    assert all(f.nav_gated for f in feats[first:])
    unscored = [a for a in rows[first:] if a.detector_scores.get(PHYSICS, 0.0) == 0.0]
    assert _nav_notes(rows[first:]) == len(unscored) > 0
    assert not any(_has(a, NAV_NOTE) for a in rows if a.detector_scores.get(PHYSICS, 0.0) > 0.0)
    assert max(f.pos_step_max_m for f in feats) == pytest.approx(max_step_m, abs=0.01)
    assert max(f.pos_vel_shortfall_gated_m for f in feats) == pytest.approx(max_shortfall_m, abs=0.01)
    if name.endswith("008.tlog"):
        assert _alerts(rows, AttackType.DOS)
    else:
        assert not any(a.threat for a in rows)
