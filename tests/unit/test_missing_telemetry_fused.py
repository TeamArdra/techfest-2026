"""Fused-level (``ThreatAssessment``) regression tests for missing-telemetry scenarios.

``test_missing_telemetry.py`` stops at the extractor + protocol detector. These tests run the REAL
``IDSPipeline`` (extractor -> four detectors -> fusion, ML off, no firmware verifier: exactly what
``scripts/hardware/run_serial_ids.py`` builds) on synthetic MAVLink envelopes and assert on the final
``ThreatAssessment`` -- ``threat``, ``severity``, ``attack_type``, ``is_alert``, ``evidence`` --
because that is what the runner persists. No hardware, no sockets, no production code touched.

Three kinds of test live here; the kind is stated in each docstring.

* ``GENUINE``  -- an expectation that follows from existing code/docs or from the "never received
  vs lost after being seen must be distinguishable" principle already adopted.
* ``DECIDED Pn`` -- the outcome of a policy question the USER has decided. P1 and P2 were decided
  on 2026-10-15 ("Coverage, not attack"):
    P1  a link that has NEVER delivered GLOBAL_POSITION_INT is, by default, a reported coverage
        condition (protocol score 0, no vote, a ``coverage: GLOBAL_POSITION_INT never received``
        evidence line in every assessment), not a threat or an alert. A profile that declares
        position as required (``protocol.require_global_position: true``) restores the DOS
        outcome and the ``never_seen_gps_*`` knobs. A NEVER-received stream is judged on elapsed
        monitoring time, so the first decision does not fire merely because nothing arrived yet.
        Loss after a stream was seen is unchanged (DOS).
    P2  ``GPS_RAW_INT`` is reported as present/absent in the coverage line (``gps_raw_seen``) but
        is NOT position presence: it does not satisfy ``require_global_position``.
* ``PENDING POLICY P3`` -- pins the CURRENT fused outcome of a still-undecided question: is a fix
  that was never acquired denial evidence at all, or a coverage condition? (scoring still OPEN)

Stage-1 numbers used below are derived from the loaded config, never hard-coded.
"""

from __future__ import annotations

import re

import pytest

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, DetectorName, Severity
from aegisflight.core.types import MessageEnvelope, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.stream import TelemetryTick

TICK_HZ = 10  # simulation.sample_rate_hz; decisions run at 5 Hz (every 2nd tick)
_CFG = load_config()
_W = _CFG.detector["fusion"]["weights"]
W_PROTO = _W["protocol_rule"] / max(_W.values())  # max-normalised protocol weight (fusion.engine)
THREAT_THRESHOLD = _CFG.detector["fusion"]["threat_threshold"]
COOLDOWN_S = _CFG.detector["fusion"]["cooldown_s"]
GPS_DROPOUT_S = _CFG.detector["protocol"]["gps_dropout_s"]
PROTO = DetectorName.PROTOCOL.value
NEVER_GPS_TEXT = "GPS dropout: never received"
COVERAGE_TEXT = "coverage: GLOBAL_POSITION_INT never received"
HB_TIMEOUT_S = _CFG.detector["protocol"]["heartbeat_timeout_s"]


# --------------------------------------------------------------------------- #
# synthetic link
# --------------------------------------------------------------------------- #


class _Link:
    """One autopilot (sysid 1 / compid 1) with ONE running MAVLink sequence counter, as a real
    flight controller has. (A per-message counter fakes a 'sequence gap 254' and pollutes every
    result with a MAVLINK_ANOMALY that has nothing to do with the scenario.)"""

    def __init__(self) -> None:
        self._seq = -1

    def env(self, t: float, name: str, msgid: int, **fields) -> MessageEnvelope:
        self._seq = (self._seq + 1) % 256
        return MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=msgid, msgname=name,
                               seq=self._seq, signed=False, byte_len=28, fields=fields)


def _stream(link: _Link, k: int, t: float, *, hb: bool = True, sys_status: bool = True,
            gpi: bool = True, raw: tuple[int, int] | None = (3, 10), att: bool = True,
            groundspeed: float = 0.0) -> list[MessageEnvelope]:
    """Messages of tick ``k``. HEARTBEAT/SYS_STATUS/GPS_RAW_INT 1 Hz, GLOBAL_POSITION_INT 5 Hz,
    ATTITUDE/VFR_HUD 10 Hz; a stationary vehicle (GPS velocity 0). ``raw`` = (fix_type, satellites)
    or None. ``groundspeed`` is the VFR_HUD groundspeed only (default 0 = consistent)."""
    out: list[MessageEnvelope] = []
    if k % TICK_HZ == 0:
        if hb:
            out.append(link.env(t, "HEARTBEAT", 0, base_mode=81, custom_mode=0))
        if sys_status:
            out.append(link.env(t, "SYS_STATUS", 1, voltage_battery=16000, battery_remaining=90))
        if raw is not None:
            out.append(link.env(t, "GPS_RAW_INT", 24, satellites_visible=raw[1],
                                fix_type=raw[0], eph=100))
    if gpi and k % 2 == 0:
        out.append(link.env(t, "GLOBAL_POSITION_INT", 33, lat=int(12.9 * 1e7),
                            lon=int(77.5 * 1e7), alt=900000, relative_alt=0, vx=0, vy=0, vz=0))
    if att:
        out.append(link.env(t, "ATTITUDE", 30, roll=0.0, pitch=0.0, yaw=0.5, rollspeed=0.0,
                            pitchspeed=0.0, yawspeed=0.0))
        out.append(link.env(t, "VFR_HUD", 74, groundspeed=groundspeed, heading=28, throttle=0,
                            alt=900.0, climb=0.0))
    return out


def _hb_only(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    return _stream(link, k, t, sys_status=False, gpi=False, raw=None, att=False)


def _gps_raw_only(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    return _stream(link, k, t, gpi=False)  # healthy GPS_RAW_INT (fix 3, 10 sats), no position


def _healthy(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    return _stream(link, k, t)


def _fix_never_acquired(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    return _stream(link, k, t, raw=(0, 0))  # position streams; the receiver never gets a fix


def _fix_lost_at_10s(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    return _stream(link, k, t, raw=(3, 10) if t < 10.0 else (0, 0))


def _gps_dropout_at_10s(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    live = t < 10.0  # both GPS channels stop together; everything else keeps flowing
    return _stream(link, k, t, gpi=live, raw=(3, 10) if live else None)


class Run:
    def __init__(self, decisions: list[tuple[ThreatAssessment, FeatureFrame]],
                 pipe: IDSPipeline) -> None:
        self.decisions = decisions
        self.pipe = pipe

    @property
    def assessments(self) -> list[ThreatAssessment]:
        return [a for a, _ in self.decisions]

    @property
    def alerts(self) -> list[ThreatAssessment]:
        return [a for a in self.assessments if a.is_alert]


def _run(stream_fn, seconds: float = 30.0, **protocol_overrides) -> Run:
    """Drive ``IDSPipeline`` (ML off, no firmware verifier -- what the serial runner builds)."""
    cfg = load_config()  # a fresh deep copy: overriding keys here cannot leak into other tests
    cfg.detector["protocol"].update(protocol_overrides)
    pipe = IDSPipeline(cfg, model_path=None, firmware_dir=None)
    link = _Link()
    decisions: list[tuple[ThreatAssessment, FeatureFrame]] = []
    for k in range(int(round(seconds * TICK_HZ))):
        t = k / TICK_HZ
        a = pipe.process_tick(TelemetryTick(t=t, tick=k, messages=stream_fn(link, k, t)))
        if a is not None:
            assert pipe.last_frame is not None
            decisions.append((a, pipe.last_frame))
    return Run(decisions, pipe)


def _text(a: ThreatAssessment) -> str:
    return " | ".join(a.evidence)


def _shape(s: str) -> str:
    """Evidence with every number masked, so two cases are compared on WORDING, not on values."""
    return re.sub(r"\d+(?:\.\d+)?", "N", s)


# --------------------------------------------------------------------------- #
# 0. control: the harness itself
# --------------------------------------------------------------------------- #


def test_control_healthy_link_is_quiet_at_fused_level():
    """GENUINE. A healthy full stream yields no threat and no alert, so every non-quiet result
    below is caused by its scenario and not by the synthetic generator."""
    run = _run(_healthy)
    assert run.decisions, "no decisions produced"
    assert not any(a.threat or a.is_alert for a in run.assessments)


# --------------------------------------------------------------------------- #
# 1. HEARTBEAT-only (the physical Pixhawk 6X passive USB stream)
# --------------------------------------------------------------------------- #


def test_heartbeat_only_flags_and_evidence_reach_the_assessment():
    """GENUINE. Heartbeat seen, GPS never seen; every decision's evidence says "never received"
    (not a measured age) -- under the default profile as the P1 coverage line; the physics
    detector is blind (score 0), not alarmed."""
    run = _run(_hb_only)
    for a, frame in run.decisions:
        assert frame.heartbeat_seen is True and frame.gps_seen is False
        assert frame.gps_raw_seen is False
        assert COVERAGE_TEXT in _text(a)
        assert a.detector_scores[DetectorName.PHYSICS.value] == 0.0


def test_heartbeat_only_default_is_a_coverage_condition_not_a_threat():
    """DECIDED P1 (user decision 2026-10-15, "Coverage, not attack"). Was: CRITICAL DOS alert on the
    first decision. Default profile: not a threat, not an alert, NORMAL/BENIGN; the condition is
    still visible in every assessment's evidence and is never worded as a dropout or a loss."""
    run = _run(_hb_only)
    for a in run.assessments:
        assert a.threat is False and a.is_alert is False
        assert a.severity is Severity.NORMAL and a.attack_type is AttackType.BENIGN
        assert a.detector_scores[PROTO] == 0.0 and a.threat_score == 0.0
        text = _text(a)
        assert COVERAGE_TEXT in text and "GPS_RAW_INT never received" in text
        assert "GPS dropout" not in text and "lost" not in text
    assert run.alerts == []


def test_heartbeat_only_with_require_global_position_is_a_critical_dos_attack():
    """DECIDED P1 opt-in (user decision 2026-10-15). ``require_global_position: true`` reproduces the
    old CRITICAL DOS outcome, except at startup: a never-received stream is judged on elapsed
    monitoring time, so the first alert is the first decision with elapsed > ``gps_dropout_s``."""
    run = _run(_hb_only, require_global_position=True)
    for a in run.assessments:
        if a.t <= GPS_DROPOUT_S:
            assert a.threat is False and NEVER_GPS_TEXT not in _text(a)
            continue
        assert a.threat is True and a.attack_type is AttackType.DOS
        assert a.severity is Severity.CRITICAL
        assert a.threat_score == pytest.approx(W_PROTO, abs=1e-3)  # protocol score 1.0 * w'
        assert NEVER_GPS_TEXT in _text(a) and COVERAGE_TEXT not in _text(a)
    alerts = run.alerts
    first_after_gate = min(a.t for a in run.assessments if a.t > GPS_DROPOUT_S)
    assert alerts and alerts[0].t == pytest.approx(first_after_gate)
    assert all(b.t - a.t >= COOLDOWN_S - 1e-6 for a, b in zip(alerts, alerts[1:], strict=False))


# --------------------------------------------------------------------------- #
# 1b. startup: a NEVER-received heartbeat is judged on elapsed monitoring time
# --------------------------------------------------------------------------- #


def test_no_heartbeat_alerts_only_after_the_timeout_has_elapsed():
    """DECIDED (user decision 2026-10-15). Full telemetry but no HEARTBEAT ever: nothing at t=0;
    the first fused alert is the first decision with elapsed > ``heartbeat_timeout_s`` -- still a
    DOS alert (HEARTBEAT is MAVLink-mandatory; that policy is unchanged)."""
    run = _run(lambda link, k, t: _stream(link, k, t, hb=False), seconds=10.0)
    assert not any(a.threat for a in run.assessments if a.t <= HB_TIMEOUT_S)
    first = run.alerts[0]
    assert first.t == pytest.approx(min(a.t for a in run.assessments if a.t > HB_TIMEOUT_S))
    assert first.attack_type is AttackType.DOS and first.threat is True
    assert "heartbeat stale (never received" in _text(first)


def test_heartbeat_arriving_after_start_but_before_the_timeout_never_alerts():
    """DECIDED (same). A heartbeat first seen at 1 s is not a fault at t=0."""
    run = _run(lambda link, k, t: _stream(link, k, t, hb=t >= 1.0), seconds=10.0)
    assert not any(a.threat or a.is_alert for a in run.assessments)
    assert not any("heartbeat" in _text(a) for a in run.assessments)


# --------------------------------------------------------------------------- #
# 2. healthy GPS_RAW_INT without GLOBAL_POSITION_INT
# --------------------------------------------------------------------------- #


def test_gps_raw_only_pipeline_holds_a_healthy_fix_yet_reports_gps_never_seen():
    """GENUINE. The extractor ingests the healthy GPS_RAW_INT (fix 3D, 10 satellites) into its
    snapshot and sets ``gps_raw_seen``; ``gps_seen`` (POSITION presence: GLOBAL_POSITION_INT ever
    received) stays False. Decided P2: these are two different facts, both reported."""
    run = _run(_gps_raw_only)
    snap = run.pipe.extractor.snapshot
    assert snap.gps_fix_type == 3 and snap.satellites == 10
    assert all(frame.gps_seen is False for _, frame in run.decisions)
    assert all(frame.gps_raw_seen is True for _, frame in run.decisions)


def test_gps_raw_only_is_a_coverage_condition_that_names_gps_raw_int_present():
    """DECIDED P2 (user decision 2026-10-15, "Coverage, not attack"). Was: CRITICAL DOS on every
    decision. Default: no threat, no alert; the coverage line says GPS_RAW_INT is present."""
    run = _run(_gps_raw_only)
    for a in run.assessments:
        assert a.threat is False and a.is_alert is False and a.severity is Severity.NORMAL
        assert COVERAGE_TEXT in _text(a) and "GPS_RAW_INT present" in _text(a)
        assert "GPS dropout" not in _text(a)


def test_gps_raw_int_does_not_satisfy_a_declared_position_requirement():
    """DECIDED P2 (same). With ``require_global_position: true`` a healthy GPS_RAW_INT does not count
    as position presence: CRITICAL DOS after the elapsed-time gate."""
    run = _run(_gps_raw_only, require_global_position=True)
    after = [a for a in run.assessments if a.t > GPS_DROPOUT_S]
    assert after and all(a.threat and a.attack_type is AttackType.DOS for a in after)
    assert all(a.severity is Severity.CRITICAL and NEVER_GPS_TEXT in _text(a) for a in after)


# --------------------------------------------------------------------------- #
# 3. GPS fix: never acquired vs lost after a previously valid fix
# --------------------------------------------------------------------------- #


def test_loss_of_a_previously_valid_fix_alerts_dos():
    """GENUINE. Fix 3D / 10 satellites for 10 s, then fix 0 / 0: the GNSS-loss rule fires after its
    5 decisions and the fused assessment is a DOS alert. (Genuine-loss detection must survive any
    policy change.)"""
    run = _run(_fix_lost_at_10s, seconds=20.0)
    first = next(a for a in run.alerts)
    assert 10.0 < first.t <= 12.0
    assert first.attack_type is AttackType.DOS and first.threat is True
    assert "GNSS fix lost" in _text(first)
    assert not any(a.threat for a in run.assessments if a.t < 10.0)


def test_never_acquired_fix_alerts_like_a_loss_but_says_never_acquired():
    """PENDING POLICY P3 (partly decided) -- pins CURRENT behaviour. A receiver that never had a 3D
    fix (fix 0 / 0 from t=0, position streams present) triggers the GNSS rule within about a second
    with the same DOS vote, score and severity as a loss.

    Decided (P3 wording): the evidence no longer claims a LOSS -- it says "GNSS fix never acquired
    ... (no valid fix since monitoring began)", and never contains "lost". Provenance: the USER's
    P3.4 brief (2026-10-15) required never-acquired / lost / healthy to be distinguishable without
    falsely claiming a lost fix and with no score/weight/threshold change; the exact string and the
    "valid fix ever seen since reset()" state were chosen by the implementer (aegis-lead with
    aegis-detection), reviewed ACCEPT-WITH-FIXES in aegis-reviewer's P3.4 review, and committed at the user's request
    (5a35143). Still OPEN (decided by no one): whether a never-acquired fix should SCORE differently (denial evidence vs a coverage
    condition); the timing/attack_type/severity assertions below pin today's unchanged scoring."""
    run = _run(_fix_never_acquired, seconds=20.0)
    first = next(a for a in run.alerts)
    assert first.t <= 1.5
    assert first.attack_type is AttackType.DOS and first.severity is Severity.SUSPICIOUS
    assert "GNSS fix never acquired" in _text(first)
    assert not any("lost" in _text(a) for a in run.assessments)


def test_never_acquired_fix_evidence_is_distinguishable_from_loss_after_valid_fix():
    """GENUINE (was a strict xfail until the P3 wording fix). The two cases must be distinguishable
    in the persisted evidence; the exact wording is deliberately not asserted (numbers are masked,
    only the wording is compared)."""
    never = next(a for a in _run(_fix_never_acquired, seconds=20.0).alerts)
    lost = next(a for a in _run(_fix_lost_at_10s, seconds=20.0).alerts)
    assert _shape(_text(never)) != _shape(_text(lost))


# --------------------------------------------------------------------------- #
# 4. genuine GPS dropout and its fused alert latency
# --------------------------------------------------------------------------- #


def _dropout_run(**protocol_overrides) -> Run:
    return _run(_gps_dropout_at_10s, seconds=30.0, **protocol_overrides)


def test_genuine_gps_dropout_detector_fires_at_threshold_but_fused_alert_waits():
    """GENUINE (pins Stage-1 fused latency; it is NOT a defect claim). Both GPS channels stop at
    10 s. The detector's "GPS dropout" rule fires as soon as the age exceeds ``gps_dropout_s``
    (score floor 0.5), but a protocol-only score of 0.5 fuses to 0.5 * w' < ``threat_threshold``,
    so the first fused THREAT/ALERT needs the score ramp to reach threshold / w' -- about twice the
    detector's own threshold. Derived from the config, nothing hard-coded."""
    run = _dropout_run()
    needed = THREAT_THRESHOLD / W_PROTO  # protocol score needed for a fused threat (~0.51)
    ramp_start, ramp_end = GPS_DROPOUT_S, 3 * GPS_DROPOUT_S
    age_for_threat = ramp_start + needed * (ramp_end - ramp_start)

    after = [(a, f) for a, f in run.decisions if a.t >= 10.0 and f.gps_age_s > ramp_start]
    fired = next((a, f) for a, f in after if a.detector_scores[PROTO] > 0.0)
    a0, f0 = fired
    assert ramp_start < f0.gps_age_s < ramp_start + 0.5
    assert a0.threat is False and not a0.is_alert  # detected, not yet a fused threat
    assert "GPS dropout" in _text(a0) and "never received" not in _text(a0)

    first_alert, f_alert = next((a, f) for a, f in after if a.is_alert)
    assert age_for_threat <= f_alert.gps_age_s <= age_for_threat + 0.25  # one decision step
    assert f_alert.gps_age_s <= ramp_end  # a genuine dropout must alert within the ramp window
    assert first_alert.attack_type is AttackType.DOS and first_alert.threat is True
    assert "GPS dropout" in _text(first_alert) and "never received" not in _text(first_alert)


def test_never_seen_gps_knobs_do_not_change_a_genuine_dropout():
    """GENUINE. The additive never-seen keys apply to never-received GPS only: the full per-decision
    outcome of a measured dropout is identical with and without them."""
    def key(run: Run):
        return [(a.t, a.threat, a.is_alert, a.attack_type, a.severity, a.threat_score)
                for a in run.assessments]

    base = key(_dropout_run())
    knobs = key(_dropout_run(never_seen_gps_vote="MAVLINK_ANOMALY", never_seen_gps_max_score=0.5))
    assert knobs == base
    required = key(_dropout_run(require_global_position=True, never_seen_gps_vote="MAVLINK_ANOMALY",
                                never_seen_gps_max_score=0.5))
    assert required == base  # P1 decision: loss after a stream was seen is unchanged


# --------------------------------------------------------------------------- #
# 5. a capped never-seen vote, tested against the final ThreatAssessment
# --------------------------------------------------------------------------- #


# The ``never_seen_gps_*`` knobs apply only when the profile declares position as required
# (DECIDED P1). Every test below sets ``require_global_position=True`` and asserts on decisions
# after the elapsed-time gate (elapsed > gps_dropout_s); before it the stream is not yet judged.


def _after_gate(run: Run) -> list[ThreatAssessment]:
    after = [a for a in run.assessments if a.t > GPS_DROPOUT_S]
    assert after
    return after


def test_cap_at_the_floor_is_not_a_threat_and_not_an_alert():
    """GENUINE (arithmetic of the current fusion; P1 decided 2026-10-15 under
    ``require_global_position: true``). ``never_seen_gps_max_score`` is floored at 0.5, but
    0.5 * w' (~0.441) is BELOW the fusion ``threat_threshold`` (0.45): the assessment is
    ``threat=False``, severity NORMAL, never an alert. The condition is visible INSIDE each
    assessment (evidence text, protocol detector score 0.5). A cap of 0.0 is clamped to 0.5."""
    assert 0.5 * W_PROTO < THREAT_THRESHOLD  # the arithmetic that makes the floor sub-threshold
    for cap in (0.5, 0.0):
        run = _run(_hb_only, require_global_position=True, never_seen_gps_vote="MAVLINK_ANOMALY",
                   never_seen_gps_max_score=cap)
        for a in _after_gate(run):
            assert a.threat is False and a.is_alert is False and a.severity is Severity.NORMAL
            assert a.threat_score == pytest.approx(0.5 * W_PROTO, abs=1e-3)
            assert a.detector_scores[PROTO] == pytest.approx(0.5)
            assert NEVER_GPS_TEXT in _text(a)
        assert run.alerts == []


def test_floor_guarantees_detector_level_evidence_not_a_fused_alert():
    """GENUINE (replaces the strict xfail ``test_documented_floor_guarantee_holds_at_the_final_
    assessment``; decided reading 2026-10-15). The 0.5 floor guarantees DETECTOR-level reporting:
    with ``require_global_position: true`` and cap 0.0 the protocol detector scores 0.5 and the
    never-received evidence is in every assessment after the elapsed-time gate. It does NOT
    guarantee a fused threat or an operator alert: 0.5 * w' < threat_threshold, so ``threat`` is
    False and nothing is alerted. Stated plainly so no doc claims otherwise."""
    run = _run(_hb_only, require_global_position=True, never_seen_gps_max_score=0.0)
    for a in _after_gate(run):
        assert a.detector_scores[PROTO] == pytest.approx(0.5)
        assert NEVER_GPS_TEXT in _text(a)
        assert a.threat is False and a.is_alert is False
    assert run.alerts == []


def test_cap_above_the_fused_threshold_is_a_suspicious_alert():
    """GENUINE (arithmetic of the current fusion). Cap 0.6 -> fused 0.6 * w' (~0.529): a threat,
    SUSPICIOUS, labelled MAVLINK_ANOMALY, alerting on the first decision after the gate."""
    assert 0.6 * W_PROTO >= THREAT_THRESHOLD
    run = _run(_hb_only, require_global_position=True, never_seen_gps_vote="MAVLINK_ANOMALY",
               never_seen_gps_max_score=0.6)
    after = _after_gate(run)
    for a in after:
        assert a.threat is True and a.severity is Severity.SUSPICIOUS
        assert a.attack_type is AttackType.MAVLINK_ANOMALY
        assert a.threat_score == pytest.approx(0.6 * W_PROTO, abs=1e-3)
    assert run.alerts and run.alerts[0].t == after[0].t


def test_vote_change_without_a_cap_only_relabels():
    """GENUINE. ``never_seen_gps_vote`` alone changes the label, not the severity: still a CRITICAL
    alert. Re-attributing the vote does not make a never-seen GPS stream any less of a threat."""
    run = _run(_hb_only, require_global_position=True, never_seen_gps_vote="MAVLINK_ANOMALY")
    after = _after_gate(run)
    for a in after:
        assert a.threat is True and a.severity is Severity.CRITICAL
        assert a.attack_type is AttackType.MAVLINK_ANOMALY
    assert run.alerts and run.alerts[0].t == after[0].t


# --------------------------------------------------------------------------- #
# 6. no position stream: absence must not become physics attack evidence (P1 follow-up)
# --------------------------------------------------------------------------- #


SPEED_EV = "GPS/VFR speed mismatch"


def _moving_no_position(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    # HEARTBEAT + ATTITUDE + VFR_HUD at 10 m/s; no GLOBAL_POSITION_INT, no GPS_RAW_INT
    return _stream(link, k, t, sys_status=False, gpi=False, raw=None, groundspeed=10.0)


def test_moving_vehicle_without_position_is_coverage_not_telemetry_manipulation():
    """DECIDED P1 follow-up (2026-10-20; the user's "Coverage, not attack" decision applied to the
    physics detector). Was: TELEMETRY_MANIPULATION alerts from the GPS/VFR speed check, which
    compared VFR groundspeed against a GPS velocity that was never received (read as 0). Now the
    rule is gated on position presence; the ML feature itself is unchanged."""
    run = _run(_moving_no_position, seconds=20.0)
    for a, frame in run.decisions:
        assert frame.gps_seen is False and frame.gps_vfr_speed_diff_ms == pytest.approx(10.0)
        assert a.detector_scores[DetectorName.PHYSICS.value] == 0.0
        assert a.threat is False and a.attack_type is not AttackType.TELEMETRY_MANIPULATION
        assert SPEED_EV not in _text(a)
        assert COVERAGE_TEXT in _text(a)
    assert run.alerts == []


def test_speed_mismatch_with_position_present_is_still_detected():
    """GENUINE (control for the gate). GLOBAL_POSITION_INT flowing (stationary, vx = vy = 0) while
    VFR_HUD reports 10 m/s: the GPS/VFR speed check still fires and fuses into a
    TELEMETRY_MANIPULATION alert."""
    run = _run(lambda link, k, t: _stream(link, k, t, groundspeed=10.0), seconds=10.0)
    assert all(frame.gps_seen is True for _, frame in run.decisions)
    alerts = [a for a in run.alerts if a.attack_type is AttackType.TELEMETRY_MANIPULATION]
    assert alerts and SPEED_EV in _text(alerts[0])
    assert COVERAGE_TEXT not in _text(alerts[0])


def test_gnss_alert_on_a_position_less_link_leads_with_the_gnss_evidence():
    """GENUINE (presentation). The score-0 coverage line is the LAST protocol evidence item, so an
    alert raised by another rule does not show it as its headline (the dashboard incident list and
    the CLI show evidence[0]). Scoring of the never-acquired fix is P3 (open) and is not asserted."""
    run = _run(lambda link, k, t: _stream(link, k, t, gpi=False, raw=(0, 0)), seconds=10.0)
    first = run.alerts[0]
    assert first.evidence[0].startswith("GNSS fix never acquired")
    assert first.evidence[-1].startswith(COVERAGE_TEXT)
