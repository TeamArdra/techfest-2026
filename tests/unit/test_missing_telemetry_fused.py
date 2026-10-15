"""Fused-level (``ThreatAssessment``) regression tests for missing-telemetry scenarios.

``test_missing_telemetry.py`` stops at the extractor + protocol detector. These tests run the REAL
``IDSPipeline`` (extractor -> four detectors -> fusion, ML off, no firmware verifier: exactly what
``scripts/hardware/run_serial_ids.py`` builds) on synthetic MAVLink envelopes and assert on the final
``ThreatAssessment`` -- ``threat``, ``severity``, ``attack_type``, ``is_alert``, ``evidence`` --
because that is what the runner persists. No hardware, no sockets, no production code touched.

Three kinds of test live here; the kind is stated in each docstring.

* ``GENUINE``  -- an expectation that follows from existing code/docs or from the "never received
  vs lost after being seen must be distinguishable" principle already adopted. Passes today.
* ``PENDING POLICY Pn`` -- pins the CURRENT fused outcome of a case whose *correct* outcome is an
  undecided policy question. It documents what the pipeline does today; it is NOT a statement that
  the outcome is right. When the policy is decided, change these tests deliberately.
    P1  minimum persisted visibility / classification of a never-observed GPS stream
        (alert? attack class? a WATCH-level coverage condition?) -- depends on whether the profile
        can say GPS is expected, which no profile can today;
    P2  does ``GPS_RAW_INT`` count as GPS presence for the liveness rule (today only
        ``GLOBAL_POSITION_INT`` does)?
    P3  is a fix that was never acquired denial evidence at all, or a coverage condition?
* ``xfail(strict=True)`` -- an expectation that currently FAILS. Strict, so the suite stays green
  today and goes red (XPASS) the moment the behaviour is fixed, prompting removal of the marker.
  ``pytest --runxfail`` shows the real failures.

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
            gpi: bool = True, raw: tuple[int, int] | None = (3, 10), att: bool = True
            ) -> list[MessageEnvelope]:
    """Messages of tick ``k``. HEARTBEAT/SYS_STATUS/GPS_RAW_INT 1 Hz, GLOBAL_POSITION_INT 5 Hz,
    ATTITUDE/VFR_HUD 10 Hz; a stationary vehicle. ``raw`` = (fix_type, satellites) or None."""
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
        out.append(link.env(t, "VFR_HUD", 74, groundspeed=0.0, heading=28, throttle=0,
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
    (not a measured age); the physics detector is blind (score 0), not alarmed."""
    run = _run(_hb_only)
    for a, frame in run.decisions:
        assert frame.heartbeat_seen is True and frame.gps_seen is False
        assert NEVER_GPS_TEXT in _text(a)
        assert a.detector_scores[DetectorName.PHYSICS.value] == 0.0


def test_heartbeat_only_default_is_currently_a_critical_dos_attack():
    """PENDING POLICY P1 -- pins CURRENT behaviour, not a statement that it is right.

    With defaults a link that never sends GLOBAL_POSITION_INT is a CRITICAL ``DOS`` threat on
    every decision; the evidence text says "incomplete telemetry, not a measured dropout" while
    ``attack_type``/``severity`` say attack. Which of the two should change is the P1 decision."""
    run = _run(_hb_only)
    for a in run.assessments:
        assert a.threat is True
        assert a.attack_type is AttackType.DOS
        assert a.severity is Severity.CRITICAL
        assert a.threat_score == pytest.approx(W_PROTO, abs=1e-3)  # protocol score 1.0 * w'
    alerts = run.alerts
    assert alerts and alerts[0].t == 0.0  # an alert on the very first decision
    assert all(b.t - a.t >= COOLDOWN_S - 1e-6 for a, b in zip(alerts, alerts[1:], strict=False))


# --------------------------------------------------------------------------- #
# 2. healthy GPS_RAW_INT without GLOBAL_POSITION_INT
# --------------------------------------------------------------------------- #


def test_gps_raw_only_pipeline_holds_a_healthy_fix_yet_reports_gps_never_seen():
    """GENUINE (a fact about the current code, not a policy). The extractor ingests the healthy
    GPS_RAW_INT (fix 3D, 10 satellites) into its snapshot, while ``gps_seen`` -- the flag the
    liveness rule reads -- stays False because only GLOBAL_POSITION_INT sets it. Two parts of the
    same pipeline disagree about whether GPS is present; P2 decides which one is right."""
    run = _run(_gps_raw_only)
    snap = run.pipe.extractor.snapshot
    assert snap.gps_fix_type == 3 and snap.satellites == 10
    assert all(frame.gps_seen is False for _, frame in run.decisions)


def test_gps_raw_only_is_currently_a_critical_dos_attack():
    """PENDING POLICY P2 -- pins CURRENT behaviour. A link that delivers a healthy GPS fix via
    GPS_RAW_INT but no position is CRITICAL ``DOS`` on every decision."""
    run = _run(_gps_raw_only)
    for a in run.assessments:
        assert a.threat is True and a.attack_type is AttackType.DOS
        assert a.severity is Severity.CRITICAL
        assert NEVER_GPS_TEXT in _text(a)


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


# --------------------------------------------------------------------------- #
# 5. a capped never-seen vote, tested against the final ThreatAssessment
# --------------------------------------------------------------------------- #


def test_cap_at_the_floor_is_not_a_threat_and_not_an_alert():
    """PENDING POLICY P1 -- pins CURRENT behaviour at the final-assessment level.

    ``never_seen_gps_max_score`` is floored at 0.5, but 0.5 * w' (~0.441) is BELOW the fusion
    ``threat_threshold`` (0.45): the assessment is ``threat=False``, severity NORMAL, never an alert
    (the serial runner persists only alerts). The condition is still visible INSIDE each assessment
    (evidence text, protocol detector score 0.5), just in nothing the runner writes out. A cap of 0.0
    is clamped to the same 0.5."""
    assert 0.5 * W_PROTO < THREAT_THRESHOLD  # the arithmetic that makes the floor sub-threshold
    for cap in (0.5, 0.0):
        run = _run(_hb_only, never_seen_gps_vote="MAVLINK_ANOMALY", never_seen_gps_max_score=cap)
        for a in run.assessments:
            assert a.threat is False and a.is_alert is False and a.severity is Severity.NORMAL
            assert a.threat_score == pytest.approx(0.5 * W_PROTO, abs=1e-3)
            assert a.detector_scores[PROTO] == pytest.approx(0.5)
            assert NEVER_GPS_TEXT in _text(a)
        assert run.alerts == []


@pytest.mark.xfail(strict=True, reason=(
    "docs/DETECTION.md and detectors/protocol.py say the cap is 'floored at 0.5 so the condition "
    "always still triggers' / 'is always still reported -- never silently accepted'. At the floor "
    "the fused assessment is neither a threat nor an alert, so nothing the runner persists records "
    "it. 'Triggers/reported' is ambiguous (detector bump vs operator-visible alert): the P1 decision "
    "must pick the minimum persisted visibility, then either the floor or the docs change."))
def test_documented_floor_guarantee_holds_at_the_final_assessment():
    """XFAIL (strict). The documented 'never silently accepted' guarantee, read as 'a never-seen GPS
    stream is a threat or an alert for every legal cap value'. The interpretation is the open
    question P1, which is exactly why this is xfail and not a hard failure."""
    run = _run(_hb_only, never_seen_gps_vote="MAVLINK_ANOMALY", never_seen_gps_max_score=0.0)
    assert any(a.threat or a.is_alert for a in run.assessments)


def test_cap_above_the_fused_threshold_is_a_suspicious_alert():
    """GENUINE (arithmetic of the current fusion). Cap 0.6 -> fused 0.6 * w' (~0.529): a threat,
    SUSPICIOUS, labelled MAVLINK_ANOMALY, alerting on the first decision."""
    assert 0.6 * W_PROTO >= THREAT_THRESHOLD
    run = _run(_hb_only, never_seen_gps_vote="MAVLINK_ANOMALY", never_seen_gps_max_score=0.6)
    for a in run.assessments:
        assert a.threat is True and a.severity is Severity.SUSPICIOUS
        assert a.attack_type is AttackType.MAVLINK_ANOMALY
        assert a.threat_score == pytest.approx(0.6 * W_PROTO, abs=1e-3)
    assert run.alerts and run.alerts[0].t == 0.0


def test_vote_change_without_a_cap_only_relabels():
    """GENUINE. ``never_seen_gps_vote`` alone changes the label, not the severity: still a CRITICAL
    alert. Re-attributing the vote does not make a never-seen GPS stream any less of a threat."""
    run = _run(_hb_only, never_seen_gps_vote="MAVLINK_ANOMALY")
    for a in run.assessments:
        assert a.threat is True and a.severity is Severity.CRITICAL
        assert a.attack_type is AttackType.MAVLINK_ANOMALY
    assert run.alerts and run.alerts[0].t == 0.0
