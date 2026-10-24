"""Black-box acceptance tests for the telemetry-presence policy ("Coverage, not attack").

USER-DECIDED POLICY (2026-10-15) and FIXED INTERFACE, written from the spec only (red/blue split:
written without reading the detection implementation diff):

* ``FeatureFrame.gps_seen``     -- GLOBAL_POSITION_INT ever received;
  ``FeatureFrame.gps_raw_seen`` -- GPS_RAW_INT ever received; ``heartbeat_seen`` unchanged.
* config ``protocol.require_global_position`` (default ``false``).
* default: a never-received GLOBAL_POSITION_INT on an otherwise healthy link is NOT a threat and NOT
  an alert; the evidence carries "coverage: GLOBAL_POSITION_INT never received" and never
  "GPS dropout" / "lost".
* ``require_global_position: true``: a never-received GLOBAL_POSITION_INT is a threat/alert with
  "GPS dropout: never received", honouring ``never_seen_gps_vote`` / ``never_seen_gps_max_score``.
* startup: never-received streams are judged on monitoring time elapsed since the first decision; the
  first decision (t=0) is never a threat merely because nothing has arrived yet; a heartbeat never
  received for longer than ``heartbeat_timeout_s`` is still a DOS threat.
* loss AFTER a stream was seen stays a DOS threat/alert under both settings.
* GPS_RAW_INT alone does not satisfy position-dependent checks (physics stays blind, score 0).

Every test drives the REAL ``IDSPipeline`` (ML off, ``firmware_dir=None``) on synthetic MAVLink
envelopes and asserts on the final ``ThreatAssessment``. Each docstring names the rule whose reversion
makes it fail. All thresholds come from ``load_config()``. The harness is copied (not imported) from
``tests/unit/test_missing_telemetry_fused.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, DetectorName
from aegisflight.core.types import MessageEnvelope, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.stream import TelemetryTick

TICK_HZ = 10  # simulation.sample_rate_hz; decisions at 5 Hz
_CFG = load_config()
_PROTO_CFG = _CFG.detector["protocol"]
_W = _CFG.detector["fusion"]["weights"]
W_PROTO = _W["protocol_rule"] / max(_W.values())
THREAT_THRESHOLD = _CFG.detector["fusion"]["threat_threshold"]
GPS_DROPOUT_S = _PROTO_CFG["gps_dropout_s"]
HB_TIMEOUT_S = _PROTO_CFG["heartbeat_timeout_s"]
DECISION_DT = 1.0 / _CFG.detector["decision_rate_hz"]

PROTO = DetectorName.PROTOCOL.value
PHYSICS = DetectorName.PHYSICS.value
COVERAGE_TEXT = "coverage: GLOBAL_POSITION_INT never received"
NEVER_GPS_TEXT = "GPS dropout: never received"
REQUIRE = {"require_global_position": True}
SETTINGS = [pytest.param({}, id="default"), pytest.param(REQUIRE, id="require_gpi")]
LOSS_AT = 10.0


# --------------------------------------------------------------------------- #
# synthetic link (copied from tests/unit/test_missing_telemetry_fused.py)
# --------------------------------------------------------------------------- #


class _Link:
    """One autopilot (``sysid`` / compid 1) with ONE running MAVLink sequence counter."""

    def __init__(self, sysid: int = 1) -> None:
        self._seq = -1
        self.sysid = sysid

    def env(self, t: float, name: str, msgid: int, **fields) -> MessageEnvelope:
        self._seq = (self._seq + 1) % 256
        return MessageEnvelope(recv_time=t, sysid=self.sysid, compid=1, msgid=msgid, msgname=name,
                               seq=self._seq, signed=False, byte_len=28, fields=fields)


def _stream(link: _Link, k: int, t: float, *, hb: bool = True, gpi: bool = True,
            raw: bool = True, fix: tuple[int, int] = (3, 10)) -> list[MessageEnvelope]:
    """HEARTBEAT/SYS_STATUS/GPS_RAW_INT 1 Hz, GLOBAL_POSITION_INT 5 Hz, ATTITUDE/VFR_HUD 10 Hz;
    a stationary vehicle. GPS_RAW_INT carries ``fix`` = (fix_type, satellites), default a healthy
    3D fix."""
    out: list[MessageEnvelope] = []
    if k % TICK_HZ == 0:
        if hb:
            out.append(link.env(t, "HEARTBEAT", 0, base_mode=81, custom_mode=0))
        out.append(link.env(t, "SYS_STATUS", 1, voltage_battery=16000, battery_remaining=90))
        if raw:
            out.append(link.env(t, "GPS_RAW_INT", 24, satellites_visible=fix[1], fix_type=fix[0],
                                eph=100))
    if gpi and k % 2 == 0:
        out.append(link.env(t, "GLOBAL_POSITION_INT", 33, lat=int(12.9 * 1e7),
                            lon=int(77.5 * 1e7), alt=900000, relative_alt=0, vx=0, vy=0, vz=0))
    out.append(link.env(t, "ATTITUDE", 30, roll=0.0, pitch=0.0, yaw=0.5, rollspeed=0.0,
                        pitchspeed=0.0, yawspeed=0.0))
    out.append(link.env(t, "VFR_HUD", 74, groundspeed=0.0, heading=28, throttle=0,
                        alt=900.0, climb=0.0))
    return out


# GPS presence matrix: name -> (send GLOBAL_POSITION_INT, send GPS_RAW_INT)
MATRIX = {
    "raw_only": (False, True),
    "gpi_only": (True, False),
    "both": (True, True),
    "neither": (False, False),
}


def _presence(gpi: bool, raw: bool):
    def fn(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
        return _stream(link, k, t, gpi=gpi, raw=raw)
    return fn


def _gpi_lost_mid_run(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    # GLOBAL_POSITION_INT stops; GPS_RAW_INT keeps a healthy fix -- raw must not mask the loss.
    return _stream(link, k, t, gpi=t < LOSS_AT)


def _hb_lost_mid_run(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    return _stream(link, k, t, hb=t < LOSS_AT)


def _hb_never(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    return _stream(link, k, t, hb=False)


class Run:
    def __init__(self, decisions: list[tuple[ThreatAssessment, FeatureFrame]]) -> None:
        self.decisions = decisions

    @property
    def assessments(self) -> list[ThreatAssessment]:
        return [a for a, _ in self.decisions]

    @property
    def alerts(self) -> list[ThreatAssessment]:
        return [a for a in self.assessments if a.is_alert]

    @property
    def t0(self) -> float:
        return self.decisions[0][0].t


def _run(stream_fn, seconds: float = 20.0, *, config_dir: Path | None = None, sysid: int = 1,
         **protocol_overrides) -> Run:
    cfg = load_config(config_dir)  # fresh copy per run: overrides cannot leak between tests
    cfg.detector["protocol"].update(protocol_overrides)
    pipe = IDSPipeline(cfg, model_path=None, firmware_dir=None)
    link = _Link(sysid)
    decisions: list[tuple[ThreatAssessment, FeatureFrame]] = []
    for k in range(int(round(seconds * TICK_HZ))):
        t = k / TICK_HZ
        a = pipe.process_tick(TelemetryTick(t=t, tick=k, messages=stream_fn(link, k, t)))
        if a is not None:
            assert pipe.last_frame is not None
            decisions.append((a, pipe.last_frame))
    assert decisions, "no decisions produced"
    return Run(decisions)


def _text(a: ThreatAssessment) -> str:
    return " | ".join(a.evidence)


def _past_startup(run: Run, window_s: float) -> list[ThreatAssessment]:
    return [a for a in run.assessments if a.t - run.t0 > window_s + DECISION_DT]


# --------------------------------------------------------------------------- #
# 0. interface + control
# --------------------------------------------------------------------------- #


def test_require_global_position_key_exists_and_defaults_false():
    """Fails if the new config key is missing or the default flips to 'attack' semantics."""
    assert load_config().detector["protocol"]["require_global_position"] is False


@pytest.mark.parametrize("overrides", SETTINGS)
def test_healthy_control_is_quiet(overrides):
    """Control: a full healthy stream is quiet under both settings and carries no coverage text.
    Fails if the harness itself is noisy, or if coverage text leaks onto a link that has GPI."""
    run = _run(_presence(True, True), **overrides)
    for a in run.assessments:
        assert not a.threat and not a.is_alert
        assert COVERAGE_TEXT not in _text(a)


# --------------------------------------------------------------------------- #
# 1. presence flags (independent of the setting)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("overrides", SETTINGS)
@pytest.mark.parametrize("case", list(MATRIX))
def test_presence_flags(case, overrides):
    """gps_seen tracks GLOBAL_POSITION_INT only; gps_raw_seen tracks GPS_RAW_INT only. Fails if the
    new field is missing, or if GPS_RAW_INT is (re)counted as gps_seen (P2 reverted)."""
    gpi, raw = MATRIX[case]
    run = _run(_presence(gpi, raw), **overrides)
    for _, frame in run.decisions:
        assert frame.heartbeat_seen is True
        assert frame.gps_seen is gpi
        assert frame.gps_raw_seen is raw


# --------------------------------------------------------------------------- #
# 2. GLOBAL_POSITION_INT present: quiet under both settings
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("overrides", SETTINGS)
@pytest.mark.parametrize("case", ["gpi_only", "both"])
def test_gpi_present_is_quiet_without_coverage_text(case, overrides):
    """With GLOBAL_POSITION_INT flowing there is nothing to report, with or without GPS_RAW_INT.
    Fails if a missing GPS_RAW_INT is treated as a GPS threat, or coverage text is emitted
    when GPI was received."""
    gpi, raw = MATRIX[case]
    run = _run(_presence(gpi, raw), **overrides)
    for a in run.assessments:
        assert not a.threat and not a.is_alert, (a.t, a.evidence)
        assert COVERAGE_TEXT not in _text(a)
        assert "never received" not in _text(a)


# --------------------------------------------------------------------------- #
# 3. GLOBAL_POSITION_INT never received -- default: coverage, not attack
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", ["raw_only", "neither"])
def test_default_gpi_never_received_is_coverage_not_threat(case):
    """Default policy. Fails if the decided 'coverage, not attack' rule is reverted (the
    pre-existing behaviour was a CRITICAL DOS on every decision with "GPS dropout: never received").

    Coverage text is asserted on every assessment past the startup window (gps_dropout_s); the spec
    did not say whether t=0 must already carry it (the implementation does)."""
    gpi, raw = MATRIX[case]
    run = _run(_presence(gpi, raw))
    for a in run.assessments:
        assert not a.threat and not a.is_alert, (a.t, a.evidence)
        assert "GPS dropout" not in _text(a)
        assert "lost" not in _text(a)
    late = _past_startup(run, GPS_DROPOUT_S)
    assert late
    for a in late:
        assert COVERAGE_TEXT in _text(a), (a.t, a.evidence)
    assert run.alerts == []


def test_default_raw_only_coverage_line_says_gps_raw_present():
    """GPS_RAW_INT-only: the coverage line must say GPS_RAW_INT IS present (so an operator can tell
    'no position stream' from 'no GPS at all'). Fails if the coverage text ignores gps_raw_seen.
    (Strengthened 2026-10-20: the bare substring "GPS_RAW_INT" also matched "GPS_RAW_INT never
    received"; the neither-case control below pins the other wording.)"""
    run = _run(_presence(False, True))
    late = _past_startup(run, GPS_DROPOUT_S)
    assert late
    for a in late:
        line = next(e for e in a.evidence if COVERAGE_TEXT in e)
        assert "GPS_RAW_INT present" in line and "GPS_RAW_INT never received" not in line, line
    neither = _past_startup(_run(_presence(False, False)), GPS_DROPOUT_S)
    for a in neither:
        line = next(e for e in a.evidence if COVERAGE_TEXT in e)
        assert "GPS_RAW_INT never received" in line and "GPS_RAW_INT present" not in line, line


@pytest.mark.parametrize("overrides", SETTINGS)
def test_gps_raw_only_physics_stays_blind(overrides):
    """GPS_RAW_INT alone does not satisfy position-dependent checks: physics score 0 on every
    decision. Fails if GPS_RAW_INT were promoted to a position source for the physics detector."""
    run = _run(_presence(False, True), **overrides)
    for a in run.assessments:
        assert a.detector_scores[PHYSICS] == 0.0


# --------------------------------------------------------------------------- #
# 4. GLOBAL_POSITION_INT never received -- require_global_position: true
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", ["raw_only", "neither"])
def test_require_gpi_never_received_is_threat(case):
    """require_global_position=true restores the pre-existing never-received threat, but with the
    startup rule (no threat at t=0). Fails if the flag is ignored (always coverage) or if the startup
    rule is missing (threat at t=0). GPS_RAW_INT must not satisfy the requirement."""
    gpi, raw = MATRIX[case]
    run = _run(_presence(gpi, raw), **REQUIRE)
    assert not run.assessments[0].threat
    threats = [a for a in run.assessments if a.threat]
    assert threats and run.alerts
    for a in threats:
        assert NEVER_GPS_TEXT in _text(a)
        assert COVERAGE_TEXT not in _text(a)
        assert a.t - run.t0 > GPS_DROPOUT_S - 1e-6  # judged on elapsed monitoring time
    assert threats[0].attack_type is AttackType.DOS


def test_require_gpi_honours_never_seen_vote_and_cap():
    """never_seen_gps_vote / never_seen_gps_max_score still apply when GPI is required. Fails if the
    require path bypasses the existing knobs."""
    cap = 0.6
    assert cap * W_PROTO >= THREAT_THRESHOLD  # derived: this cap can still reach a fused threat
    run = _run(_presence(False, True), never_seen_gps_vote="MAVLINK_ANOMALY",
               never_seen_gps_max_score=cap, **REQUIRE)
    threats = [a for a in run.assessments if a.threat]
    assert threats
    for a in threats:
        assert a.attack_type is AttackType.MAVLINK_ANOMALY
    for a in run.assessments:
        assert a.detector_scores[PROTO] <= cap + 1e-6

    floored = _run(_presence(False, True), never_seen_gps_vote="MAVLINK_ANOMALY",
                   never_seen_gps_max_score=0.0, **REQUIRE)
    assert 0.5 * W_PROTO < THREAT_THRESHOLD
    assert not any(a.threat for a in floored.assessments)
    assert any(NEVER_GPS_TEXT in _text(a) for a in floored.assessments)


# --------------------------------------------------------------------------- #
# 5. startup and never-received heartbeat
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("overrides", SETTINGS)
@pytest.mark.parametrize("stream", ["raw_only", "neither", "hb_never"])
def test_startup_first_decision_is_quiet(stream, overrides):
    """t=0: nothing has had time to arrive; the first decision is not a threat. Fails if
    never-received is judged on the 999 s sentinel instead of elapsed monitoring time (the old
    behaviour alerted at t=0)."""
    fn = _hb_never if stream == "hb_never" else _presence(*MATRIX[stream])
    run = _run(fn, seconds=2.0, **overrides)
    first = run.assessments[0]
    assert first.t == run.t0
    assert not first.threat and not first.is_alert, first.evidence


@pytest.mark.parametrize("overrides", SETTINGS)
def test_heartbeat_never_received_threat_only_after_timeout(overrides):
    """A heartbeat never received must become a DOS threat once monitoring time exceeds
    heartbeat_timeout_s, and not before. Fails if the never-received heartbeat is suppressed
    as 'coverage' (silent suppression) or if it fires during startup."""
    run = _run(_hb_never, seconds=20.0, **overrides)
    for a in run.assessments:
        if a.t - run.t0 <= HB_TIMEOUT_S - 1e-6:
            assert not a.threat, (a.t, a.evidence)
    threats = [a for a in run.assessments if a.threat]
    assert threats, "never-received heartbeat produced no threat"
    first = threats[0]
    # Loose spec-level bound (the exact first decision is pinned in
    # tests/unit/test_missing_telemetry_fused.py). There is no elapsed-time ramp: once elapsed
    # monitoring time exceeds heartbeat_timeout_s the protocol score jumps straight to the
    # age-ramp value of the 999 s never-seen sentinel, i.e. 1.0.
    assert first.t - run.t0 <= 2 * HB_TIMEOUT_S + DECISION_DT
    assert first.attack_type is AttackType.DOS
    assert "heartbeat stale" in _text(first)
    assert "coverage" not in _text(first)  # a missing heartbeat is never a mere coverage note
    assert run.alerts


# --------------------------------------------------------------------------- #
# 6. loss after previously seen stays a DOS alert under both settings
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("overrides", SETTINGS)
def test_gpi_lost_mid_run_is_dos_alert(overrides):
    """GLOBAL_POSITION_INT flows for 10 s then stops (GPS_RAW_INT continues). Fails if the
    coverage policy swallows a genuine loss, or if GPS_RAW_INT presence masks the GPI loss."""
    run = _run(_gpi_lost_mid_run, seconds=30.0, **overrides)
    assert not any(a.threat for a in run.assessments if a.t < LOSS_AT)
    alerts = [a for a in run.alerts if a.t >= LOSS_AT]
    assert alerts, "genuine GPI loss produced no alert"
    first = alerts[0]
    assert first.threat and first.attack_type is AttackType.DOS
    assert first.t - LOSS_AT <= 3 * GPS_DROPOUT_S + DECISION_DT  # within the dropout ramp
    for a in (x for x in run.assessments if x.t >= LOSS_AT):
        assert "never received" not in _text(a) and "coverage" not in _text(a)
    assert "GPS dropout" in _text(first)


@pytest.mark.parametrize("overrides", SETTINGS)
def test_heartbeat_lost_mid_run_is_dos_alert(overrides):
    """HEARTBEAT flows for 10 s then stops. Fails if a previously-seen heartbeat loss is
    reclassified as never-received/coverage, or not alerted."""
    run = _run(_hb_lost_mid_run, seconds=30.0, **overrides)
    assert not any(a.threat for a in run.assessments if a.t < LOSS_AT)
    alerts = [a for a in run.alerts if a.t >= LOSS_AT]
    assert alerts, "genuine heartbeat loss produced no alert"
    first = alerts[0]
    assert first.threat and first.attack_type is AttackType.DOS
    assert first.t - LOSS_AT <= 2 * HB_TIMEOUT_S + 1.0 + DECISION_DT  # 1 Hz HB + ramp
    assert "heartbeat stale" in _text(first)
    for a in (x for x in run.assessments if x.t >= LOSS_AT):
        assert "never received" not in _text(a) and "coverage" not in _text(a)


# --------------------------------------------------------------------------- #
# 7. IDSPipeline.reset() clears presence flags, the elapsed-time origin and the
#    GNSS valid-fix memory (added 2026-10-20, aegis-validation)
# --------------------------------------------------------------------------- #

RESET_AT = 5.0
RAW_BACK_AFTER_S = 1.0  # post-reset GPS_RAW_INT (fix 0 / 0 satellites) starts this long after reset
_MEASURED_AGE = re.compile(r"(heartbeat stale|GPS dropout) \d")  # "...stale 4.2s", "...dropout 2.4s"


def _reset_run(**protocol_overrides) -> tuple[Run, Run]:
    """Phase A (0 to RESET_AT s): full healthy stream with a valid 3D fix. Then ``IDSPipeline.reset()``
    on the SAME pipeline, and phase B (10 s; clock and tick counter continue): no HEARTBEAT, no
    GLOBAL_POSITION_INT, and GPS_RAW_INT with fix 0 / 0 satellites only from
    RESET_AT + RAW_BACK_AFTER_S."""
    cfg = load_config()
    cfg.detector["protocol"].update(protocol_overrides)
    pipe = IDSPipeline(cfg, model_path=None, firmware_dir=None)
    link = _Link()
    n_a = int(round(RESET_AT * TICK_HZ))
    before: list[tuple[ThreatAssessment, FeatureFrame]] = []
    after: list[tuple[ThreatAssessment, FeatureFrame]] = []
    for k in range(n_a + 10 * TICK_HZ):
        t = k / TICK_HZ
        if k == n_a:
            pipe.reset()
        if k < n_a:
            msgs = _stream(link, k, t)
        else:
            msgs = _stream(link, k, t, hb=False, gpi=False, raw=t >= RESET_AT + RAW_BACK_AFTER_S,
                           fix=(0, 0))
        a = pipe.process_tick(TelemetryTick(t=t, tick=k, messages=msgs))
        if a is not None:
            assert pipe.last_frame is not None
            (before if k < n_a else after).append((a, pipe.last_frame))
    assert before and after
    return Run(before), Run(after)


@pytest.mark.parametrize("overrides", SETTINGS)
def test_pipeline_reset_clears_presence_flags_elapsed_origin_and_gnss_memory(overrides):
    """After ``IDSPipeline.reset()`` the presence policy restarts from scratch:

    * ``heartbeat_seen`` / ``gps_seen`` / ``gps_raw_seen`` reflect post-reset traffic only (fails if
      ``FeatureExtractor.reset`` keeps a seen-flag: a heartbeat/position silence would then be
      judged on a measured age, "heartbeat stale 3.2s" / "GPS dropout 2.2s");
    * the never-received heartbeat is judged on elapsed time since the FIRST POST-RESET decision
      (fails if ``ProtocolDetector.reset`` keeps ``_t0``: it would fire on the first post-reset
      decision);
    * a bad fix after reset is "GNSS fix never acquired", never "lost" (fails if the valid fix seen
      before the reset is remembered);
    * never-received position after reset is the coverage line by default and the DOS fault only
      under ``require_global_position``. This pins the security consequence disclosed in
      docs/DETECTION.md: a reset while position is already suppressed is reported as coverage, not
      as an alert, under the default profile."""
    before, after = _reset_run(**overrides)
    require = bool(overrides.get("require_global_position", False))
    for a, frame in before.decisions:  # control: phase A is healthy and quiet
        assert not a.threat, (a.t, a.evidence)
        assert frame.heartbeat_seen and frame.gps_seen and frame.gps_raw_seen
    assert after.t0 == pytest.approx(RESET_AT)
    first = after.assessments[0]
    assert not first.threat and not first.is_alert, first.evidence
    gnss_fired = False
    for a, frame in after.decisions:
        elapsed = a.t - after.t0
        text = _text(a)
        assert frame.heartbeat_seen is False and frame.gps_seen is False, a.t
        assert frame.gps_raw_seen is (elapsed >= RAW_BACK_AFTER_S - 1e-9), a.t
        assert not _MEASURED_AGE.search(text), (a.t, a.evidence)
        assert ("heartbeat stale (never received" in text) is (elapsed > HB_TIMEOUT_S + 1e-9), (a.t, a.evidence)
        assert "GNSS fix lost" not in text, (a.t, a.evidence)
        gnss_fired = gnss_fired or "GNSS fix never acquired" in text
        if require:
            assert (NEVER_GPS_TEXT in text) is (elapsed > GPS_DROPOUT_S + 1e-9), (a.t, a.evidence)
            assert COVERAGE_TEXT not in text
        else:
            assert COVERAGE_TEXT in text and "GPS dropout" not in text, (a.t, a.evidence)
    assert gnss_fired, "post-reset bad fix never reached the GNSS rule"


# --------------------------------------------------------------------------- #
# 8. configs/px4_sitl: startup_grace_s and the elapsed-time gate combine as a
#    MAXIMUM (the later applies), black-box (added 2026-10-20, aegis-validation)
# --------------------------------------------------------------------------- #

PX4_PROFILE = Path(__file__).resolve().parents[2] / "configs" / "px4_sitl"
PX4_SYSID = 3  # the profile's expected_sysids: a sysid-1 link would raise "rogue telemetry source"
PX4_GRACE_S = load_config(PX4_PROFILE).detector["protocol"]["startup_grace_s"]


def _hb_never_stream(link: _Link, k: int, t: float) -> list[MessageEnvelope]:
    return _stream(link, k, t, hb=False)


def test_px4_sitl_profile_control_is_quiet():
    """Control for section 8: the full stream on the PX4 profile (sysid 3) is quiet, so every result
    below is caused by the missing stream, not by the profile/harness combination."""
    run = _run(_presence(True, True), config_dir=PX4_PROFILE, sysid=PX4_SYSID)
    assert not any(a.threat or a.is_alert for a in run.assessments)


@pytest.mark.parametrize(("stream", "overrides", "gate_s", "text"), [
    pytest.param(_hb_never_stream, {}, HB_TIMEOUT_S, "heartbeat stale (never received",
                 id="hb_never-profile_grace"),
    pytest.param(_presence(False, True), REQUIRE, GPS_DROPOUT_S, NEVER_GPS_TEXT,
                 id="gpi_never_required-profile_grace"),
    pytest.param(_hb_never_stream, {"startup_grace_s": 4.0}, HB_TIMEOUT_S,
                 "heartbeat stale (never received", id="hb_never-grace_beyond_gate"),
])
def test_px4_sitl_profile_grace_and_gate_combine_as_maximum(stream, overrides, gate_s, text):
    """docs/DETECTION.md: ``startup_grace_s`` combines with the elapsed-time gate as a maximum, it
    does not add to it. The first fault is the first decision with elapsed > gate AND elapsed >=
    grace. Fails if the two were summed (first fault at gate + grace), or if the grace alone decided
    (first fault right after the grace)."""
    grace = float(overrides.get("startup_grace_s", PX4_GRACE_S))
    assert grace > 0.0  # the profile really sets a grace, or this test proves nothing
    run = _run(stream, config_dir=PX4_PROFILE, sysid=PX4_SYSID, **overrides)
    elapsed = [a.t - run.t0 for a in run.assessments]
    expected = min(e for e in elapsed if e > gate_s + 1e-9 and e >= grace - 1e-9)
    assert expected < gate_s + grace - 1e-9  # a summing implementation would fire later
    fired = [(e, a) for e, a in zip(elapsed, run.assessments, strict=True) if text in _text(a)]
    assert fired, "the never-received fault never fired"
    assert fired[0][0] == pytest.approx(expected)
    assert fired[0][1].threat and fired[0][1].attack_type is AttackType.DOS
    assert not any(a.threat for e, a in zip(elapsed, run.assessments, strict=True) if e < expected - 1e-9)
