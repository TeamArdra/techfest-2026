"""EKF-health and GPS receiver-signature rules (extractor fields + PhysicsDetector votes).

Environment: SYNTHETIC frames / envelopes built in this file (no real receiver, no spoofer
captured). They show the rules are wired and behave as documented; they are NOT evidence of
real-world detection performance. Thresholds are uncalibrated engineering defaults.
"""

from __future__ import annotations

import numpy as np

from aegisflight.attacks import build_attack
from aegisflight.config import load_config
from aegisflight.core.enums import AttackType
from aegisflight.core.types import MessageEnvelope, TelemetrySnapshot
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.features.extractor import FeatureExtractor, FeatureFrame
from aegisflight.sources.stream import SimulatedTelemetrySource

CFG = load_config().detector["physics"]
GS = AttackType.GPS_SPOOFING


def _env(t, name, msgid, **f):
    return MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=msgid, msgname=name,
                           seq=0, signed=False, byte_len=28, fields=f)


def _frame(**kw) -> FeatureFrame:
    snap = TelemetrySnapshot(t=0.0)
    snap.gps_fix_type = kw.pop("fix", 3)
    return FeatureFrame(t=0.0, snapshot=snap, **kw)


def _ticks(det, n, **kw):
    return [det.process(_frame(**kw)) for _ in range(n)]


def _gs_hits(res):
    return GS in res.attack_votes and res.triggered


# ---- extractor ---------------------------------------------------------------------------- #

def test_ekf_variances_exposed_and_expire():
    ex = FeatureExtractor()
    ex.update(_env(1.0, "EKF_STATUS_REPORT", 193, flags=0x33F, velocity_variance=1.2,
                   pos_horiz_variance=0.4, compass_variance=0.1))
    fr = ex.extract(1.5)
    assert (fr.ekf_vel_var, fr.ekf_pos_var, fr.ekf_compass_var) == (1.2, 0.4, 0.1)
    fr = ex.extract(3.5)  # older than 2 s
    assert fr.ekf_vel_var is None and fr.ekf_pos_var is None and fr.ekf_compass_var is None


def test_sat_jump_snr_and_vel_disagree_fields():
    ex = FeatureExtractor()
    ex.update(_env(0.0, "GPS_STATUS", 25, satellite_snr=[40] * 12 + [0] * 8, satellites_visible=12))
    ex.update(_env(0.0, "GPS_RAW_INT", 24, satellites_visible=14, fix_type=3, eph=100, vel=1000))
    ex.update(_env(1.0, "GPS_RAW_INT", 24, satellites_visible=5, fix_type=3, eph=100, vel=1000))
    ex.update(_env(1.0, "GLOBAL_POSITION_INT", 33, lat=0, lon=0, alt=0, relative_alt=0,
                   vx=0, vy=0, vz=0))
    fr = ex.extract(1.2)
    assert fr.gps_sat_jump == 9
    assert fr.gps_snr_sats == 12 and fr.gps_snr_spread_db == 0.0
    assert fr.gps_vel_disagree_ms == 10.0
    assert ex.extract(2.6).gps_sat_jump == 0  # held only 1 s


def test_snr_none_with_few_satellites():
    ex = FeatureExtractor()
    ex.update(_env(0.0, "GPS_STATUS", 25, satellite_snr=[40] * 7 + [0] * 13, satellites_visible=7))
    fr = ex.extract(0.5)
    assert fr.gps_snr_spread_db is None and fr.gps_snr_sats == 0


def test_new_fields_none_on_sim_stream():
    """SIM stream (real simulator + spoofing attack): the new fields stay at their defaults."""
    cfg = load_config()
    attack = build_attack("gps_spoofing", cfg.attacks, np.random.default_rng(1))
    ex = FeatureExtractor()
    n = 0
    for tick in SimulatedTelemetrySource(cfg, attack, seed=3).stream():
        for m in tick.messages:
            ex.update(m)
        fr = ex.extract(tick.t)
        assert fr.ekf_vel_var is None and fr.ekf_pos_var is None and fr.ekf_compass_var is None
        assert fr.gps_sat_jump == 0 and fr.gps_snr_spread_db is None
        assert fr.gps_vel_disagree_ms is None
        n += 1
        if n > 600:
            break
    assert n > 100


# ---- detector ----------------------------------------------------------------------------- #

def test_inert_when_messages_absent():
    res = PhysicsDetector(CFG).process(_frame())
    assert res.score == 0.0 and not res.evidence and not res.attack_votes


def test_ekf_variance_rule_with_hysteresis_and_warning_level():
    det = PhysicsDetector(CFG)
    first, second = _ticks(det, 2, ekf_vel_var=1.4, ekf_pos_var=0.1, ekf_compass_var=0.0)
    assert not first.triggered  # damped until hysteresis_ticks
    assert _gs_hits(second) and any("EKF innovation ratio" in e for e in second.evidence)
    det = PhysicsDetector(CFG)
    res = _ticks(det, 3, ekf_vel_var=0.1, ekf_pos_var=0.6, ekf_compass_var=0.0)[-1]
    assert not res.triggered and res.attack_votes[GS] < 0.5 and res.evidence  # evidence only
    quiet = _ticks(PhysicsDetector(CFG), 3, ekf_vel_var=0.05, ekf_pos_var=0.1, ekf_compass_var=0.0)
    assert all(r.score == 0.0 for r in quiet)


def test_satellite_jump_rule():
    det = PhysicsDetector(CFG)
    res = _ticks(det, 2, gps_sat_jump=8)[-1]
    assert _gs_hits(res) and any("satellites_visible" in e for e in res.evidence)
    assert all(r.score == 0.0 for r in _ticks(PhysicsDetector(CFG), 3, gps_sat_jump=2))
    # fix lost: that is jamming / loss (other rules), not this one
    assert all(r.score == 0.0 for r in _ticks(PhysicsDetector(CFG), 3, gps_sat_jump=8, fix=0))


def test_snr_uniformity_rule():
    det = PhysicsDetector(CFG)
    res = _ticks(det, 2, gps_snr_spread_db=0.4, gps_snr_sats=10)[-1]
    assert _gs_hits(res) and any("SNR spread" in e for e in res.evidence)
    assert all(r.score == 0.0 for r in _ticks(PhysicsDetector(CFG), 3, gps_snr_spread_db=5.5,
                                              gps_snr_sats=10))
    assert all(r.score == 0.0 for r in _ticks(PhysicsDetector(CFG), 3, gps_snr_spread_db=0.4,
                                              gps_snr_sats=5))


def test_velocity_disagreement_rule():
    det = PhysicsDetector(CFG)
    res = _ticks(det, 2, gps_vel_disagree_ms=6.0)[-1]
    assert _gs_hits(res) and any("velocity differs" in e for e in res.evidence)
    assert all(r.score == 0.0 for r in _ticks(PhysicsDetector(CFG), 3, gps_vel_disagree_ms=0.8))
    det = PhysicsDetector(CFG)
    _ticks(det, 1, gps_vel_disagree_ms=6.0)
    det.process(_frame(gps_vel_disagree_ms=0.5))  # streak broken
    assert not det.process(_frame(gps_vel_disagree_ms=6.0)).triggered


def test_plain_set_mode_message_is_recorded_as_a_do_set_mode_command():
    """A pilot's legacy SET_MODE message must count as a mode-change command (it cancels the GPS ladder)."""
    from aegisflight.features.extractor import FeatureExtractor

    ex = FeatureExtractor()
    ex.update(MessageEnvelope(recv_time=1.0, sysid=255, compid=190, msgid=11, msgname="SET_MODE", seq=0,
                              signed=False, byte_len=14, fields={"target_system": 1, "base_mode": 1, "custom_mode": 5}))
    cmds = ex.extract(1.2).commands_recent
    assert len(cmds) == 1 and cmds[0].command == 176 and cmds[0].sysid == 255 and cmds[0].params[1] == 5.0
