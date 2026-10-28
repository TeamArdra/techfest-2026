"""Mission-path check. Environment: SYNTHETIC envelopes built here (no real vehicle or capture);
shows the wiring and documented behaviour, not real-world detection performance."""

from __future__ import annotations

from dataclasses import replace

import numpy as np

from aegisflight.attacks import build_attack
from aegisflight.config import load_config
from aegisflight.core.enums import AttackType
from aegisflight.core.geo import offset_latlon
from aegisflight.core.types import MessageEnvelope
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.features.extractor import FeatureExtractor
from aegisflight.sources.stream import SimulatedTelemetrySource

CFG = load_config().detector["physics"]
L0 = (47.0, 8.0)
WPS = [L0, offset_latlon(*L0, 1000.0, 0.0), offset_latlon(*L0, 1000.0, 1000.0), offset_latlon(*L0, 0.0, 1000.0)]


def env(t, name, **f):
    return MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=0, msgname=name, seq=0,
                           signed=False, byte_len=20, fields=f)


def upload(ex, wps=WPS, t=0.0, skip=None, use_int=True):
    ex.update(env(t, "MISSION_COUNT", count=len(wps), mission_type=0))
    for i, (la, lo) in enumerate(wps):
        if i == skip:
            continue
        if use_int:
            ex.update(env(t, "MISSION_ITEM_INT", seq=i, frame=6, command=16,
                          x=int(la * 1e7), y=int(lo * 1e7), mission_type=0))
        else:
            ex.update(env(t, "MISSION_ITEM", seq=i, frame=3, command=16, x=la, y=lo, mission_type=0))


def fly(ex, t, pos, cur=1, mode=3, armed=True, send_current=True):
    if send_current:
        ex.update(env(t, "MISSION_CURRENT", seq=cur))
    ex.update(env(t, "HEARTBEAT", type=2, autopilot=3, base_mode=128 if armed else 0, custom_mode=mode))
    ex.update(env(t, "GLOBAL_POSITION_INT", lat=int(pos[0] * 1e7), lon=int(pos[1] * 1e7), alt=100000,
                  relative_alt=50000, vx=0, vy=0, vz=0))
    return ex.extract(t)


def _nores(f):
    # synthetic teleports would trip the position-residual rule; isolate the mission rule
    return replace(f, pos_residual_m=0.0, pos_residual_nav_m=None)


def on_leg(frac, off_e=0.0):
    return offset_latlon(L0[0], L0[1], 1000.0 * frac, off_e)


def test_complete_upload_builds_and_incomplete_does_not():
    ex = FeatureExtractor()
    upload(ex)
    assert ex._mission.complete and len(ex._mission.waypoints()) == 4
    ex2 = FeatureExtractor()
    upload(ex2, skip=2)
    assert not ex2._mission.complete
    f = fly(ex2, 1.0, on_leg(0.5))
    assert f.mission_known is False and f.mission_xtrack_m is None


def test_mission_item_degrees_variant():
    ex = FeatureExtractor()
    upload(ex, use_int=False)
    assert ex._mission.complete
    assert abs(ex._mission.waypoints()[1][1] - WPS[1][0]) < 1e-9


def test_new_upload_replaces_mission():
    ex = FeatureExtractor()
    upload(ex)
    ex.update(env(1.0, "MISSION_COUNT", count=2, mission_type=0))
    assert not ex._mission.complete
    upload(ex, WPS[:2], t=1.0)
    assert len(ex._mission.waypoints()) == 2


def test_along_leg_quiet_and_offset_alerts_after_hysteresis():
    ex, det = FeatureExtractor(), PhysicsDetector(CFG)
    upload(ex)
    f = fly(ex, 0.0, L0, cur=1)  # origin = first AUTO position
    assert f.mission_known and f.mission_xtrack_m < 1.0
    for k in range(1, 8):
        f = fly(ex, k * 0.2, on_leg(k / 10, 5.0))
        assert not det.process(_nores(f)).triggered
    hits = []
    for k in range(8):
        f = fly(ex, 2.0 + k * 0.2, on_leg(0.5, 100.0))
        assert 99 < f.mission_xtrack_m < 101
        r = det.process(_nores(f))
        hits.append(AttackType.GPS_SPOOFING in r.attack_votes and r.triggered)
    assert hits[:4] == [False] * 4 and hits[4] and r.evidence
    assert "mission leg" in " ".join(r.evidence) and "waypoint 1" in " ".join(r.evidence)


def test_current_advances_to_next_leg():
    ex = FeatureExtractor()
    upload(ex)
    fly(ex, 0.0, L0, cur=1)
    f = fly(ex, 1.0, offset_latlon(*L0, 1000.0, 500.0), cur=2)
    assert f.mission_wp_seq == 2 and f.mission_xtrack_m < 1.0
    assert abs(f.mission_wp_dist_m - 500.0) < 2.0
    f = fly(ex, 1.2, offset_latlon(*L0, 1000.0, 500.0), cur=1)
    assert f.mission_xtrack_m > 400


def test_segment_not_line():
    ex = FeatureExtractor()
    upload(ex)
    fly(ex, 0.0, L0, cur=1)
    f = fly(ex, 0.5, offset_latlon(*L0, 1300.0, 0.0), cur=1)  # beyond the segment end
    assert 290 < f.mission_xtrack_m < 310


def test_inert_cases():
    ex = FeatureExtractor()
    assert fly(ex, 0.0, L0).mission_known is False  # upload unseen
    upload(ex)
    assert fly(ex, 1.0, L0, mode=4).mission_known is False  # not AUTO (GUIDED)
    assert fly(ex, 2.0, L0, armed=False).mission_known is False
    assert fly(ex, 3.0, L0).mission_known is True
    f = fly(ex, 7.0, L0, send_current=False)  # MISSION_CURRENT 4 s old
    assert f.mission_known is False and f.mission_xtrack_m is None
    ex.reset()
    assert not ex._mission.complete


def test_none_on_sim_stream():
    cfg = load_config()
    attack = build_attack("gps_spoofing", cfg.attacks, np.random.default_rng(1))
    ex = FeatureExtractor()
    n = 0
    for tick in SimulatedTelemetrySource(cfg, attack, seed=3).stream():
        for m in tick.messages:
            ex.update(m)
        fr = ex.extract(tick.t)
        assert fr.mission_known is False and fr.mission_xtrack_m is None and fr.mission_wp_dist_m is None
        n += 1
        if n > 600:
            break
    assert n > 100
