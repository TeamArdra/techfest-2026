"""Regression: RESET returns the simulated vehicle to a clean baseline.

Covers the Firmware-Tamper -> Reset -> next-attack flow that previously left a
stale INVALID firmware verdict poisoning subsequent runs. RESET must:

  * reflash the simulated firmware to known-good (verify -> VALID),
  * clear extractor / detector / fusion runtime state,
  * not carry a firmware contribution into the next run, and
  * let an unrelated later attack be classified on its own evidence,

while historical audit records from earlier runs are preserved.
"""

from __future__ import annotations

import numpy as np

from aegisflight.attacks import build_attack
from aegisflight.attacks.base import NoAttack
from aegisflight.backend.engine import LiveEngine
from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import ThreatAssessment
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.stream import SimulatedTelemetrySource

CFG = load_config()
CFG.simulation["duration_s"] = 300.0


def _drive(pipeline: IDSPipeline, source: SimulatedTelemetrySource, n_decisions: int):
    """Run the source through the pipeline until n decisions are produced."""
    last = None
    made = 0
    for tick in source.stream():
        a = pipeline.process_tick(tick)
        if a is not None:
            last = a
            made += 1
            if made >= n_decisions:
                break
    return last


def _fw_score(a) -> float:
    return a.detector_scores.get("firmware_integrity", 0.0)


def test_pipeline_reset_restores_firmware_and_clears_state(tmp_path):
    fw_dir = tmp_path / "fw"
    pipeline = IDSPipeline(CFG, model_path=None, firmware_dir=fw_dir)

    # A. Fresh: firmware VALID, no firmware contribution.
    a = _drive(pipeline, SimulatedTelemetrySource(CFG, NoAttack(), seed=42), 10)
    assert a.integrity_status is IntegrityStatus.VALID
    assert _fw_score(a) == 0.0

    # B. Firmware tamper (shared directory, as the real attack does) -> INVALID.
    rng = np.random.default_rng(1)
    atk = build_attack("firmware_integrity", CFG.attacks, rng, firmware_dir=str(fw_dir))
    atk.start_s = 0.0
    atk.duration_s = 300.0
    a = _drive(pipeline, SimulatedTelemetrySource(CFG, atk, seed=42), 10)
    assert a.integrity_status is IntegrityStatus.INVALID
    assert _fw_score(a) == 1.0
    assert "firmware_integrity" in a.contributing_detectors

    # C. Reset -> firmware reflashed to VALID and all runtime state cleared.
    pipeline.reset()
    assert pipeline.verifier.verify().status is IntegrityStatus.VALID
    assert pipeline.anomaly._ticks == 0            # ML warm-up restarted
    assert pipeline.integrity._cached is None      # verifier cache cleared
    assert pipeline.integrity._n == 0
    assert pipeline._last is None
    assert len(pipeline.extractor._recv_times) == 0  # network window cleared

    # The next benign run must read a clean baseline (no stale INVALID / score).
    a = _drive(pipeline, SimulatedTelemetrySource(CFG, NoAttack(), seed=42), 10)
    assert a.integrity_status is IntegrityStatus.VALID
    assert _fw_score(a) == 0.0
    assert a.attack_type is AttackType.BENIGN


def test_reset_then_unrelated_attack_uses_own_evidence(tmp_path):
    """After a firmware tamper + reset, a GPS-spoofing attack is attributed to
    GPS spoofing with no inherited firmware evidence."""
    fw_dir = tmp_path / "fw"
    pipeline = IDSPipeline(CFG, model_path=None, firmware_dir=fw_dir)

    rng = np.random.default_rng(1)
    atk = build_attack("firmware_integrity", CFG.attacks, rng, firmware_dir=str(fw_dir))
    atk.start_s = 0.0
    atk.duration_s = 300.0
    a = _drive(pipeline, SimulatedTelemetrySource(CFG, atk, seed=42), 10)
    assert a.integrity_status is IntegrityStatus.INVALID

    pipeline.reset()

    rng2 = np.random.default_rng(2)
    gps = build_attack("gps_spoofing", CFG.attacks, rng2)
    gps.start_s = 0.0
    gps.duration_s = 300.0
    a = _drive(pipeline, SimulatedTelemetrySource(CFG, gps, seed=42), 40)

    assert a.attack_type is AttackType.GPS_SPOOFING
    assert a.integrity_status is IntegrityStatus.VALID
    assert _fw_score(a) == 0.0
    assert "firmware_integrity" not in a.contributing_detectors


def _assessment(t: float) -> ThreatAssessment:
    return ThreatAssessment(
        t=t, wall_time=1.0, threat=True, threat_score=0.7, severity=Severity.HIGH,
        attack_type=AttackType.FIRMWARE_INTEGRITY, confidence=0.8, evidence=["e"],
        detector_scores={"firmware_integrity": 1.0},
        contributing_detectors=["firmware_integrity"],
        integrity_status=IntegrityStatus.INVALID, latency_ms=0.4, telemetry={}, is_alert=True,
    )


def test_live_engine_reset_clean_and_preserves_history(tmp_path):
    """LiveEngine.reset() reflashes firmware, mints a new run id, and clears
    live state — while historical audit records from the prior run survive."""
    db = tmp_path / "live.sqlite"
    engine = LiveEngine(cfg=load_config(), db_path=str(db), model_path="__no_model__")

    run_a = engine._run_id
    # Simulate alerts logged during the first run.
    for i in range(3):
        engine.store.log_event(_assessment(float(i)), run_a)
    assert engine.store.verify_chain(run_a).ok

    # Tamper the firmware the engine's pipeline watches, then reset.
    assert engine.pipeline.verifier.tamper("ekf3_params.bin") is True
    assert engine.pipeline.verifier.verify().status is IntegrityStatus.INVALID

    engine.reset()

    # Clean baseline after reset.
    run_b = engine._run_id
    assert run_b != run_a
    assert engine.pipeline.verifier.verify().status is IntegrityStatus.VALID
    assert engine._active_attack_name is None
    assert engine.recent_alerts() == []  # the new run has no alerts (read back from the store)
    assert engine.pipeline.anomaly._ticks == 0
    assert engine.pipeline._last is None

    # Historical audit from the earlier run is preserved and still verifiable.
    assert engine.store.verify_chain(run_a).length == 3
    assert engine.store.verify_chain(run_a).ok
    run_ids = {r["run_id"] for r in engine.store.list_runs()}
    assert run_a in run_ids and run_b in run_ids


def test_new_run_id_is_unique_across_rapid_resets(tmp_path):
    """Two resets within the same wall-clock second must not share a run id
    (a shared id would merge two independent hash chains)."""
    db = tmp_path / "live.sqlite"
    engine = LiveEngine(cfg=load_config(), db_path=str(db), model_path="__no_model__")
    ids = {engine._run_id}
    for _ in range(3):
        engine.reset()
        ids.add(engine._run_id)
    assert len(ids) == 4  # all distinct


def test_reset_endpoint_does_not_error_and_reflashes(tmp_path):
    """The dashboard Reset button hits POST /api/simulation/reset while the live
    loop is running. The endpoint must run its restart on the event loop (a sync
    endpoint would ``create_task`` in a threadpool worker with no loop and 500),
    reflash the firmware, and leave a clean baseline.
    """
    from fastapi.testclient import TestClient

    import aegisflight.backend.app as appmod

    appmod.engine = LiveEngine(db_path=str(tmp_path / "live.sqlite"), model_path="__no_model__")
    try:
        with TestClient(appmod.app) as client:  # lifespan starts the live loop
            eng = appmod.engine
            # Tamper the firmware the running pipeline watches.
            assert eng.pipeline.verifier.tamper("ekf3_params.bin") is True
            assert eng.pipeline.verifier.verify().status is IntegrityStatus.INVALID
            run_before = eng._run_id

            r = client.post("/api/simulation/reset")
            assert r.status_code == 200, r.text
            assert r.json()["ok"] is True

            # Firmware reflashed to known-good; a fresh run started.
            assert eng.pipeline.verifier.verify().status is IntegrityStatus.VALID
            assert eng._run_id != run_before
            assert client.get("/api/status").json()["integrity_status"] == "VALID"
    finally:
        appmod.engine = None
