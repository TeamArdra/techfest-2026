"""Stage-1 SIM streams never reach the never-received / coverage paths (added 2026-10-20, aegis-validation).

docs/DETECTION.md ("Stage-1 effect") states that the simulated streams carry HEARTBEAT and
GLOBAL_POSITION_INT from the first decision, so the P1/P2 presence policy (2026-10-15) cannot move
the Stage-1 benchmark. That was a one-off lead check; this test pins it.

Why short sessions suffice: the seen-flags are monotone (they only turn False again on
``reset()``, which ``benchmark.runner.run_session`` never calls mid-session), and the never-received
and coverage evidence is only emitted while a flag is False. So "every flag True from the first
decision, for every Stage-1 scenario" implies "no Stage-1 benchmark decision takes these paths".
Each attack is started at t=0 (the benchmark starts them at 30-45 s), which is a strictly harder
start-of-stream condition than the benchmark's. Only the default attack modes that the Stage-1
benchmark runs (``benchmark.harness.SCENARIOS`` with ``configs/attacks.yaml``) are covered; the
extended benchmark's packet-dropping modes (blackout, packet_loss) are out of scope here.

Ground truth stays benchmark-side: the test reads ``FeatureFrame`` flags and assessment evidence only.
"""

from __future__ import annotations

import numpy as np
import pytest

from aegisflight.attacks import build_attack
from aegisflight.benchmark.harness import SCENARIOS
from aegisflight.config import load_config
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.stream import SimulatedTelemetrySource

SESSION_S = 8.0  # 40 decisions at 5 Hz
SEED = 1  # first Stage-1 benchmark seed
FORBIDDEN = ("coverage:", "never received", "never acquired")


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_stage1_sim_scenario_never_takes_never_received_paths(scenario, tmp_path):
    cfg = load_config()
    cfg.simulation["duration_s"] = SESSION_S
    if scenario in cfg.attacks:
        cfg.attacks[scenario]["start_s"] = 0.0
        if "duration_s" in cfg.attacks[scenario]:
            cfg.attacks[scenario]["duration_s"] = SESSION_S + 1.0
    fw_dir = tmp_path / "fw"
    pipe = IDSPipeline(cfg, model_path=None, firmware_dir=fw_dir)
    kwargs = {"firmware_dir": str(fw_dir)} if scenario == "firmware_integrity" else {}
    attack = build_attack(scenario, cfg.attacks, np.random.default_rng(SEED + 99), **kwargs)
    if scenario != "benign":
        assert attack.start_s == 0.0  # the attack really is active from the first tick

    decisions = 0
    for tick in SimulatedTelemetrySource(cfg, attack, seed=SEED).stream():
        a = pipe.process_tick(tick)
        if a is None:
            continue
        decisions += 1
        f = pipe.last_frame
        assert f is not None
        assert f.heartbeat_seen is True and f.gps_seen is True and f.gps_raw_seen is True, (scenario, a.t)
        hits = [e for e in a.evidence if any(s in e for s in FORBIDDEN)]
        assert hits == [], (scenario, a.t, hits)
    assert decisions >= int(SESSION_S * 5) - 1, (scenario, decisions)
