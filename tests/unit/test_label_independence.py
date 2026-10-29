"""Detectors decide from telemetry, not from test labels (template section 5: "not from test labels, injected-attack
flags or the attack generator's state").

Two complementary checks, because an import grep alone proves little:

* behavioural: the same attacked session is processed twice, once as produced (``TelemetryTick`` carries the
  hidden ground truth) and once with every ground-truth field scrubbed. The decisions must be identical;
* structural: the detector, feature and fusion modules import neither the simulator, the attacks, the benchmark nor the
  ground-truth types. (Code can still reach labels without importing them; the behavioural test is what would catch that.)

Scope: SIM, five attack classes, ML off, one seed each. It does not cover the firmware-integrity class (the integrity
detector reads the firmware directory, which the attack hook alters: that is a telemetry-independent signal by design).
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import numpy as np
import pytest

from aegisflight.attacks import build_attack
from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, IntegrityStatus
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.stream import SimulatedTelemetrySource

SRC = Path(__file__).resolve().parents[2] / "src" / "aegisflight"
FORBIDDEN = ("aegisflight.simulator", "aegisflight.attacks", "aegisflight.benchmark", "aegisflight.metrics")
FORBIDDEN_NAMES = {"FlightState", "TelemetryTick"}  # ground truth rides on TelemetryTick; detectors take FeatureFrame
VOLATILE = {"wall_time", "latency_ms"}


def _scrub(tick):
    return dataclasses.replace(tick, truth_state=None, label=AttackType.BENIGN, labels=frozenset(),
                               integrity_truth=IntegrityStatus.VALID)


def _decisions(cfg, attack, scrub: bool, seed: int):
    src = SimulatedTelemetrySource(cfg, attack=attack, seed=seed)
    pipe = IDSPipeline(cfg, model_path=None)
    out = []
    for tick in src.stream():
        a = pipe.process_tick(_scrub(tick) if scrub else tick)
        if a is not None:
            out.append({k: v for k, v in a.to_dict().items() if k not in VOLATILE})
    return out


@pytest.mark.parametrize("name", ["gps_spoofing", "mavlink_anomaly", "command_injection",
                                  "telemetry_manipulation", "dos"])
def test_decisions_do_not_depend_on_ground_truth_fields(name):
    cfg = load_config()
    seed = 11
    with_truth = _decisions(cfg, build_attack(name, cfg.attacks, np.random.default_rng(seed)), False, seed)
    scrubbed = _decisions(cfg, build_attack(name, cfg.attacks, np.random.default_rng(seed)), True, seed)
    assert len(with_truth) > 50
    assert with_truth == scrubbed
    # the check is only meaningful if the attack actually changed some decision
    assert any(d["threat"] for d in with_truth), f"{name}: no threat decision, test would be vacuous"


@pytest.mark.parametrize("sub", ["detectors", "features", "fusion"])
def test_detection_modules_do_not_import_simulator_attacks_or_ground_truth(sub):
    offenders = []
    for path in sorted((SRC / sub).rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:  # relative import: resolve against the package path
                    parts = list(path.relative_to(SRC.parent).with_suffix("").parts[:-1])
                    parts = parts[: len(parts) - (node.level - 1)]
                    base = ".".join([*parts, *(base.split(".") if base else [])])
                if any(base == f or base.startswith(f + ".") for f in FORBIDDEN):
                    offenders.append(f"{path.name}: from {base}")
                offenders += [f"{path.name}: imports {a.name}" for a in node.names if a.name in FORBIDDEN_NAMES]
            elif isinstance(node, ast.Import):
                offenders += [f"{path.name}: import {a.name}" for a in node.names
                              if any(a.name == f or a.name.startswith(f + ".") for f in FORBIDDEN)]
    assert not offenders, offenders
