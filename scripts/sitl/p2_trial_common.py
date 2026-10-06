"""Shared boilerplate for the P2 live-attack trial drivers that were added alongside the
drop/delay/replay attacks (``run_p2_drop_trial.py``, ``run_p2_delay_trial.py``,
``run_p2_replay_trial.py``). Deliberately NOT used by the two earlier drivers
(``run_p2_trial.py``, ``run_p2_injection_trial.py``) -- they are not refactored here, per
the task that added this module; this file exists only to avoid copy-pasting the same
~40 lines of WSL discovery / overwrite-guard / model-resolution / manifest-serialisation
logic a third, fourth and fifth time.

Nothing here touches sockets, PX4, or the attack hooks themselves -- it is pure argparse/
subprocess/json plumbing reused by each driver's own ``main()``.
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

MODEL_STAGE1 = "models/isoforest.joblib"
MODEL_PX4 = "models/isoforest_px4.joblib"
#: Real PX4 SITL vehicle identity (instance 0 + 1 = sysid 3, compid 1) --
#: docs/PX4_SITL_INTEGRATION.md. Simulator-only test fixtures use the same numbers.
PX4_VEHICLE_SYSID = 3
PX4_VEHICLE_COMPID = 1


def wsl_ip(distro: str = "Ubuntu-24.04") -> str:
    out = subprocess.run(["wsl", "-d", distro, "--", "hostname", "-I"],
                         capture_output=True, text=True, timeout=30)
    return out.stdout.split()[0]


def px4_describe(distro: str = "Ubuntu-24.04", px4_dir: str = "/home/astryx/PX4-Autopilot") -> str:
    out = subprocess.run(["wsl", "-d", distro, "--cd", px4_dir, "--", "git", "describe", "--tags", "--always"],
                         capture_output=True, text=True, timeout=30)
    return out.stdout.strip()


def build_argparser(description: str, *, default_seconds: float) -> argparse.ArgumentParser:
    """The flag set every P2 trial driver shares. ``--seed``/``--out`` stay required;
    everything else has the same defaults as ``run_p2_trial.py``/``run_p2_injection_trial.py``."""
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--px4-host", default=None, help="default: discovered WSL IP")
    ap.add_argument("--px4-port", type=int, default=18572)
    ap.add_argument("--relay-listen-port", type=int, default=18672)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--trial-index", type=int, default=0)
    ap.add_argument("--seconds", type=float, default=default_seconds)
    ap.add_argument("--out", required=True)
    ap.add_argument("--profile", default="configs/px4_sitl", help="load_config dir; use '' for Stage-1 default")
    ap.add_argument("--model", choices=("px4", "stage1", "none"), default=None,
                    help="default: 'px4' if --profile is set, else 'stage1' (B2 cross-pairing is refused)")
    return ap


def refuse_if_exists(out: Path, suffixes: tuple[str, ...]) -> bool:
    """``True`` if none of ``out.with_suffix(suffix)`` already exist; otherwise prints an
    error (naming the first colliding path) and returns ``False``. Mirrors the
    refuse-to-overwrite guard in both earlier drivers -- a prior crashed/aborted attempt
    at this exact ``--out`` must be removed explicitly, never silently appended to."""
    for suffix in suffixes:
        p = out.with_suffix(suffix)
        if p.exists():
            print(f"ERROR: {p} already exists. Remove it explicitly before rerunning -- refusing "
                  f"to append/overwrite evidence files silently.", file=sys.stderr)
            return False
    return True


def resolve_model(profile: str, model_arg: str | None) -> tuple[str | None, str]:
    """Same B2-cross-pairing guard as both earlier drivers: returns ``(model_path_or_None,
    model_choice)``, or raises :class:`SystemExit` with the same refusal message if
    ``--model px4`` is requested without ``--profile``."""
    model_choice = model_arg or ("px4" if profile else "stage1")
    if model_choice == "px4" and not profile:
        print("ERROR: --model px4 without --profile is the untested B2 cross-pairing", file=sys.stderr)
        raise SystemExit(2)
    model_path = {"px4": MODEL_PX4, "stage1": MODEL_STAGE1, "none": None}[model_choice]
    model = model_path if model_path and Path(model_path).exists() else None
    return model, model_choice


def provenance_block(distro: str, px4_dir: str, extra: dict[str, Any]) -> dict[str, Any]:
    """``provenance`` dict for :class:`aegisflight.proxy.groundtruth.Manifest`, built from
    ``scripts/sitl/provenance.py``'s ``collect()`` (the required
    ``aegisflight_git_commit``/``python_version`` keys) plus the PX4 side (``px4_git_describe``,
    discovered via WSL, never hard-coded) and ``pymavlink_version``. ``extra`` is passed
    through to ``collect()`` (e.g. ``python_version=...``)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from provenance import collect  # noqa: E402 -- sibling script module, path set above

    prov_raw = collect(**extra)
    return {
        "provenance": {
            "px4_git_describe": px4_describe(distro, px4_dir),
            "aegisflight_git_commit": prov_raw["aegisflight_commit"],
            "python_version": prov_raw["python"],
            "pymavlink_version": md.version("pymavlink"),
        },
        "full_provenance": prov_raw,
    }


def write_manifest(out: Path, manifest: Any, full_provenance: dict[str, Any], ids_summary: dict[str, Any]) -> None:
    """Serialise a :class:`aegisflight.proxy.groundtruth.Manifest` the same way both
    earlier drivers do: ``manifest.__dict__`` plus the ``init=False`` fields and an
    ``ids_summary`` block, written to ``out.with_suffix(".manifest.json")``."""
    out.with_suffix(".manifest.json").write_text(json.dumps(
        {**manifest.__dict__, "schema_id": manifest.schema_id, "schema_version": manifest.schema_version,
         "detector_decision": manifest.detector_decision, "time_to_detection_s": manifest.time_to_detection_s,
         "full_provenance": full_provenance, "ids_summary": ids_summary},
        indent=2, default=str))
