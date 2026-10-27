"""Scratch probe: list every ALFA decision predicted GPS_SPOOFING (ML on, production config), via the
external-validation script's own per-tlog worker. Run once per code tree (PYTHONPATH selects it).

usage: alfa_gps_probe.py <out.json> [workers]
"""
from __future__ import annotations

import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]  # artifacts/validation/estimator_gate_v2/tools/ -> repo root
sys.path.insert(0, str(REPO / "scripts"))

import external_validation as ev  # noqa: E402


def one(path: str) -> list[dict]:
    f = ev._alfa_one((path, None, True))
    out = []
    for r in f.get("rows", []):
        if r["pred"] == "GPS_SPOOFING":
            out.append({"file": f["file"], "t_unix": round(r["t_unix"], 2), "gt": r["gt"],
                        "airborne": r["airborne"], "threat": r["threat"], "pred": r["pred"],
                        "det_physics": r.get("det_physics_consistency"),
                        "evidence": list(r.get("evidence") or [])[:3]})
    return out


def main() -> None:
    out_path, workers = Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 4
    import aegisflight
    tlogs = sorted(str(p) for p in (ev.ALFA_ROOT / "telemetry").rglob("*.tlog"))
    with ProcessPoolExecutor(max_workers=workers) as ex:
        rows = [r for chunk in ex.map(one, tlogs) for r in chunk]
    out_path.write_text(json.dumps({"code": aegisflight.__file__, "n_tlogs": len(tlogs), "rows": rows},
                                   indent=1), encoding="utf-8")
    print(f"{aegisflight.__file__}: {len(rows)} GPS_SPOOFING decisions over {len(tlogs)} tlogs -> {out_path}")


if __name__ == "__main__":
    main()
