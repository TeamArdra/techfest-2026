"""Scratch: decisions around the GPS-init jump in the two ALFA flights, for whichever tree PYTHONPATH selects."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts"))  # repo-relative
import external_validation as ev  # noqa: E402

fin = json.load(open(sys.argv[1], encoding="utf-8"))
files = sorted({r["file"] for r in fin["rows"] if "discontinuity" in r["evidence"][0]})
ts = {f: [r["t_unix"] for r in fin["rows"] if r["file"] == f] for f in files}
for f in files:
    out = ev._alfa_one((str(ev.ALFA_ROOT / f), None, True))
    lo, hi = min(ts[f]) - 0.5, max(ts[f]) + 0.5
    for r in out["rows"]:
        if lo <= r["t_unix"] <= hi:
            print(f.split("/")[-3], round(r["t_unix"], 2), "threat" if r["threat"] else "-", r["pred"],
                  f"phys={r.get('det_physics_consistency') or 0:.2f}", f"pos_res={r.get('pos_residual_m', -1):.1f}",
                  "|", (r.get("evidence") or [""])[0][:90])
