"""Leave-one-flight-out check of the derivation policy, WITHIN the calibration set.

    .venv/Scripts/python.exe scripts/sitl/calib_lofo.py

Environment: SITL (replayed tlog), attack NONE. For each calibration flight f: derive the
profile from the other four flights (same policy as ``calib_derive.py``), then count false
alarms on f with ML off (condition B). This estimates how stable the derived numbers are and
how they generalise across flights of the SAME route/host/session -- it is less optimistic
than the in-sample numbers but is NOT a substitute for the held-out set, and the flights are
not independent (one scripted route). Output: ``artifacts/sitl/calibration/lofo_rules.json``.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import calib_common as cc  # noqa: E402
import calib_derive as cd  # noqa: E402

from aegisflight.config import _deep_merge  # noqa: E402


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    flights = cd.load_flights()
    base = cc.cfg_for("default")
    folds = {}
    tot_fa = tot_n = 0
    for held in flights:
        train = {k: v for k, v in flights.items() if k != held}
        _D, po = cd.derive(train)
        cfg = copy.deepcopy(base)
        cfg.detector = _deep_merge(cfg.detector, po)
        rows = cc.replay_rows(flights[held]["tlog"], cfg, None)
        fa = sum(r["threat"] for r in rows)
        tot_fa += fa
        tot_n += len(rows)
        folds[held] = {"derived_from": sorted(train), "overrides": po, "decisions": len(rows),
                       "false_alarm_decisions": fa,
                       "evidence": sorted({e.split(":")[0][:60] for r in rows if r["threat"] for e in r["evidence"]})}
        print(held, "FA", fa, "/", len(rows), po["protocol"].get("nominal_msg_rate_hz"),
              po["protocol"].get("msg_rate_spike_factor"), po["physics"])
    doc = {"schema": "aegisflight.sitl_calibration_lofo_rules/1", "environment": "SITL (replayed tlog)",
           "attack_status": "NONE", "condition": "B (profile derived from 4 flights, ML off)",
           "folds": folds, "pooled": {"decisions": tot_n, "false_alarm_decisions": tot_fa},
           "caveat": "within the calibration set; same route/host; not independent of the held-out question"}
    (cc.OUT_DIR / "lofo_rules.json").write_text(json.dumps(doc, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
