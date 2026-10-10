"""Can an attack run's evidence be re-derived from its recorded bytes alone?  (validation side)

    .venv/Scripts/python.exe scripts/ardupilot/check_ap_attack_reproducible.py artifacts/ardupilot/<run>

Two independent checks, both OFFLINE (no simulator, no WSL), written to ``<run>/reproducibility.json``:

1. **Attack re-application.** The run's CLEAN tlog is fed through a fresh attack hook built from the
   run's recorded spec, with each frame's receive time taken from the tlog (microsecond stamps).
   The result is compared frame by frame with the OBSERVED tlog the live run actually produced.
   Not expected to be byte-identical everywhere: live hook timing used nanosecond monotonic stamps,
   the tlog keeps microseconds, so a frame within a microsecond of a window edge can fall either
   side. Every difference is listed with its distance to the nearest window edge.
2. **Verdict re-derivation.** The OBSERVED tlog is replayed through the unchanged pipeline with the
   run's configuration and ML setting, and its alert verdicts are compared with the live decisions.

Environment: SITL capture, REPLAY analysis. Claim class: link-level detection; nothing here says
anything about the vehicle's estimator or flight.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "scripts" / "sitl"))
REPO = HERE.parents[1]

from ap_attack import build_attack  # noqa: E402
from replay_ap_tlog import replay  # noqa: E402
from tlog_stats import iter_raw_frames  # noqa: E402

from aegisflight.config import load_config  # noqa: E402
from aegisflight.proxy.hooks import FrameContext  # noqa: E402
from aegisflight.sources.frame_tap import frame_header  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run")
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    run = Path(a.run)
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    att = manifest["attack"]
    clean, observed = Path(manifest["clean_tlog"]["path"]), Path(manifest["observed_tlog"]["path"])

    # 1. re-apply the attack to the clean frames ---------------------------------------------- #
    scratch = run / "_repro_scratch"
    scratch.mkdir(exist_ok=True)
    hook, handle = build_attack(att["spec"], scratch)
    clean_frames = [(ts, fb) for ts, _sy, _co, _sq, _mid, _sg, fb in iter_raw_frames(clean)]
    obs_frames = [fb for _ts, _sy, _co, _sq, _mid, _sg, fb in iter_raw_frames(observed)]
    out_frames: list[bytes] = []
    for ts, fb in clean_frames:
        sysid, compid, seq, msgid, signed = frame_header(fb)
        out_frames += hook(FrameContext("down", fb, int(round(ts * 1e6)) * 1000, sysid, compid, seq, msgid, signed))
    re_result = handle.finalize()
    win = att["window_decision_time"]
    n = min(len(out_frames), len(obs_frames))
    diffs = [i for i in range(n) if out_frames[i] != obs_frames[i]]
    # times of the differing frames, relative to the first frame, to compare with the window edges
    rel = [(clean_frames[i][0] - clean_frames[0][0]) for i in diffs]
    edge_dist = [round(min(abs(t - win["onset_t_s"]), abs(t - win["end_t_s"])), 3) for t in rel]
    attack_check = {
        "clean_frames": len(clean_frames), "observed_frames_live": len(obs_frames), "reapplied_frames": len(out_frames),
        "identical_frames": n - len(diffs), "differing_frames": len(diffs),
        "differing_frame_distance_to_window_edge_s": edge_dist,
        "frames_modified_live": att["result"]["frames_modified"],
        "frames_modified_reapplied": re_result["frames_modified"],
        "all_differences_within_0.25s_of_a_window_edge": all(d <= 0.25 for d in edge_dist),
        "byte_identical_everywhere": len(out_frames) == len(obs_frames) and not diffs}

    # 2. re-derive the verdicts from the OBSERVED tlog ---------------------------------------- #
    cfg_dir = None if summary["config_dir"].startswith("configs (Stage-1") else summary["config_dir"]
    cfg = load_config(cfg_dir)
    model = str(REPO / "models" / "isoforest.joblib") if summary["ml_enabled"] else None
    rows, _ = replay(observed, cfg, model, float(cfg.simulation.get("sample_rate_hz", 10.0)))
    live = [json.loads(x) for x in (run / "decisions.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    live = [d for d in live if d.get("phase") != "post_link"]
    m = min(len(live), len(rows))
    same = sum(live[i]["alert"] == rows[i]["alert"] for i in range(m))
    first_live = next((d for d in live if d["alert"] and d["t"] >= win["onset_t_s"]), None)
    first_re = next((d for d in rows if d["alert"] and d["t"] >= win["onset_t_s"]), None)
    verdict_check = {"live_decisions": len(live), "replay_decisions": len(rows), "compared": m,
                     "same_alert_verdict": same, "live_alerts": sum(d["alert"] for d in live),
                     "replay_alerts": sum(d["alert"] for d in rows),
                     "first_alert_after_onset_live": ({"t": first_live["t"], "type": first_live["type"]}
                                                      if first_live else None),
                     "first_alert_after_onset_replay": ({"t": first_re["t"], "type": first_re["type"]}
                                                        if first_re else None)}
    out = {"run": str(run), "environment": "SITL capture, REPLAY analysis", "claim_class": att["claim_class"],
           "attack_reapplication": attack_check, "verdict_rederivation": verdict_check}
    (run / "reproducibility.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    for p in scratch.glob("*"):
        p.unlink()
    scratch.rmdir()
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
