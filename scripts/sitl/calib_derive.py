"""Derive the PX4-SITL per-vehicle detector profile from the CALIBRATION flights only.

    .venv/Scripts/python.exe scripts/sitl/calib_derive.py

Environment: SITL (replayed tlog). Attack: NONE. This is false-alarm calibration,
NOT attack detection. Reads ONLY ``data/sitl/raw/benign_001..005.tlog`` (the
calibration split); the held-out flights 006..010 are never opened here.

Writes (all generated, never hand-edited):
  * ``artifacts/sitl/calibration/derivation.json`` - inputs, formulas, per-flight
    values and the derived numbers
  * ``configs/px4_sitl/detector.yaml``            - overrides only, each commented
    with the derivation entry that justifies it

Derivation policy (one explicit margin, no per-threshold hand nudging)
----------------------------------------------------------------------
``M = 1.25``. Steady-state decisions = those after the cold-start decisions where
no heartbeat / no GPS message has been seen yet (extractor sentinel 999 s).

* A Stage-1 threshold ``theta0`` that guards a benign-bounded feature is changed
  **only if** ``theta0 < M * x*`` where ``x*`` is the largest steady-state value of
  that feature over all calibration flights; the new value is ``M * x*`` rounded UP
  to a coarse grid. A threshold already >= ``M * x*`` is left exactly as Stage-1.
  Thresholds are never lowered (no tightening without attack data).
* Message rate: SITL time is not wall time (real-time factor RTF < 1, measured per
  flight from ``boot_clock_vs_recv_drift_ppm``: RTF = 1 + ppm/1e6). Rates are
  normalised to RTF = 1 (``r_norm = rate / RTF_flight``) so the allowance covers a
  host that keeps up with real time (Gazebo lockstep caps RTF at 1 unless the
  sim speed factor is changed - an assumption stated in docs/CALIBRATION_PX4.md).
    nominal_msg_rate_hz  = median(r_norm)
    spike threshold      = M * max(r_norm)  -> msg_rate_spike_factor = ceil_0.05(spike / nominal)
    max_msg_rate_hz      = nominal * (400 / 28)   (Stage-1 hard/nominal ratio kept)
* expected_sysids = vehicle sysids observed (excluding the default GCS ids).
* startup_grace_s = ceil_0.2( M * max over flights of the first-observed
  heartbeat/GPS time ) - suppresses ONLY the never-seen-yet liveness rules.
"""

from __future__ import annotations

import json
import math
import platform
import subprocess
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import calib_common as cc  # noqa: E402

from aegisflight.config import DEFAULT_DETECTOR  # noqa: E402

M = 1.25
SENTINEL = 999.0
STAGE1_HARD_OVER_NOMINAL = 400.0 / 28.0  # Stage-1 max_msg_rate_hz / nominal_msg_rate_hz


def ceil_to(x: float, grid: float) -> float:
    return round(math.ceil(x / grid - 1e-9) * grid, 10)


def git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              cwd=cc.REPO, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def load_flights() -> dict[str, dict]:
    """Per-flight features (config-independent: ML off, pure feature extraction) for the CALIBRATION flights."""
    cfg = cc.cfg_for("default")
    flights: dict[str, dict] = {}
    for tl in cc.CALIB_FLIGHTS:
        assert "benign_00" in tl and int(Path(tl).stem.split("_")[1]) <= 5, tl  # calibration only
        name = Path(tl).stem
        stats = json.loads(cc.resolve(f"artifacts/sitl/{name}_stream_stats.json").read_text())
        rtf = 1.0 + stats["boot_clock_vs_recv_drift_ppm"] / 1e6
        rows = cc.replay_rows(tl, cfg, None)
        steady = [r for r in rows if r["heartbeat_age_s"] < SENTINEL and r["gps_age_s"] < SENTINEL]
        first_hb = next((r["t"] for r in rows if r["heartbeat_age_s"] < SENTINEL), None)
        first_gps = next((r["t"] for r in rows if r["gps_age_s"] < SENTINEL), None)
        flights[name] = {"tlog": tl, "sha256": cc.sha256(cc.resolve(tl)), "rtf": rtf, "rows": rows,
                         "steady": steady, "first_hb_t": first_hb, "first_gps_t": first_gps}
    return flights


def derive(flights: dict[str, dict]) -> tuple[dict, dict]:
    """Apply the derivation policy to ``flights``; returns ``(derivations, profile_overrides)``."""
    prot0, phys0 = DEFAULT_DETECTOR["protocol"], DEFAULT_DETECTOR["physics"]

    def feat(name: str, fn=lambda v: v):
        return {n: np.array([fn(r[name]) for r in f["steady"]]) for n, f in flights.items()}

    D: dict = {}
    po: dict = {"protocol": {}, "physics": {}}

    # ---- expected vehicle sysid(s) ------------------------------------------------
    gcs = set(prot0["expected_gcs_sysids"])
    seen = sorted({int(s.split("/")[0]) for f in flights.values() for r in f["rows"]
                   for s in r["sources"]} - gcs)
    D["expected_sysids"] = {"rule": "vehicle sysids observed in the stream, excluding default GCS ids",
                            "stage1": prot0["expected_sysids"], "observed": seen, "profile": seen}
    po["protocol"]["expected_sysids"] = seen

    # ---- message rate (RTF-normalised) ---------------------------------------------
    rn = {n: feat("msg_rate_hz")[n] / f["rtf"] for n, f in flights.items()}
    pooled = np.concatenate(list(rn.values()))
    raw_pooled = np.concatenate(list(feat("msg_rate_hz").values()))
    nominal = ceil_to(float(np.median(pooled)), 1.0)
    x_star = max(float(v.max()) for v in rn.values())
    spike = M * x_star
    factor = ceil_to(spike / nominal, 0.05)
    hard = ceil_to(nominal * STAGE1_HARD_OVER_NOMINAL, 50.0)
    D["msg_rate"] = {
        "rule": "nominal=median(rate/RTF); spike=M*max(rate/RTF); factor=ceil_0.05(spike/nominal); "
                "hard=ceil_50(nominal*400/28)",
        "stage1": {"nominal": prot0["nominal_msg_rate_hz"], "spike_factor": prot0["msg_rate_spike_factor"],
                   "max_msg_rate_hz": prot0["max_msg_rate_hz"]},
        "observed_raw": {"median": float(np.median(raw_pooled)), "p99": float(np.percentile(raw_pooled, 99)),
                         "max": float(raw_pooled.max())},
        "observed_rtf_normalised": {"median": float(np.median(pooled)), "p99": float(np.percentile(pooled, 99)),
                                    "max_over_flights": x_star,
                                    "per_flight_max": {n: float(v.max()) for n, v in rn.items()}},
        "stage1_hard_limit_vs_rtf1_benign_max": {"hard_limit": prot0["max_msg_rate_hz"],
                                                 "benign_max_at_rtf1": x_star,
                                                 "stage1_hard_limit_would_fire": bool(x_star >= prot0["max_msg_rate_hz"])},
        "profile": {"nominal": nominal, "spike_factor": factor, "spike_threshold_msgs": nominal * factor,
                    "max_msg_rate_hz": hard},
    }
    po["protocol"].update({"nominal_msg_rate_hz": nominal, "msg_rate_spike_factor": factor,
                           "max_msg_rate_hz": hard})

    # ---- start-of-stream grace ------------------------------------------------------
    firsts = [t for f in flights.values() for t in (f["first_hb_t"], f["first_gps_t"]) if t is not None]
    grace = ceil_to(M * max(firsts), 0.2)
    D["startup_grace_s"] = {
        "rule": "ceil_0.2(M * max over flights of first-observed heartbeat/GPS decision time)",
        "stage1": 0.0, "max_first_seen_t": max(firsts), "profile": grace,
        "stage1_cold_start_decisions_per_flight": {n: len(f["rows"]) - len(f["steady"]) for n, f in flights.items()}}
    po["protocol"]["startup_grace_s"] = grace

    # ---- physics thresholds ----------------------------------------------------------
    phys_map = {
        # config key: (feature, abs?, stage-1 threshold)
        "gps_pos_residual_m": ("pos_residual_m", False, phys0["gps_pos_residual_m"]),
        "gps_pos_residual_hard_m": ("pos_residual_m", False, phys0["gps_pos_residual_hard_m"]),
        "gps_speed_consistency_ms": ("gps_vfr_speed_diff_ms", False, phys0["gps_speed_consistency_ms"]),
        "alt_consistency_m": ("gps_baro_alt_diff_m", False, phys0["alt_consistency_m"]),
        "alt_jump_ms": ("alt_rate_ms", True, phys0["alt_jump_ms"]),
        "max_accel_ms2": ("accel_ms2", False, phys0["max_accel_ms2"]),
        "battery_rise_v": ("battery_v_rise", False, phys0["battery_rise_v"]),
        "battery_drop_rate_v_s": ("battery_v_rate", "neg", phys0["battery_drop_rate_v_s"]),
        "yaw_course_deg": ("yaw_course_diff_deg", False, 25.0),  # hard-coded 25.0 in Stage-1 PhysicsDetector
    }
    grids = {"battery_rise_v": 0.05, "battery_drop_rate_v_s": 0.05, "yaw_course_deg": 5.0}
    for key, (fname, mode, th0) in phys_map.items():
        fn = (lambda v: abs(v)) if mode is True else ((lambda v: max(0.0, -v)) if mode == "neg" else (lambda v: v))
        per = {n: float(v.max()) for n, v in feat(fname, fn).items()}
        xs = max(per.values())
        need = M * xs
        changed = th0 < need
        new = ceil_to(need, grids.get(key, 0.5)) if changed else th0
        D[f"physics.{key}"] = {"feature": fname, "stage1": th0, "x_star_max_steady": xs,
                               "per_flight_max": per, "M_x_star": need, "changed": bool(changed),
                               "profile": new}
        if changed:
            po["physics"][key] = new
    D["note"] = (
        "No attack data was used. Unchanged physics thresholds sit >= M * benign max; whether they are "
        "too LOOSE for attack sensitivity on this stack is not measured (needs P2 attack data).")

    return D, po


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    flights = load_flights()
    D, po = derive(flights)
    out: dict = {
        "schema": "aegisflight.sitl_calibration_derivation/1",
        "environment": "SITL (replayed tlog)", "attack_status": "NONE",
        "claim_class": "none (false-alarm calibration; NOT attack detection)",
        "split": "calibration = benign_001..005; held-out 006..010 NOT read by this script",
        "margin_M": M,
        "flights": {n: {"tlog": f["tlog"], "tlog_sha256": f["sha256"], "rtf": f["rtf"],
                        "decisions": len(f["rows"]), "steady_decisions": len(f["steady"]),
                        "cold_start_decisions": len(f["rows"]) - len(f["steady"]),
                        "first_heartbeat_decision_t": f["first_hb_t"],
                        "first_gps_decision_t": f["first_gps_t"]}
                    for n, f in flights.items()},
        "provenance": {"git_commit": git_commit(), "python": platform.python_version(),
                       "numpy": np.__version__, "script": "scripts/sitl/calib_derive.py"},
        "derivations": D, "profile_overrides": po,
    }
    # ---- artifacts --------------------------------------------------------------------
    cc.OUT_DIR.mkdir(parents=True, exist_ok=True)
    (cc.OUT_DIR / "derivation.json").write_text(json.dumps(out, indent=2, default=str))
    write_yaml(out)
    print(json.dumps(out["profile_overrides"], indent=2))
    return 0


def write_yaml(out: dict) -> None:
    D, po = out["derivations"], out["profile_overrides"]
    p, h = po["protocol"], po["physics"]
    mr = D["msg_rate"]
    lines = [
        "# AegisFlight - PX4 SITL calibration PROFILE (overrides only; GENERATED - do not hand-edit)",
        "#",
        "# Regenerate: .venv/Scripts/python.exe scripts/sitl/calib_derive.py",
        "# Load:       aegisflight.config.load_config('configs/px4_sitl')   (deep-merged over built-in defaults;",
        "#             simulation.yaml / attacks.yaml are intentionally absent -> built-in defaults, unused on replay)",
        "# Evidence:   artifacts/sitl/calibration/derivation.json (numbers below) from the CALIBRATION flights",
        "#             benign_001..005 only. Environment SITL, attack NONE. This is false-alarm calibration, NOT",
        "#             attack detection, and says nothing about real vehicles. configs/detector.yaml (Stage-1) is",
        "#             untouched and remains the reference condition.",
        f"# Margin policy: M = {out['margin_M']} x the largest steady-state benign value; thresholds are only",
        "#             raised (never lowered); a Stage-1 value already >= M x benign max is not overridden.",
        "",
        "protocol:",
        f"  # observed vehicle sysid(s) {D['expected_sysids']['observed']} (Stage-1 expects {D['expected_sysids']['stage1']}):"
        " clears 'rogue telemetry source' AND the command-source rule (PX4's own COMMAND_LONG is sys3/comp1)",
        f"  expected_sysids: {p['expected_sysids']}",
        f"  # median of rate/RTF over calibration flights (Stage-1: {mr['stage1']['nominal']}; derivation.json -> msg_rate)",
        f"  nominal_msg_rate_hz: {p['nominal_msg_rate_hz']}",
        f"  # spike = nominal*factor = {mr['profile']['spike_threshold_msgs']:.0f} msg/s = ceil(M x max benign rate normalised to RTF=1"
        f" ({mr['observed_rtf_normalised']['max_over_flights']:.0f}))",
        f"  msg_rate_spike_factor: {p['msg_rate_spike_factor']}",
        f"  # Stage-1 hard/nominal ratio (400/28) kept; Stage-1's 400 is below the RTF=1 benign max"
        f" ({mr['observed_rtf_normalised']['max_over_flights']:.0f})",
        f"  max_msg_rate_hz: {p['max_msg_rate_hz']}",
        "  # NEW additive key (default 0 = Stage-1 behaviour): ignore only the never-seen-yet heartbeat/GPS",
        f"  # sentinel during the first {p['startup_grace_s']} s (derivation.json -> startup_grace_s)",
        f"  startup_grace_s: {p['startup_grace_s']}",
    ]
    if h:
        lines += ["", "physics:"]
        for key, val in h.items():
            d = D[f"physics.{key}"]
            extra = "  # NEW additive key (default 25 = Stage-1 value)" if key == "yaw_course_deg" else ""
            lines.append(f"  # {d['feature']}: Stage-1 {d['stage1']}, calibration max {d['x_star_max_steady']:.3f}, "
                         f"M x max = {d['M_x_star']:.3f} (derivation.json -> physics.{key})")
            if extra:
                lines.append(extra)
            lines.append(f"  {key}: {val}")
    d = cc.resolve(cc.PROFILE_DIR)
    d.mkdir(parents=True, exist_ok=True)
    (d / "detector.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
