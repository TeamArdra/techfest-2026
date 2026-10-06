"""Run ONE trial of the approved P2 first live attack (downlink GLOBAL_POSITION_INT
gradual-drift, docs/ATTACK_PROXY.md Sec3) through the MavlinkRelay against a local PX4 SITL.

    .venv/Scripts/python.exe scripts/sitl/run_p2_trial.py --px4-port 18572 --seed 1001 \
        --out artifacts/sitl/p2_trial_001

Topology for this trial:
    PX4 SITL (WSL, GCS link) <-> MavlinkRelay (this process, upstream+downstream legs)
        <-down_hook=PositionDriftAttack-- downstream clients: this script's own IDS tap
                                           (LiveMavlinkSource over the relay's loopback port)

Environment: SITL. Attack: the proxy-level downlink modification ONLY -- PX4 never receives
a modified frame (the relay's up_hook stays passthrough; only down_hook runs the attack).
Claim class: link-level detection (SITL) at most. This does NOT show vehicle trajectory
deviation, GPS spoofing of PX4's estimator, or anything about MAVLink signing.

Writes, per trial: manifest.json + frames.jsonl (proxy/groundtruth.py schema, ground truth
authored by the attack hook itself, never from detector output) and ids_decisions.jsonl (the
Stage-1 IDSPipeline's decisions on the IDS tap) -- joined post-hoc, not written here.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from provenance import collect

from aegisflight.config import load_config
from aegisflight.pipeline import IDSPipeline
from aegisflight.proxy import (
    FrameLogWriter,
    Manifest,
    PositionDriftAttack,
    compute_actual_effect,
    draw_params,
)
from aegisflight.proxy.transport import make_udp_relay
from aegisflight.sources.mavlink_live import LiveMavlinkSource, UdpMavlinkTransport

# Stage-1 default model: trained on simulator-benign data, used with --profile '' (Stage-1 default).
MODEL_STAGE1 = "models/isoforest.joblib"
# PX4-trained model (artifacts/sitl/calibration/isoforest_px4_training.json): trained on the
# calibration-set benign SITL flights (001-005), matches configs/px4_sitl -- see docs/CALIBRATION_PX4.md
# condition C. Using the Stage-1 model with the PX4 profile is condition B2 (diagnostic only): it
# false-alarms ~96% on benign SITL (ML saturation) and must NOT be used for an attack trial.
MODEL_PX4 = "models/isoforest_px4.joblib"
PX4_HOME_LAT = 47.397742  # PX4 SITL default home (matches start_px4_sitl.sh); used only
# to convert the attack's lat/lon deltas to metres for the post-hoc actual_effect check.


def wsl_ip(distro: str = "Ubuntu-24.04") -> str:
    import subprocess

    out = subprocess.run(["wsl", "-d", distro, "--", "hostname", "-I"], capture_output=True, text=True, timeout=30)
    return out.stdout.split()[0]


def px4_describe(distro: str = "Ubuntu-24.04", px4_dir: str = "/home/astryx/PX4-Autopilot") -> str:
    import subprocess

    out = subprocess.run(["wsl", "-d", distro, "--cd", px4_dir, "--", "git", "describe", "--tags", "--always"],
                         capture_output=True, text=True, timeout=30)
    return out.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--px4-host", default=None, help="default: discovered WSL IP")
    ap.add_argument("--px4-port", type=int, default=18572)
    ap.add_argument("--relay-listen-port", type=int, default=18672)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--trial-index", type=int, default=0)
    ap.add_argument("--seconds", type=float, default=90.0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--profile", default="configs/px4_sitl", help="load_config dir; use '' for Stage-1 default")
    ap.add_argument("--model", choices=("px4", "stage1", "none"), default=None,
                    help="default: 'px4' if --profile is set, else 'stage1' (B2 cross-pairing is refused)")
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # FrameLogWriter is append-only by design (groundtruth.py); refuse to silently merge two
    # trials' evidence into one file -- a prior crashed/aborted attempt at this exact --out
    # must be removed explicitly, never appended to.
    for suffix in (".frames.jsonl", ".manifest.json", ".ids_decisions.jsonl"):
        p = out.with_suffix(suffix)
        if p.exists():
            print(f"ERROR: {p} already exists (stale output from a previous attempt at this "
                  f"--out). Remove it explicitly before rerunning -- refusing to append/overwrite "
                  f"evidence files silently.", file=sys.stderr)
            return 2
    px4_host = a.px4_host or wsl_ip()
    params = draw_params(a.seed, a.trial_index)

    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    attack = PositionDriftAttack(params, frame_log=frame_log)
    relay = make_udp_relay(px4_host, a.px4_port, a.relay_listen_port, down_hook=attack)
    relay.start()
    if not relay.wait_upstream_alive(timeout=15.0):
        relay.close()
        frame_log.close()
        print("ERROR: PX4 never answered the relay's heartbeat within 15s", file=sys.stderr)
        return 2

    # The IDS taps the relay's downstream (post-attack) leg as an ordinary loopback client.
    ids_transport = UdpMavlinkTransport(connect=("127.0.0.1", relay.downstream.local_address[1]), gcs_heartbeat=True)
    ids_transport.start()
    cfg = load_config(a.profile or None)
    model_choice = a.model or ("px4" if a.profile else "stage1")
    if model_choice == "px4" and not a.profile:
        print("ERROR: --model px4 without --profile configs/px4_sitl is the untested B2 cross-pairing", file=sys.stderr)
        return 2
    if model_choice == "stage1" and a.profile:
        print("WARNING: --model stage1 with a PX4 profile is condition B2 (diagnostic only, ~96% FA on "
              "benign SITL per docs/CALIBRATION_PX4.md) -- proceeding because it was explicitly requested",
              file=sys.stderr)
    model_path = {"px4": MODEL_PX4, "stage1": MODEL_STAGE1, "none": None}[model_choice]
    model = model_path if model_path and Path(model_path).exists() else None
    if model_path and model is None:
        print(f"ERROR: requested model {model_path!r} does not exist", file=sys.stderr)
        return 2
    pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)
    ids_src = LiveMavlinkSource(ids_transport, sample_rate_hz=10.0, max_ticks=int(a.seconds * 10))

    started = datetime.now(UTC).isoformat()
    n_decisions = n_threats = 0
    try:
        with open(out.with_suffix(".ids_decisions.jsonl"), "w", encoding="utf-8") as jf:
            for tick in ids_src.stream():
                asmt = pipe.process_tick(tick)
                if asmt is None:
                    continue
                n_decisions += 1
                n_threats += bool(asmt.threat)
                jf.write(json.dumps({"t": round(asmt.t, 2), "threat": bool(asmt.threat),
                                     "type": asmt.attack_type.value, "score": round(asmt.threat_score, 3),
                                     "evidence": list(asmt.evidence)}) + "\n")
    finally:
        ids_stats = ids_src.stats
        ids_transport.close()
        relay.close()
        frame_log.close()

    actual = compute_actual_effect(out.with_suffix(".frames.jsonl"), ref_lat_deg=PX4_HOME_LAT)
    prov_raw = collect(python_version=sys.version.split()[0])
    import importlib.metadata as md

    manifest = Manifest(
        trial_id=out.name, seed=a.seed, trial_index=a.trial_index,
        provenance={"px4_git_describe": px4_describe(), "aegisflight_git_commit": prov_raw["aegisflight_commit"],
                   "python_version": prov_raw["python"], "pymavlink_version": md.version("pymavlink")},
        attack_type="GPS_SPOOFING", attack_mode="gradual_drift_live",
        message_type="GLOBAL_POSITION_INT", target_system=0, target_component=0,
        injection_point="downlink", claim_class="link-level detection (SITL)", environment="SITL",
        attack_action="modified", parameters={"onset_s": params.onset_s, "duration_s": params.duration_s,
                                              "drift_rate_ms": params.drift_rate_ms, "bearing_deg": params.bearing_deg,
                                              "detector_profile": a.profile or "stage1_default", "model_choice": model_choice},
        attack_start_utc=started, attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped, frames_injected=attack.frames_injected,
        expected_effect={"max_displacement_m": params.drift_rate_ms * params.duration_s, "bearing_deg": params.bearing_deg},
        actual_effect=actual, frames_skipped_signed=attack.frames_skipped_signed,
    )
    out.with_suffix(".manifest.json").write_text(json.dumps(
        {**manifest.__dict__, "schema_id": manifest.schema_id, "schema_version": manifest.schema_version,
         "detector_decision": manifest.detector_decision, "time_to_detection_s": manifest.time_to_detection_s,
         "full_provenance": prov_raw,
         "ids_summary": {"decisions": n_decisions, "threat_decisions": n_threats, "source_stats": ids_stats,
                         "relay_stats": relay.stats}},
        indent=2, default=str))
    print(json.dumps({"frames_seen": attack.frames_seen, "frames_modified": attack.frames_modified,
                      "actual_effect": actual, "ids_decisions": n_decisions, "ids_threat_decisions": n_threats,
                      "relay_stats": relay.stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
