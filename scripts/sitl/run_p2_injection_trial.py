"""Run ONE trial of the second P2 live attack (uplink COMMAND_LONG injection -- rogue
MAV_CMD_COMPONENT_ARM_DISARM force-disarm, docs/ATTACK_PROXY.md order item 2;
src/aegisflight/proxy/attacks_live.py CommandInjectionAttack) through the MavlinkRelay
against a local PX4 SITL.

    .venv/Scripts/python.exe scripts/sitl/run_p2_injection_trial.py --px4-port 18572 \
        --seed 2001 --out artifacts/sitl/p2i_trial_001

Topology:
    PX4 SITL (WSL, GCS link) <-> MavlinkRelay <-up_hook=CommandInjectionAttack(inject)--
        downstream clients: this script's own IDS tap (down_hook watches for COMMAND_ACK)
        + a benign flight-driver client (its uplink heartbeat is the carrier the attack
        piggybacks its forged COMMAND_LONG onto)

Environment: SITL. Attack: rogue uplink COMMAND_LONG injection ONLY -- no downlink frame is
ever modified (down_hook only watches for COMMAND_ACK, never changes it). Claim class:
wire-level fact (frames_injected > 0) at minimum; **command-path effect (SITL)** only if a
matching COMMAND_ACK is actually observed -- this script reports both, never conflating
them. Does not show IDS detection of this specific attack type (not measured here) or any
vehicle trajectory/estimator effect beyond what a disarm's own telemetry shows.

A benign flight driver (scripts/sitl/record_flight.py, distinct sysid) should be running
concurrently against the relay's downstream port so PX4 is actually armed/flying when the
disarm lands -- otherwise the ground truth answers "did PX4 ack a disarm command" but not
"while armed/flying". This script does not launch the driver itself.
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
    CommandInjectionAttack,
    FrameLogWriter,
    Manifest,
    compute_command_injection_effect,
    draw_command_injection_params,
)
from aegisflight.proxy.transport import make_udp_relay
from aegisflight.sources.mavlink_live import LiveMavlinkSource, UdpMavlinkTransport

MODEL_PX4 = "models/isoforest_px4.joblib"
MODEL_STAGE1 = "models/isoforest.joblib"


def wsl_ip(distro: str = "Ubuntu-24.04") -> str:
    import subprocess

    out = subprocess.run(["wsl", "-d", distro, "--", "hostname", "-I"], capture_output=True, text=True, timeout=30)
    return out.stdout.split()[0]


def px4_describe(distro: str = "Ubuntu-24.04", px4_dir: str = "/home/astryx/PX4-Autopilot") -> str:
    import subprocess

    out = subprocess.run(["wsl", "-d", distro, "--cd", px4_dir, "--", "git", "describe", "--tags", "--always"],
                         capture_output=True, text=True, timeout=30)
    return out.stdout.strip()


class CarrierRecorder:
    """Wraps the attack hook (installed as BOTH up_hook and down_hook); records the sysid of the uplink
    client whose frame carried each injection. Changes no behaviour: the attack's output is returned
    untouched. Ground truth for 'which client carried it', which the pre-fix batch did not log."""

    def __init__(self, attack: CommandInjectionAttack) -> None:
        self.attack = attack
        self.carriers: list[int] = []

    def __call__(self, ctx):
        out = self.attack(ctx)
        if ctx.direction == "up" and len(out) == 2:  # [carrier, injection]
            self.carriers.append(ctx.sysid)
        return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--px4-host", default=None)
    ap.add_argument("--px4-port", type=int, default=18572)
    ap.add_argument("--relay-listen-port", type=int, default=18672)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--trial-index", type=int, default=0)
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--profile", default="configs/px4_sitl")
    ap.add_argument("--model", choices=("px4", "stage1", "none"), default=None)
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    for suffix in (".frames.jsonl", ".manifest.json", ".ids_decisions.jsonl", ".ids_ingest.jsonl"):
        p = out.with_suffix(suffix)
        if p.exists():
            print(f"ERROR: {p} already exists. Remove explicitly before rerunning -- refusing "
                  f"to append/overwrite evidence files silently.", file=sys.stderr)
            return 2
    px4_host = a.px4_host or wsl_ip()
    params = draw_command_injection_params(a.seed, a.trial_index)

    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    attack = CommandInjectionAttack(params, frame_log=frame_log)
    # Same instance as BOTH hooks: up_hook injects, down_hook only ever watches for the ack
    # (see the class docstring -- this is the documented mechanism, not a shortcut).
    # mirror_uplink_to_clients=True: without it the IDS tap (a downstream client) has ZERO
    # visibility into uplink traffic (including this attack's own injected frames) -- see
    # docs/STAGE2_PROGRESS.md's "architectural finding" entry. Default-off elsewhere; this
    # trial specifically needs it to answer "would the IDS see this attack at all".
    hook = CarrierRecorder(attack)
    relay = make_udp_relay(px4_host, a.px4_port, a.relay_listen_port, up_hook=hook, down_hook=hook,
                           mirror_uplink_to_clients=True)
    relay.start()
    if not relay.wait_upstream_alive(timeout=15.0):
        relay.close()
        frame_log.close()
        print("ERROR: PX4 never answered the relay's heartbeat within 15s", file=sys.stderr)
        return 2

    model_choice = a.model or ("px4" if a.profile else "stage1")
    if model_choice == "px4" and not a.profile:
        print("ERROR: --model px4 without --profile is the untested B2 cross-pairing", file=sys.stderr)
        return 2
    model_path = {"px4": MODEL_PX4, "stage1": MODEL_STAGE1, "none": None}[model_choice]
    model = model_path if model_path and Path(model_path).exists() else None
    cfg = load_config(a.profile or None)
    pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)

    # Mirroring excludes the SENDER of the carrier frame (a client must not see an echo of
    # its own traffic). The attack piggybacks on whichever real uplink frame it next sees, so
    # if the IDS tap were the only relay client, it would always be that sender and would
    # never receive the mirror of its own carrier's injection. A separate, otherwise-inert
    # "carrier" client supplies real uplink heartbeats for the attack to piggyback on, so the
    # mirrored result reaches the IDS as a non-sending recipient (closer to a real deployment,
    # where other clients/GCSes exist on the same link).
    carrier_transport = UdpMavlinkTransport(connect=("127.0.0.1", relay.downstream.local_address[1]),
                                             gcs_heartbeat=True, gcs_sysid=252, gcs_compid=193)
    carrier_transport.start()

    ids_transport = UdpMavlinkTransport(connect=("127.0.0.1", relay.downstream.local_address[1]), gcs_heartbeat=True,
                                        gcs_sysid=254, gcs_compid=191)
    ids_transport.start()
    ids_src = LiveMavlinkSource(ids_transport, sample_rate_hz=10.0, max_ticks=int(a.seconds * 10))

    started = datetime.now(UTC).isoformat()
    n_decisions = n_threats = 0
    # Ingest tap: every non-vehicle-source message the IDS source hands to the pipeline, written
    # BEFORE the pipeline sees it (diagnoses "did the frame reach the IDS at all" vs "did the
    # detector ignore it"). Independent of detector output.
    ingest_f = open(out.with_suffix(".ids_ingest.jsonl"), "w", encoding="utf-8")  # noqa: SIM115
    try:
        with open(out.with_suffix(".ids_decisions.jsonl"), "w", encoding="utf-8") as jf:
            for tick in ids_src.stream():
                for m in tick.messages:
                    if m.sysid != 3 or m.msgname == "COMMAND_LONG":
                        ingest_f.write(json.dumps({"tick_t": round(tick.t, 2), "recv_time": round(m.recv_time, 3),
                                                   "sysid": m.sysid, "compid": m.compid, "msg": m.msgname,
                                                   "seq": m.seq}) + "\n")
                asmt = pipe.process_tick(tick)
                if asmt is None:
                    continue
                n_decisions += 1
                n_threats += bool(asmt.threat)
                jf.write(json.dumps({"t": round(asmt.t, 2), "threat": bool(asmt.threat),
                                     "type": asmt.attack_type.value, "score": round(asmt.threat_score, 3),
                                     "evidence": list(asmt.evidence)}) + "\n")
    finally:
        ingest_f.close()
        ids_stats = ids_src.stats
        ids_transport.close()
        carrier_transport.close()
        relay.close()
        frame_log.close()

    effect = compute_command_injection_effect(out.with_suffix(".frames.jsonl"))
    prov_raw = collect(python_version=sys.version.split()[0])
    import importlib.metadata as md

    manifest = Manifest(
        trial_id=out.name, seed=a.seed, trial_index=a.trial_index,
        provenance={"px4_git_describe": px4_describe(), "aegisflight_git_commit": prov_raw["aegisflight_commit"],
                   "python_version": prov_raw["python"], "pymavlink_version": md.version("pymavlink")},
        attack_type="COMMAND_INJECTION", attack_mode="rogue_force_disarm_live",
        message_type="COMMAND_LONG", target_system=0, target_component=0,
        injection_point="uplink", claim_class="wire-level fact; command-path effect (SITL) only if acked",
        environment="SITL", attack_action="injected",
        parameters={"onset_s": params.onset_s, "burst_count": params.burst_count,
                   "inter_injection_gap_s": params.inter_injection_gap_s,
                   "command": "MAV_CMD_COMPONENT_ARM_DISARM", "detector_profile": a.profile or "stage1_default",
                   "model_choice": model_choice},
        attack_start_utc=started, attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped, frames_injected=attack.frames_injected,
        expected_effect={"command": "MAV_CMD_COMPONENT_ARM_DISARM", "burst_count": params.burst_count,
                        "expected_result_if_accepted": "MAV_RESULT_ACCEPTED (0)"},
        actual_effect=effect, frames_skipped_signed=attack.frames_skipped_signed,
    )
    out.with_suffix(".manifest.json").write_text(json.dumps(
        {**manifest.__dict__, "schema_id": manifest.schema_id, "schema_version": manifest.schema_version,
         "detector_decision": manifest.detector_decision, "time_to_detection_s": manifest.time_to_detection_s,
         "full_provenance": prov_raw,
         # post-fix batch marker: hook-added frames are mirrored to ALL clients (carrier sender included);
         # the pre-fix batch (p2i_trial_*) lacks these keys. injection_carriers[i] = sysid whose uplink
         # frame carried injection i (rogue MAVLink seq == i).
         "relay_mirror_semantics": "hook_added_frames_to_all_clients",
         "injection_carriers": hook.carriers,
         "ids_summary": {"decisions": n_decisions, "threat_decisions": n_threats, "source_stats": ids_stats,
                         "relay_stats": relay.stats}},
        indent=2, default=str))
    print(json.dumps({"frames_seen": attack.frames_seen, "frames_injected": attack.frames_injected,
                      "actual_effect": effect, "ids_decisions": n_decisions, "ids_threat_decisions": n_threats,
                      "relay_stats": relay.stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
