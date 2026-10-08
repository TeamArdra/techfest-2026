"""Run ONE trial of the P2 expected-GCS IMPERSONATION attack: a FRESH forged ``COMMAND_LONG``
(force-disarm, the command already proven accepted live) stamped with an identity the PX4
profile treats as an expected GCS (sysid 255 / compid 190, in ``expected_gcs_sysids``).

    .venv/Scripts/python.exe scripts/sitl/run_p2_gcs_impersonation_trial.py --px4-port 18572 \
        --seed 6101 --seq-policy track_identity --out artifacts/sitl/p2g_trial_001

Not a replay: nothing is captured. The frame is built from scratch by
``attacks_live.CommandInjectionAttack(rogue_sysid=255, rogue_compid=190, seq_policy=...)`` and
piggybacked on a real uplink frame. Two attacker strengths, run as separate batches:

* ``--seq-policy own_counter``   (naive)  the forger keeps its own MAVLink sequence counter, starting at 0.
* ``--seq-policy track_identity`` (informed) the forger passively reads the real 255/190 heartbeat's
  running sequence number off the clear-text link and continues it.

Topology: PX4 SITL <-> MavlinkRelay(up_hook=down_hook=the attack, mirror_uplink_to_clients=True) <->
IDS tap (sysid 254/compid 191, registers FIRST) + a benign scripted GCS client (255/190, 1 Hz heartbeats; the
legitimate source of that identity). No rogue "carrier" client and no flight driver, so the trial has no
rogue-source harness noise; the vehicle is disarmed on the ground, so a force-disarm acked ACCEPTED is a
command-path effect measured by the ACK only (no state change is observable).

Environment: SITL. Questions answered separately, never merged (see make_p2g_summary.py): did the forged
frame reach PX4 and was it accepted (command-path effect, from the proxy's own frame log); did it reach the
IDS pipeline (harness delivery, from the ingest tap); did any rule flag it, and which one (link-level
detection). No estimator or physical effect is claimed.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from p2_trial_common import (
    PX4_VEHICLE_COMPID,
    PX4_VEHICLE_SYSID,
    build_argparser,
    provenance_block,
    refuse_if_exists,
    resolve_model,
    write_manifest,
    wsl_ip,
)

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

IMPERSONATED_SYSID = 255
IMPERSONATED_COMPID = 190


class _CarrierRecorder:
    """Records (sysid, compid, len(out)) for every uplink call that produced an injection. Changes no behaviour."""

    def __init__(self, attack: CommandInjectionAttack) -> None:
        self.attack = attack
        self.injections: list[dict] = []

    def __call__(self, ctx):
        out = self.attack(ctx)
        if ctx.direction == "up" and len(out) > 1:
            self.injections.append({"carrier_sysid": ctx.sysid, "carrier_compid": ctx.compid,
                                    "carrier_seq": ctx.seq, "n_out": len(out)})
        return out


def main(argv: list[str] | None = None) -> int:
    ap = build_argparser(__doc__, default_seconds=100.0)
    ap.add_argument("--seq-policy", choices=("own_counter", "track_identity"), required=True)
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not refuse_if_exists(out, (".frames.jsonl", ".manifest.json", ".ids_decisions.jsonl", ".ids_ingest.jsonl")):
        return 2

    px4_host = a.px4_host or wsl_ip()
    params = draw_command_injection_params(a.seed, a.trial_index)
    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    attack = CommandInjectionAttack(params, rogue_sysid=IMPERSONATED_SYSID, rogue_compid=IMPERSONATED_COMPID,
                                    seq_policy=a.seq_policy, frame_log=frame_log)
    hook = _CarrierRecorder(attack)
    relay = make_udp_relay(px4_host, a.px4_port, a.relay_listen_port, up_hook=hook, down_hook=hook,
                           mirror_uplink_to_clients=True)
    relay.start()
    if not relay.wait_upstream_alive(timeout=15.0):
        relay.close()
        frame_log.close()
        print("ERROR: PX4 never answered the relay's heartbeat within 15s", file=sys.stderr)
        return 2
    try:
        model, model_choice = resolve_model(a.profile, a.model)
    except SystemExit as exc:
        relay.close()
        frame_log.close()
        return int(exc.code or 2)

    port = relay.downstream.local_address[1]
    ids_transport = UdpMavlinkTransport(connect=("127.0.0.1", port), gcs_heartbeat=True, gcs_sysid=254, gcs_compid=191)
    ids_transport.start()
    gcs_transport = UdpMavlinkTransport(connect=("127.0.0.1", port), gcs_heartbeat=True,
                                        gcs_sysid=IMPERSONATED_SYSID, gcs_compid=IMPERSONATED_COMPID)
    gcs_transport.start()
    time.sleep(2.0)

    cfg = load_config(a.profile or None)
    pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)
    ids_src = LiveMavlinkSource(ids_transport, sample_rate_hz=10.0, max_ticks=int(a.seconds * 10))

    started = datetime.now(UTC).isoformat()
    n_decisions = n_threats = 0
    ingest_f = open(out.with_suffix(".ids_ingest.jsonl"), "w", encoding="utf-8")  # noqa: SIM115
    try:
        with open(out.with_suffix(".ids_decisions.jsonl"), "w", encoding="utf-8") as jf:
            for tick in ids_src.stream():
                for m in tick.messages:
                    if m.sysid != PX4_VEHICLE_SYSID or m.msgname in ("COMMAND_LONG", "COMMAND_ACK"):
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
                                     "evidence": list(asmt.evidence)}, ensure_ascii=False) + "\n")
    finally:
        ingest_f.close()
        ids_stats = ids_src.stats
        ids_transport.close()
        gcs_transport.close()
        relay.close()
        frame_log.close()

    effect = compute_command_injection_effect(out.with_suffix(".frames.jsonl"))
    prov = provenance_block("Ubuntu-24.04", "/home/astryx/PX4-Autopilot", {"python_version": sys.version.split()[0]})
    manifest = Manifest(
        trial_id=out.name, seed=a.seed, trial_index=a.trial_index, provenance=prov["provenance"],
        attack_type="COMMAND_INJECTION", attack_mode=f"expected_gcs_impersonation_{a.seq_policy}",
        message_type="COMMAND_LONG", target_system=PX4_VEHICLE_SYSID, target_component=PX4_VEHICLE_COMPID,
        injection_point="uplink",
        claim_class="command-path effect (SITL) only if acked; link-level detection reported separately",
        environment="SITL", attack_action="injected",
        parameters={"onset_s": params.onset_s, "burst_count": params.burst_count,
                    "inter_injection_gap_s": params.inter_injection_gap_s,
                    "impersonated_sysid": IMPERSONATED_SYSID, "impersonated_compid": IMPERSONATED_COMPID,
                    "seq_policy": a.seq_policy, "detector_profile": a.profile or "stage1_default",
                    "model_choice": model_choice},
        attack_start_utc=started, attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped, frames_injected=attack.frames_injected,
        expected_effect={"hypothesis_fixed_before_running": {
            "own_counter": "flagged by the sequence-continuity rule (stale-vs-running seq), not by identity",
            "track_identity": "NOT flagged by the provenance rule (255 is expected) and NOT by sequence "
                              "continuity (the forgery continues the real counter) -> the authentication gap"}[a.seq_policy]},
        actual_effect=effect, frames_skipped_signed=attack.frames_skipped_signed,
    )
    write_manifest(out, manifest, prov["full_provenance"],
                   {"decisions": n_decisions, "threat_decisions": n_threats, "source_stats": ids_stats,
                    "relay_stats": relay.stats, "injection_carriers": hook.injections,
                    "frames_skipped_no_identity_seq": attack.frames_skipped_no_identity_seq})
    print(json.dumps({"frames_injected": attack.frames_injected, "actual_effect": effect,
                      "ids_decisions": n_decisions, "ids_threat_decisions": n_threats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
