"""Run ONE trial of the REDESIGNED P2 replay attack: capture a legitimate, unsigned
``COMMAND_LONG`` from an **expected GCS identity** (sysid 255 / compid 190, in the PX4
profile's ``expected_gcs_sysids``) carrying the SAME command already proven accepted by a
live PX4 (``MAV_CMD_COMPONENT_ARM_DISARM``, force-disarm params -- see
``src/aegisflight/proxy/attacks_live.py`` ``DEFAULT_COMMAND``/``DEFAULT_COMMAND_PARAMS``,
10/10 accepted in the command-injection batch), then re-send the byte-identical frame a
drawn delay later (``src/aegisflight/proxy/attacks_live_dos_replay.py`` ``ReplayAttack``).

Supersedes ``run_p2_replay_trial.py`` (pilot p2r_trial_001), which captured from a
non-expected-GCS identity (sysid 252) using a command PX4 rejected both times (neither
flaw is a code bug -- both were deliberate pilot choices this redesign corrects per the
task). The pilot's evidence is kept, not deleted; this is a separate experiment.

    .venv/Scripts/python.exe scripts/sitl/run_p2_replay_v2_trial.py --px4-port 18572 \
        --seed 5101 --out artifacts/sitl/p2r_v2_trial_001

Topology: PX4 SITL (WSL, GCS link) <-> MavlinkRelay <-up_hook=ReplayAttack(capture+replay),
down_hook=ReplayAttack(ack-watch only), mirror_uplink_to_clients=True-- downstream clients:
this script's own IDS tap (sysid 254/compid 191, ALSO an expected GCS identity, so this
topology does not need a non-expected "carrier" client and has none of the P2 injection
batch's rogue-source harness-artifact noise) + a capture client (sysid 255/compid 190) that
sends ONE legitimate force-disarm command for the attack to capture, then ordinary periodic
heartbeats that later serve as piggyback carriers for the replay. No flight driver: the
vehicle is disarmed on the ground throughout (same simplicity as the drop/delay batches);
disarming an already-disarmed vehicle is expected to be accepted as a no-op by PX4, giving
a clean, low-risk "accepted both times" result without needing an in-flight safety
discussion.

Environment: SITL. Attack: uplink replay of a previously-observed, real frame ONLY -- no
frame is ever decoded, modified, or re-packed. Claim ceiling: command-path effect (SITL)
only if a matching COMMAND_ACK is observed after the replay. Detection claim: this
specifically tests whether a command from an EXPECTED GCS sysid is ever flagged by the
protocol detector's provenance rule -- by construction of that rule
(``detectors/protocol.py``: ``c.sysid not in self.expected_gcs`` short-circuits the check),
it CANNOT be, replay or not; this trial measures the harness/delivery side of that claim
(did the frame reach the IDS, is there really no evidence), not whether the rule itself
could be changed.
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
    FrameLogWriter,
    Manifest,
    ReplayAttack,
    compute_replay_effect,
    draw_replay_params,
)
from aegisflight.proxy.attacks_live import DEFAULT_COMMAND, DEFAULT_COMMAND_PARAMS
from aegisflight.proxy.transport import make_udp_relay
from aegisflight.sources.mavlink_live import LiveMavlinkSource, UdpMavlinkTransport

#: An expected GCS identity (``configs/px4_sitl/detector.yaml`` inherits the Stage-1
#: default ``expected_gcs_sysids: [255, 254]``) -- the point of this redesign.
CAPTURE_SYSID = 255
CAPTURE_COMPID = 190
#: seconds of heartbeats the capture client sends before its one command (so the command carries a mid-stream seq).
CAPTURE_PREROLL_S = 3.0


class _CarrierRecorder:
    """Diagnostic wrapper around the real attack hook: records every call's direction/sysid/compid and
    whether it produced a 2-frame (replay) output. Changes no behaviour -- same pattern as
    ``run_p2_injection_trial.py``'s ``CarrierRecorder``."""

    def __init__(self, attack: ReplayAttack) -> None:
        self.attack = attack
        self.calls: list[tuple[str, int, int, int]] = []  # (direction, sysid, compid, len(out))

    def __call__(self, ctx):
        out = self.attack(ctx)
        self.calls.append((ctx.direction, ctx.sysid, ctx.compid, len(out)))
        return out


def main(argv: list[str] | None = None) -> int:
    ap = build_argparser(__doc__, default_seconds=60.0)
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not refuse_if_exists(out, (".frames.jsonl", ".manifest.json", ".ids_decisions.jsonl", ".ids_ingest.jsonl")):
        return 2

    px4_host = a.px4_host or wsl_ip()
    params = draw_replay_params(a.seed, a.trial_index)
    if params.replay_delay_s + 10.0 > a.seconds:
        print(f"WARNING: replay_delay_s={params.replay_delay_s:.1f}s leaves under 10s of trial "
              f"time ({a.seconds:g}s total) for a carrier to arrive after it fires -- the replay "
              f"may never happen this trial. Not fatal; proceeding because --seed/--seconds were "
              f"both explicit.", file=sys.stderr)

    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    attack = ReplayAttack(params, capture_sysid=CAPTURE_SYSID, capture_compid=CAPTURE_COMPID,
                          capture_command=DEFAULT_COMMAND, frame_log=frame_log)
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

    # The IDS tap registers with the relay FIRST, so it observes the ORIGINAL legitimate command (mirrored
    # uplink) as well as the replay. (v2 draft ordering started it after the capture client's command and so
    # saw only the replay -- a harness flaw, found in the first diagnostic run.)
    ids_transport = UdpMavlinkTransport(connect=("127.0.0.1", relay.downstream.local_address[1]), gcs_heartbeat=True,
                                        gcs_sysid=254, gcs_compid=191)
    ids_transport.start()
    capture_transport = UdpMavlinkTransport(connect=("127.0.0.1", relay.downstream.local_address[1]),
                                            gcs_heartbeat=True, gcs_sysid=CAPTURE_SYSID,
                                            gcs_compid=CAPTURE_COMPID)
    capture_transport.start()
    time.sleep(CAPTURE_PREROLL_S)  # let the GCS build a natural running sequence before it sends its command
    sent, capture_seq = capture_transport.send_gcs_message(lambda m: m.command_long_encode(
        PX4_VEHICLE_SYSID, PX4_VEHICLE_COMPID, DEFAULT_COMMAND, 0, *DEFAULT_COMMAND_PARAMS))
    if not sent:
        relay.close()
        capture_transport.close()
        ids_transport.close()
        frame_log.close()
        print("ERROR: could not send the one legitimate COMMAND_LONG for the attack to capture",
              file=sys.stderr)
        return 2
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
                                     "evidence": list(asmt.evidence)}) + "\n")
    finally:
        ingest_f.close()
        ids_stats = ids_src.stats
        ids_transport.close()
        capture_transport.close()
        relay.close()
        frame_log.close()

    effect = compute_replay_effect(out.with_suffix(".frames.jsonl"))
    prov = provenance_block("Ubuntu-24.04", "/home/astryx/PX4-Autopilot",
                            {"python_version": sys.version.split()[0]})

    manifest = Manifest(
        trial_id=out.name, seed=a.seed, trial_index=a.trial_index, provenance=prov["provenance"],
        attack_type="COMMAND_INJECTION", attack_mode="gcs_replay_live_v2_expected_identity",
        message_type="COMMAND_LONG", target_system=PX4_VEHICLE_SYSID, target_component=PX4_VEHICLE_COMPID,
        injection_point="uplink",
        claim_class="command-path effect (SITL) only if acked; NO detection claim possible by rule construction",
        environment="SITL", attack_action="replayed",
        parameters={"replay_delay_s": params.replay_delay_s, "capture_sysid": CAPTURE_SYSID,
                   "capture_compid": CAPTURE_COMPID, "capture_seq": capture_seq, "capture_command": int(DEFAULT_COMMAND),
                   "detector_profile": a.profile or "stage1_default", "model_choice": model_choice},
        attack_start_utc=started, attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped, frames_injected=attack.frames_replayed,
        expected_effect={"expected_detector_signal": "none possible: sysid 255 is in expected_gcs_sysids, "
                        "so detectors/protocol.py's command-provenance rule short-circuits before even "
                        "looking at the command -- this is the P4 before/after baseline for an EXPECTED "
                        "identity, distinct from the rogue-identity (sysid 66) injection result",
                        "expected_result_if_accepted": "MAV_RESULT_ACCEPTED (0) on both the original "
                        "and the replay ack (disarming an already-disarmed vehicle is expected to be a "
                        "no-op accept)"},
        actual_effect=effect, frames_skipped_signed=attack.frames_skipped_signed,
    )
    write_manifest(out, manifest, prov["full_provenance"],
                   {"decisions": n_decisions, "threat_decisions": n_threats, "source_stats": ids_stats,
                    "relay_stats": relay.stats,
                    # diagnostic only (not a schema field relied on elsewhere): every up/down hook call's
                    # (direction, sysid, compid, len(out)) -- lets a replay's carrier be identified from
                    # the manifest alone, which the pre-fix p2r_trial_001 pilot could not do.
                    "hook_calls_tail": hook.calls[-20:]})
    print(json.dumps({"frames_seen": attack.frames_seen, "frames_replayed": attack.frames_replayed,
                      "actual_effect": effect, "ids_decisions": n_decisions, "ids_threat_decisions": n_threats,
                      "relay_stats": relay.stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
