"""Run ONE trial of the fifth P2 live attack (uplink COMMAND_LONG replay -- the
documented ``command_injection:gcs_replay`` known gap, live: capture one legitimate,
unsigned ``MAV_CMD_SET_MESSAGE_INTERVAL`` from the carrier GCS identity (sysid 252 /
compid 193) and re-send the byte-identical frame a drawn delay later, piggybacked on a
later real uplink frame; docs/ATTACK_PROXY.md order item 4;
``src/aegisflight/proxy/attacks_live_dos_replay.py`` ``ReplayAttack``) through the
``MavlinkRelay`` against a local PX4 SITL.

    .venv/Scripts/python.exe scripts/sitl/run_p2_replay_trial.py --px4-port 18572 \
        --seed 5001 --out artifacts/sitl/p2r_trial_001

Topology:
    PX4 SITL (WSL, GCS link) <-> MavlinkRelay <-up_hook=ReplayAttack(capture+replay),
        down_hook=ReplayAttack(ack-watch only)-- downstream clients: this script's own IDS
        tap (down_hook watches for COMMAND_ACK; mirror_uplink_to_clients=True gives the IDS
        tap visibility into the uplink it otherwise has none of, see
        run_p2_injection_trial.py's own note on this) + a "carrier" client (sysid 252 /
        compid 193) that sends ONE legitimate MAV_CMD_SET_MESSAGE_INTERVAL for the attack to
        capture, then ordinary periodic heartbeats that later serve as piggyback carriers
        for the replay.

Environment: SITL. Attack: uplink replay of a previously-observed, real frame ONLY -- no
frame is ever decoded, modified, or re-packed by this attack; it is a pure byte replay.
Claim ceiling: command-path effect (SITL) -- and only that, only if a matching
COMMAND_ACK is observed after the replay; this script reports both the original and the
replay ack (or their absence), never a detection claim. Under ``require_signing: false``
(the current default -- see ``configs/px4_sitl``/``configs/detector.yaml``) the replayed
frame is byte-identical to the legitimate one (same sysid/compid/seq), so the protocol
detector's identity/provenance checks are **not expected** to see anything different --
that absence is the point: this is the "before" half of the P4 signing before/after
measurement that would close this known gap, not an incidental negative result.

A benign flight driver (scripts/sitl/record_flight.py, distinct sysid) running
concurrently against the relay's downstream port is NOT required for this attack (unlike
the arm/disarm command-injection attack) -- MAV_CMD_SET_MESSAGE_INTERVAL has no
armed/flying precondition.
"""

from __future__ import annotations

import json
import sys
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
from pymavlink.dialects.v20 import common as mav2

from aegisflight.config import load_config
from aegisflight.pipeline import IDSPipeline
from aegisflight.proxy import (
    FrameLogWriter,
    Manifest,
    ReplayAttack,
    compute_replay_effect,
    draw_replay_params,
)
from aegisflight.proxy.attacks_live_dos_replay import (
    DEFAULT_CAPTURE_COMMAND,
    DEFAULT_CAPTURE_COMPID,
    DEFAULT_CAPTURE_SYSID,
)
from aegisflight.proxy.transport import make_udp_relay
from aegisflight.sources.mavlink_live import LiveMavlinkSource, UdpMavlinkTransport


def _legit_command_long_raw(seq: int = 0) -> bytes:
    """The ONE legitimate, unsigned frame this trial sends for ``ReplayAttack`` to
    capture -- ``MAV_CMD_SET_MESSAGE_INTERVAL`` (511) targeting MESSAGE_INTERVAL (244) at
    100 ms, from the carrier identity (sysid 252 / compid 193), targeting PX4's real SITL
    vehicle identity (sysid 3 / compid 1, ``docs/PX4_SITL_INTEGRATION.md``). Harmless --
    it only asks PX4 to (re)stream a message at a given rate, chosen (per the task) so
    PX4's acceptance/rejection via COMMAND_ACK is unambiguous without an arm/disarm-style
    safety discussion."""
    m = mav2.MAVLink(None, srcSystem=DEFAULT_CAPTURE_SYSID, srcComponent=DEFAULT_CAPTURE_COMPID)
    m.seq = seq
    return bytes(m.command_long_encode(
        PX4_VEHICLE_SYSID, PX4_VEHICLE_COMPID, DEFAULT_CAPTURE_COMMAND, 0,
        244.0, 100_000.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    ).pack(m))


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
    attack = ReplayAttack(params, frame_log=frame_log)
    # Same instance as BOTH hooks -- up_hook captures+replays, down_hook only ever watches
    # for the ack (see the class docstring, same convention as CommandInjectionAttack).
    # mirror_uplink_to_clients=True: without it the IDS tap has ZERO visibility into uplink
    # traffic, including this attack's own replayed frame -- see run_p2_injection_trial.py's
    # own note (docs/STAGE2_PROGRESS.md "architectural finding").
    relay = make_udp_relay(px4_host, a.px4_port, a.relay_listen_port, up_hook=attack, down_hook=attack,
                           mirror_uplink_to_clients=True)
    relay.start()
    if not relay.wait_upstream_alive(timeout=15.0):
        relay.close()
        frame_log.close()
        print("ERROR: PX4 never answered the relay's heartbeat within 15s", file=sys.stderr)
        return 2

    # A dedicated "carrier" client (sysid 252 / compid 193) supplies the ONE legitimate
    # command this trial's attack captures, then ordinary periodic heartbeats that later
    # serve as piggyback carriers for the replay (mirroring excludes the sender of the
    # carrier frame, so the IDS tap -- a separate, non-sending client below -- is the one
    # that actually observes the mirrored replay, same rationale as run_p2_injection_trial.py).
    carrier_transport = UdpMavlinkTransport(connect=("127.0.0.1", relay.downstream.local_address[1]),
                                             gcs_heartbeat=True, gcs_sysid=DEFAULT_CAPTURE_SYSID,
                                             gcs_compid=DEFAULT_CAPTURE_COMPID)
    carrier_transport.start()
    if not carrier_transport.send(_legit_command_long_raw(seq=0)):
        relay.close()
        carrier_transport.close()
        frame_log.close()
        print("ERROR: could not send the one legitimate COMMAND_LONG for the attack to capture",
              file=sys.stderr)
        return 2

    ids_transport = UdpMavlinkTransport(connect=("127.0.0.1", relay.downstream.local_address[1]), gcs_heartbeat=True,
                                        gcs_sysid=254, gcs_compid=191)
    ids_transport.start()
    try:
        model, model_choice = resolve_model(a.profile, a.model)
    except SystemExit as exc:
        relay.close()
        ids_transport.close()
        carrier_transport.close()
        frame_log.close()
        return int(exc.code or 2)
    cfg = load_config(a.profile or None)
    pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)
    ids_src = LiveMavlinkSource(ids_transport, sample_rate_hz=10.0, max_ticks=int(a.seconds * 10))

    started = datetime.now(UTC).isoformat()
    n_decisions = n_threats = 0
    # Ingest tap: every non-vehicle-source message handed to the pipeline, written BEFORE
    # the pipeline sees it -- diagnoses "did the frame reach the IDS at all" vs "did the
    # detector ignore it", independent of detector output. Same pattern as
    # run_p2_injection_trial.py.
    ingest_f = open(out.with_suffix(".ids_ingest.jsonl"), "w", encoding="utf-8")  # noqa: SIM115
    try:
        with open(out.with_suffix(".ids_decisions.jsonl"), "w", encoding="utf-8") as jf:
            for tick in ids_src.stream():
                for m in tick.messages:
                    if m.sysid != PX4_VEHICLE_SYSID or m.msgname in ("COMMAND_LONG", "COMMAND_ACK"):
                        ingest_f.write(json.dumps({"tick_t": round(tick.t, 2), "recv_time": round(m.recv_time, 3),
                                                   "sysid": m.sysid, "compid": m.compid, "msg": m.msgname}) + "\n")
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

    effect = compute_replay_effect(out.with_suffix(".frames.jsonl"))
    prov = provenance_block("Ubuntu-24.04", "/home/astryx/PX4-Autopilot",
                            {"python_version": sys.version.split()[0]})

    manifest = Manifest(
        trial_id=out.name, seed=a.seed, trial_index=a.trial_index, provenance=prov["provenance"],
        attack_type="COMMAND_INJECTION", attack_mode="gcs_replay_live",
        message_type="COMMAND_LONG", target_system=PX4_VEHICLE_SYSID, target_component=PX4_VEHICLE_COMPID,
        injection_point="uplink",
        claim_class="command-path effect (SITL) only if acked; NO detection claim (see module docstring)",
        environment="SITL", attack_action="replayed",
        parameters={"replay_delay_s": params.replay_delay_s, "capture_sysid": DEFAULT_CAPTURE_SYSID,
                   "capture_compid": DEFAULT_CAPTURE_COMPID, "capture_command": int(DEFAULT_CAPTURE_COMMAND),
                   "detector_profile": a.profile or "stage1_default", "model_choice": model_choice},
        attack_start_utc=started, attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped,
        # Manifest has no dedicated "frames_replayed" counter (schema predates this attack);
        # attack.frames_injected is always 0 for ReplayAttack (kept only for API parity with
        # the other hooks) -- attack.frames_replayed is mapped into frames_injected here as
        # the closest honest fit ("a previously-captured frame put back on the wire"), not
        # because a replay IS an injection in the CommandInjectionAttack sense.
        frames_injected=attack.frames_replayed,
        expected_effect={"expected_detector_signal": "none expected under require_signing=false -- "
                        "this IS the P4 before/after baseline, not an incidental negative result",
                        "expected_result_if_accepted": "MAV_RESULT_ACCEPTED (0) on both the original "
                        "and the replay ack"},
        actual_effect=effect, frames_skipped_signed=attack.frames_skipped_signed,
    )
    write_manifest(out, manifest, prov["full_provenance"],
                   {"decisions": n_decisions, "threat_decisions": n_threats, "source_stats": ids_stats,
                    "relay_stats": relay.stats})
    print(json.dumps({"frames_seen": attack.frames_seen, "frames_replayed": attack.frames_replayed,
                      "actual_effect": effect, "ids_decisions": n_decisions, "ids_threat_decisions": n_threats,
                      "relay_stats": relay.stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
