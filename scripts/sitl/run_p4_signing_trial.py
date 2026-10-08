"""Run ONE trial of P4 (MAVLink 2 signing): does turning signing on between the legitimate
GCS and PX4 change the outcome of the expected-GCS impersonation attack that defeated every
current detection mechanism (``run_p2_gcs_impersonation_trial.py --seq-policy track_identity``,
0/10 detected, 10/10 ACCEPTED by PX4)? Evolved from the n=1 pilot into an n=10-capable driver
(the pilot's two harness bugs -- IDS-tap target learning breaking once PX4 signs its own
downlink, and a signing key persisting across SITL restarts within the same run dir -- are
fixed here, not re-discovered per trial; the batch runner also clears the persisted key file
before every boot, see ``run_trial_batch.sh``).

    .venv/Scripts/python.exe scripts/sitl/run_p4_signing_trial.py --px4-port 18572 \
        --seed 7001 --trial-index 0 --out artifacts/sitl/p4_sign_n10_trial_001

Topology (vehicle disarmed throughout -- PX4 rejects SETUP_SIGNING while armed,
``mavlink_main.cpp``, scoped read-only): PX4 SITL <-> MavlinkRelay(up/down_hook=the informed-
impersonation attack, mirror_uplink_to_clients=True) <-> an IDS tap (sysid 254/compid 191,
registers FIRST, running the REAL ``IDSPipeline`` with ``require_signing`` forced on and a
VERIFYING parser using the SAME per-trial key the legitimate GCS uses -- the realistic
"signing is this deployment's policy" configuration) + the legitimate GCS (255/190, signed
after bootstrap) + an inert, always-unsigned carrier (253/192, delivery only -- the attack
hook never piggybacks on an already-signed frame by design, and the GCS's own traffic is now
signed, so the forged command needs an unsigned carrier to ride on at all).

Five questions, answered SEPARATELY per trial, never merged (the task's own framing):
1. legitimate signed command: accepted/rejected by PX4 (ack result, polled off the GCS's own
   transport -- never via the attack's ack-watcher).
2. unsigned forged command: accepted/rejected by PX4 (ack count via the proxy's own frame log).
3. did the IDS's transport observe the forged bytes at all (``LiveStats.sig_invalid`` on the
   IDS's own verifying parser increasing by exactly the number of forged frames -- a frame
   that fails verification is still COUNTED, proving it reached and was processed by the
   parser, even though it never becomes a decodable envelope; this is the "observed" signal,
   independent of "accepted as valid").
4. did the IDS DETECT it via the new P4 rule specifically (``detectors/protocol.py``:
   ``require_signing and frame.sig_invalid_count > 0`` -> evidence string containing
   "signature verification").
5. did the IDS flag ANYTHING in that window via any other rule (e.g. the pre-existing,
   cruder ``signed_ratio < 1.0`` rule, which -- disclosed, not hidden -- fires almost
   continuously in THIS harness because the inert carrier is deliberately always unsigned,
   so it is not a clean pre-onset false-alarm baseline on its own; reported separately from
   question 4, which stays clean because ``sig_invalid_count`` is 0 until the forged frames
   actually arrive).

This is explicitly a controlled n=10 experiment (one trial per invocation; batch with
``run_trial_batch.sh``), not a statistically powered study -- the design floor used
throughout this Stage-2 effort.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
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
)
from aegisflight.proxy.attacks_live import DEFAULT_COMMAND, DEFAULT_COMMAND_PARAMS
from aegisflight.proxy.attacks_live import CommandInjectionParams as _Params
from aegisflight.proxy.transport import make_udp_relay
from aegisflight.sources.mavlink_live import (
    LiveMavlinkSource,
    MavlinkFrameParser,
    UdpMavlinkTransport,
    send_setup_signing,
)

GCS_SYSID, GCS_COMPID = 255, 190
CARRIER_SYSID, CARRIER_COMPID = 253, 192  # inert, always-unsigned -- delivery only, see module docstring
IDS_SYSID, IDS_COMPID = 254, 191
ONSET_S, BURST_COUNT, GAP_S = 8.0, 2, 1.5
TAIL_S = 5.0


def main(argv: list[str] | None = None) -> int:
    ap = build_argparser(__doc__, default_seconds=45.0)
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not refuse_if_exists(out, (".frames.jsonl", ".manifest.json", ".ids_decisions.jsonl")):
        return 2

    # Deterministic per-trial key -- reproducible, never reused byte-for-byte across trials
    # (hygiene only; the key is a test value, not security-sensitive, see docstring).
    secret_key = hashlib.sha256(f"p4-signing:{a.seed}:{a.trial_index}".encode()).digest()

    px4_host = a.px4_host or wsl_ip()
    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    params = _Params(trial_seed=a.seed, trial_index=a.trial_index, onset_s=ONSET_S,
                     burst_count=BURST_COUNT, inter_injection_gap_s=GAP_S)
    # target_sysid/compid passed explicitly: once signing is active PX4 signs ALL its own
    # outgoing traffic (SIGN_OUTGOING is set link-wide, not just for what it receives), so the
    # attack's usual passive-learn-from-an-unsigned-PX4-heartbeat path (fail-closed on a signed
    # frame it does not verify) would never fire post-signing -- found live by the n=1 pilot's
    # first attempt; bypassed here (irrelevant to what this experiment measures), not "fixed".
    attack = CommandInjectionAttack(params, target_sysid=PX4_VEHICLE_SYSID, target_compid=PX4_VEHICLE_COMPID,
                                    rogue_sysid=GCS_SYSID, rogue_compid=GCS_COMPID,
                                    seq_policy="track_identity", frame_log=frame_log)
    relay = make_udp_relay(px4_host, a.px4_port, a.relay_listen_port, up_hook=attack, down_hook=attack,
                           mirror_uplink_to_clients=True)
    relay.start()
    log: list[dict] = []

    def record(event: str, **fields: object) -> None:
        entry = {"t": round(time.monotonic(), 3), "event": event, **fields}
        log.append(entry)
        print(json.dumps(entry))

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

    # IDS tap registers FIRST (learned from the replay-v2 harness fix: the relay excludes a
    # frame's own sender from the uplink mirror, so whichever client's heartbeat carries an
    # injection never sees its own mirrored copy -- irrelevant to signing itself, but keeping
    # the convention avoids re-discovering that bug here too).
    ids_transport = UdpMavlinkTransport(connect=("127.0.0.1", port), gcs_heartbeat=True,
                                        gcs_sysid=IDS_SYSID, gcs_compid=IDS_COMPID)
    ids_transport.start()

    cfg = load_config(a.profile or None)
    cfg.detector["protocol"]["require_signing"] = True  # THIS experiment's explicit policy
    pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)
    ids_src = LiveMavlinkSource(ids_transport, sample_rate_hz=10.0, max_ticks=int(a.seconds * 10),
                                secret_key=secret_key)

    gcs = UdpMavlinkTransport(connect=("127.0.0.1", port), gcs_heartbeat=False, gcs_sysid=GCS_SYSID,
                              gcs_compid=GCS_COMPID)
    gcs.start()
    carrier = UdpMavlinkTransport(connect=("127.0.0.1", port), gcs_heartbeat=True, heartbeat_hz=1.0,
                                  gcs_sysid=CARRIER_SYSID, gcs_compid=CARRIER_COMPID)
    carrier.start()
    time.sleep(1.0)

    sent, seq = send_setup_signing(gcs, PX4_VEHICLE_SYSID, PX4_VEHICLE_COMPID, secret_key, initial_timestamp=1000)
    record("setup_signing_sent", sent=sent, seq=seq)
    time.sleep(1.0)  # let PX4 process + broadcast its STATUSTEXT before anything else happens
    gcs.enable_signing(secret_key, initial_timestamp=1000)
    record("gcs_signing_enabled")

    # The GCS's own heartbeat loop starts only AFTER signing is enabled, so every heartbeat
    # this trial ever sends from the legitimate identity is genuinely signed, not a mix.
    gcs._hb_enabled = True
    hb_thread = threading.Thread(target=gcs._hb_loop, daemon=True)
    hb_thread.start()

    # one legitimate, SIGNED resend of the proven-accepted command
    sent, seq = gcs.send_gcs_message(lambda m: m.command_long_encode(
        PX4_VEHICLE_SYSID, PX4_VEHICLE_COMPID, DEFAULT_COMMAND, 0, *DEFAULT_COMMAND_PARAMS))
    record("legit_signed_command_sent", sent=sent, seq=seq)

    # independently confirm its ack straight off the GCS's own receive queue -- never via the
    # attack's ack-watcher, which only starts watching after ITS OWN injection
    legit_parser = MavlinkFrameParser()
    legit_ack: dict | None = None
    n_decisions = n_threats = 0
    sig_invalid_before = ids_src.stats.get("sig_invalid", 0)
    started = datetime.now(UTC).isoformat()
    with open(out.with_suffix(".ids_decisions.jsonl"), "w", encoding="utf-8") as jf:
        for tick in ids_src.stream():
            asmt = pipe.process_tick(tick)
            for _, raw in gcs.poll():
                for env in legit_parser.parse(raw, tick.t):
                    if env.msgname == "COMMAND_ACK" and env.fields.get("command") == int(DEFAULT_COMMAND):
                        if legit_ack is None:
                            legit_ack = {"result": env.fields.get("result"), "signed": env.signed}
                            record("legit_command_ack_observed", **legit_ack)
            if asmt is None:
                continue
            n_decisions += 1
            n_threats += bool(asmt.threat)
            jf.write(json.dumps({"t": round(asmt.t, 2), "threat": bool(asmt.threat),
                                 "type": asmt.attack_type.value, "score": round(asmt.threat_score, 3),
                                 "evidence": list(asmt.evidence)}, ensure_ascii=False) + "\n")

    sig_invalid_after = ids_src.stats.get("sig_invalid", 0)
    ids_stats = ids_src.stats
    gcs.close()
    carrier.close()
    ids_transport.close()
    relay.close()
    frame_log.close()

    effect = compute_command_injection_effect(out.with_suffix(".frames.jsonl"))
    record("attack_effect", **effect)
    prov = provenance_block("Ubuntu-24.04", "/home/astryx/PX4-Autopilot", {"python_version": sys.version.split()[0]})
    manifest = Manifest(
        trial_id=out.name, seed=a.seed, trial_index=a.trial_index, provenance=prov["provenance"],
        attack_type="COMMAND_INJECTION", attack_mode="expected_gcs_impersonation_track_identity_post_signing",
        message_type="COMMAND_LONG", target_system=PX4_VEHICLE_SYSID, target_component=PX4_VEHICLE_COMPID,
        injection_point="uplink",
        claim_class="command-path effect (PX4 acceptance) + link-level detection (IDS, signing-aware), "
                    "scored separately -- see module docstring",
        environment="SITL", attack_action="injected",
        parameters={"onset_s": ONSET_S, "burst_count": BURST_COUNT, "inter_injection_gap_s": GAP_S,
                   "seq_policy": "track_identity", "signing_secret_key_sha256": hashlib.sha256(secret_key).hexdigest(),
                   "detector_profile": a.profile or "stage1_default", "model_choice": model_choice,
                   "require_signing_forced": True},
        attack_start_utc=started, attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped, frames_injected=attack.frames_injected,
        expected_effect={"hypothesis_fixed_before_running":
                         "with signing active and require_signing forced on the IDS profile: PX4 should not "
                         "accept the unsigned forged command (0 acks); the IDS's verifying parser should "
                         "still observe it (sig_invalid increases by frames_injected) and the new "
                         "sig_invalid_count rule should flag it; the legitimate signed resend should be "
                         "accepted by PX4 and produce no sig_invalid signal."},
        actual_effect=effect, frames_skipped_signed=attack.frames_skipped_signed,
    )
    write_manifest(out, manifest, prov["full_provenance"],
                   {"decisions": n_decisions, "threat_decisions": n_threats, "source_stats": ids_stats,
                    "relay_stats": relay.stats, "event_log": log, "legit_signed_command_ack": legit_ack,
                    "ids_sig_invalid_before": sig_invalid_before, "ids_sig_invalid_after": sig_invalid_after})
    print(json.dumps({"relay_stats": relay.stats, "actual_effect": effect, "legit_signed_command_ack": legit_ack,
                      "ids_decisions": n_decisions, "ids_threat_decisions": n_threats,
                      "ids_sig_invalid_delta": sig_invalid_after - sig_invalid_before}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
