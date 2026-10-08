"""Run ONE pilot trial of P4 (MAVLink 2 signing): does turning signing on between the
legitimate GCS and PX4 change the outcome of the expected-GCS impersonation attack that
defeated every current detection mechanism (``run_p2_gcs_impersonation_trial.py
--seq-policy track_identity``, 0/10 detected, 10/10 ACCEPTED by PX4)?

    .venv/Scripts/python.exe scripts/sitl/run_p4_signing_trial.py --px4-port 18572 \
        --seed 7001 --out artifacts/sitl/p4_sign_trial_001

Sequence (vehicle disarmed throughout -- PX4 rejects SETUP_SIGNING while armed,
``mavlink_main.cpp``, scoped read-only):
1. The legitimate GCS client (sysid 255/compid 190) sends ONE unsigned ``SETUP_SIGNING``
   to PX4's vehicle identity, bootstrapping a shared secret (PX4's own
   ``MavlinkSignControl::check_for_signing`` accepts the first non-blank key unconditionally
   -- a disclosed "trust on first contact" property of PX4's own mechanism, not an
   AegisFlight choice; the GCS sends it first and signing is confirmed live via PX4's
   ``STATUSTEXT`` before anything else happens, so there is no race in THIS trial).
2. The GCS then calls ``enable_signing`` so every further message it sends (heartbeats,
   and the one legitimate re-send of the proven-accepted force-disarm command) is really
   signed (HMAC-SHA256, matching PX4's own algorithm).
3. The SAME informed-impersonation attack as the P2 batch (``CommandInjectionAttack``,
   ``rogue_sysid=255, rogue_compid=190, seq_policy="track_identity"``) runs unchanged,
   still forging an UNSIGNED frame (it has no key -- this attack is about impersonating an
   identity, not about forging a valid signature, which it structurally cannot do without
   the secret). Claim class: command-path effect (SITL) -- does PX4 still accept it?
   Piggybacked on an INERT, always-unsigned third client's heartbeat (sysid 253/compid
   192, same convention as the earlier P2 command-injection batch) rather than the GCS's
   own traffic -- the attack hook never piggybacks on an already-signed carrier (fail
   closed, by design, see ``CommandInjectionAttack``'s own docstring), and the real GCS's
   traffic is now signed, so the attack needs an unsigned carrier to ride on at all; this
   is purely about DELIVERING the forged frame to PX4, not part of what is being measured.
4. Separately, the legitimate GCS's own SIGNED resend of the same command is sent and its
   ACK is independently confirmed (polled straight off the GCS's own transport, not via
   the attack's ack-watcher, which only watches after its own injection), to confirm
   signing did not also block the real GCS.

This is explicitly a PILOT (n=1): the first live attempt at a brand-new capability, run to
catch harness bugs before any batch, per the same convention as every other first attempt
this Stage-2 effort has used (GPS-drift, injection, drop/delay/replay, impersonation).
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
    write_manifest,
    wsl_ip,
)

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
    MavlinkFrameParser,
    UdpMavlinkTransport,
    send_setup_signing,
)

GCS_SYSID, GCS_COMPID = 255, 190
CARRIER_SYSID, CARRIER_COMPID = 253, 192  # inert, always-unsigned -- delivery only, see module docstring
SECRET_KEY = bytes(range(1, 33))  # arbitrary, fixed for reproducibility -- NOT security-sensitive (test only)
ONSET_S, BURST_COUNT, GAP_S = 8.0, 2, 1.5


def main(argv: list[str] | None = None) -> int:
    ap = build_argparser(__doc__, default_seconds=45.0)
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not refuse_if_exists(out, (".frames.jsonl", ".manifest.json", ".log.jsonl")):
        return 2

    px4_host = a.px4_host or wsl_ip()
    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    params = _Params(trial_seed=a.seed, trial_index=a.trial_index, onset_s=ONSET_S,
                     burst_count=BURST_COUNT, inter_injection_gap_s=GAP_S)
    # target_sysid/compid passed explicitly: once signing is active PX4 signs ALL its own
    # outgoing traffic (SIGN_OUTGOING is set link-wide, not just for what it receives), so
    # the attack's usual passive-learn-from-an-unsigned-PX4-heartbeat path (deliberately
    # fail-closed on a signed frame it does not verify) would never fire post-signing --
    # found live by this trial's first attempt (frames_injected stayed 0); documented, not
    # a harness bug to hide, and irrelevant to what THIS experiment measures (PX4's own
    # acceptance of an unsigned forged command), so bypassed here rather than "fixed".
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

    port = relay.downstream.local_address[1]
    gcs = UdpMavlinkTransport(connect=("127.0.0.1", port), gcs_heartbeat=False, gcs_sysid=GCS_SYSID,
                              gcs_compid=GCS_COMPID)
    gcs.start()
    carrier = UdpMavlinkTransport(connect=("127.0.0.1", port), gcs_heartbeat=True, heartbeat_hz=1.0,
                                  gcs_sysid=CARRIER_SYSID, gcs_compid=CARRIER_COMPID)
    carrier.start()
    time.sleep(1.0)

    sent, seq = send_setup_signing(gcs, PX4_VEHICLE_SYSID, PX4_VEHICLE_COMPID, SECRET_KEY, initial_timestamp=1000)
    record("setup_signing_sent", sent=sent, seq=seq)
    time.sleep(1.0)  # let PX4 process + broadcast its STATUSTEXT before anything else happens
    gcs.enable_signing(SECRET_KEY, initial_timestamp=1000)
    record("gcs_signing_enabled")

    # Start the GCS's own heartbeat loop only AFTER signing is enabled, so every heartbeat this
    # trial ever sends from the legitimate identity is genuinely signed, not a mix.
    gcs._hb_enabled = True
    import threading

    hb_thread = threading.Thread(target=gcs._hb_loop, daemon=True)
    hb_thread.start()

    # one legitimate, SIGNED resend of the proven-accepted command
    sent, seq = gcs.send_gcs_message(lambda m: m.command_long_encode(
        PX4_VEHICLE_SYSID, PX4_VEHICLE_COMPID, DEFAULT_COMMAND, 0, *DEFAULT_COMMAND_PARAMS))
    record("legit_signed_command_sent", sent=sent, seq=seq)

    # independently confirm its ack straight off the GCS's own receive queue -- never via the
    # attack's ack-watcher, which only starts watching after ITS OWN injection (none expected here)
    legit_parser = MavlinkFrameParser()
    legit_ack: dict | None = None
    deadline = time.monotonic() + a.seconds
    while time.monotonic() < deadline:
        time.sleep(0.5)
        if legit_ack is None:
            for _, raw in gcs.poll():
                for env in legit_parser.parse(raw, time.monotonic()):
                    if env.msgname == "COMMAND_ACK" and env.fields.get("command") == int(DEFAULT_COMMAND):
                        legit_ack = {"result": env.fields.get("result"), "signed": env.signed}
                        record("legit_command_ack_observed", **legit_ack)
    gcs.close()
    carrier.close()
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
        claim_class="command-path effect (SITL): does PX4 still accept the unsigned forged command once "
                    "signing is active (P4 after), contrasted with the P2 impersonation batch's 10/10 ACCEPTED (before)",
        environment="SITL", attack_action="injected",
        parameters={"onset_s": ONSET_S, "burst_count": BURST_COUNT, "inter_injection_gap_s": GAP_S,
                   "seq_policy": "track_identity", "signing_secret_key_sha256": __import__("hashlib")
                   .sha256(SECRET_KEY).hexdigest()},
        attack_start_utc=datetime.now(UTC).isoformat(), attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped, frames_injected=attack.frames_injected,
        expected_effect={"hypothesis_fixed_before_running":
                         "with signing active, PX4 should no longer dispatch/accept the unsigned forged "
                         "COMMAND_LONG (not on PX4's own unsigned-message allowlist) -- expect no "
                         "MAV_RESULT_ACCEPTED for the forged command, while the legitimate SIGNED resend "
                         "is still accepted. This is a PILOT (n=1): the hypothesis is recorded, not yet "
                         "validated at the n=10 design floor."},
        actual_effect=effect, frames_skipped_signed=attack.frames_skipped_signed,
    )
    write_manifest(out, manifest, prov["full_provenance"],
                   {"relay_stats": relay.stats, "event_log": log, "legit_signed_command_ack": legit_ack})
    print(json.dumps({"relay_stats": relay.stats, "actual_effect": effect, "legit_signed_command_ack": legit_ack},
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
