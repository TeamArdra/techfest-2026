"""Run ONE trial of the third P2 live attack (downlink GPS-channel drop -- suppress all
GLOBAL_POSITION_INT and GPS_RAW_INT frames from PX4 for a window, docs/ATTACK_PROXY.md
order item 3; ``src/aegisflight/proxy/attacks_live_dos_replay.py`` ``DropAttack``) through
the ``MavlinkRelay`` against a local PX4 SITL.

    .venv/Scripts/python.exe scripts/sitl/run_p2_drop_trial.py --px4-port 18572 \
        --seed 3001 --out artifacts/sitl/p2d_trial_001

Topology:
    PX4 SITL (WSL, GCS link) <-> MavlinkRelay <-down_hook=DropAttack--
        downstream clients: this script's own IDS tap (LiveMavlinkSource over the
        relay's loopback port)

Environment: SITL. Attack: the proxy-level downlink suppression ONLY -- PX4 never
receives anything different (the relay's up_hook stays passthrough; only down_hook runs
the attack). Claim class: link-level detection (SITL) at most -- PX4 itself is the
sender of the suppressed frames and is mechanically unaffected by their absence on the
wire toward the IDS/GCS. This does NOT show vehicle trajectory deviation, GPS spoofing
of PX4's estimator, or anything about MAVLink signing.

Writes, per trial: manifest.json + frames.jsonl (proxy/groundtruth.py schema, ground
truth authored by the attack hook itself, never from detector output) and
ids_decisions.jsonl / ids_ingest.jsonl (the Stage-1 IDSPipeline's decisions and raw
message ingest on the IDS tap) -- joined post-hoc, not written here.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from p2_trial_common import (
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
    DropAttack,
    FrameLogWriter,
    Manifest,
    compute_drop_effect,
    draw_drop_params,
)
from aegisflight.proxy.transport import make_udp_relay
from aegisflight.sources.mavlink_live import LiveMavlinkSource, UdpMavlinkTransport


def main(argv: list[str] | None = None) -> int:
    ap = build_argparser(__doc__, default_seconds=90.0)
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not refuse_if_exists(out, (".frames.jsonl", ".manifest.json", ".ids_decisions.jsonl", ".ids_ingest.jsonl")):
        return 2

    px4_host = a.px4_host or wsl_ip()
    params = draw_drop_params(a.seed, a.trial_index)

    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    attack = DropAttack(params, frame_log=frame_log)
    relay = make_udp_relay(px4_host, a.px4_port, a.relay_listen_port, down_hook=attack)
    relay.start()
    if not relay.wait_upstream_alive(timeout=15.0):
        relay.close()
        frame_log.close()
        print("ERROR: PX4 never answered the relay's heartbeat within 15s", file=sys.stderr)
        return 2

    ids_transport = UdpMavlinkTransport(connect=("127.0.0.1", relay.downstream.local_address[1]), gcs_heartbeat=True)
    ids_transport.start()
    try:
        model, model_choice = resolve_model(a.profile, a.model)
    except SystemExit as exc:
        relay.close()
        frame_log.close()
        return int(exc.code or 2)
    cfg = load_config(a.profile or None)
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

    actual = compute_drop_effect(out.with_suffix(".frames.jsonl"))
    prov = provenance_block("Ubuntu-24.04", "/home/astryx/PX4-Autopilot",
                            {"python_version": sys.version.split()[0]})

    manifest = Manifest(
        trial_id=out.name, seed=a.seed, trial_index=a.trial_index, provenance=prov["provenance"],
        attack_type="MAVLINK_ANOMALY", attack_mode="gps_channel_drop_live",
        message_type="GLOBAL_POSITION_INT+GPS_RAW_INT", target_system=0, target_component=0,
        injection_point="downlink", claim_class="link-level detection (SITL)", environment="SITL",
        attack_action="dropped",
        parameters={"onset_s": params.onset_s, "duration_s": params.duration_s,
                   "detector_profile": a.profile or "stage1_default", "model_choice": model_choice},
        attack_start_utc=started, attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped, frames_injected=attack.frames_injected,
        expected_effect={"feature": "gps_age_s", "detector": "protocol (gps dropout, threshold 2.0s)",
                        "predicted_detection": "dos-style attack_type (hypothesis, not asserted)"},
        actual_effect=actual, frames_skipped_signed=attack.frames_skipped_signed,
    )
    write_manifest(out, manifest, prov["full_provenance"],
                   {"decisions": n_decisions, "threat_decisions": n_threats, "source_stats": ids_stats,
                    "relay_stats": relay.stats})
    print(json.dumps({"frames_seen": attack.frames_seen, "frames_dropped": attack.frames_dropped,
                      "actual_effect": actual, "ids_decisions": n_decisions, "ids_threat_decisions": n_threats,
                      "relay_stats": relay.stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
