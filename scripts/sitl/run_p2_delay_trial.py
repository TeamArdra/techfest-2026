"""Run ONE trial of the fourth P2 live attack (downlink hold-and-release delay --
every downlink frame is held for a drawn per-trial delay during a window, then released
byte-identical in original order, docs/ATTACK_PROXY.md order item 5 reordered earlier per
this task; ``src/aegisflight/proxy/attacks_live_dos_replay.py`` ``DelayAttack``) through
the ``MavlinkRelay`` against a local PX4 SITL.

    .venv/Scripts/python.exe scripts/sitl/run_p2_delay_trial.py --px4-port 18572 \
        --seed 4001 --out artifacts/sitl/p2l_trial_001

Topology:
    PX4 SITL (WSL, GCS link) <-> MavlinkRelay <-down_hook=DelayAttack--
        downstream clients: this script's own IDS tap (LiveMavlinkSource over the
        relay's loopback port)

Environment: SITL. Attack: the proxy-level downlink timing manipulation ONLY -- no
frame content is ever changed (bytes released are exactly the bytes received); PX4
itself is unaffected (the relay's up_hook stays passthrough). Claim class: link-level
detection (SITL) at most, and only as a *hypothesis* -- docs/ATTACK_PROXY.md §2 already
flags delay/jitter as sitting close to the benign WSL/Gazebo jitter noise floor, so a
negative (not detected) result is an expected, reportable outcome here, not a failure.

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
    DelayAttack,
    FrameLogWriter,
    Manifest,
    compute_delay_effect,
    draw_delay_params,
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
    params = draw_delay_params(a.seed, a.trial_index)

    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    attack = DelayAttack(params, frame_log=frame_log)
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

    actual = compute_delay_effect(out.with_suffix(".frames.jsonl"))
    prov = provenance_block("Ubuntu-24.04", "/home/astryx/PX4-Autopilot",
                            {"python_version": sys.version.split()[0]})

    manifest = Manifest(
        trial_id=out.name, seed=a.seed, trial_index=a.trial_index, provenance=prov["provenance"],
        attack_type="MAVLINK_ANOMALY", attack_mode="downlink_hold_and_release_live",
        message_type="ALL", target_system=0, target_component=0,
        injection_point="downlink", claim_class="link-level detection (SITL), hypothesis only",
        environment="SITL", attack_action="delayed",
        parameters={"onset_s": params.onset_s, "duration_s": params.duration_s, "delay_s": params.delay_s,
                   "detector_profile": a.profile or "stage1_default", "model_choice": model_choice},
        attack_start_utc=started, attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped, frames_injected=attack.frames_injected,
        expected_effect={"feature": "interarrival_mean_ms", "detector": "protocol (jitter/rate)",
                        "predicted_detection": "may well be a negative result -- see module docstring"},
        actual_effect=actual, frames_skipped_signed=attack.frames_skipped_signed,
    )
    write_manifest(out, manifest, prov["full_provenance"],
                   {"decisions": n_decisions, "threat_decisions": n_threats, "source_stats": ids_stats,
                    "relay_stats": relay.stats, "frames_delayed": attack.frames_delayed})
    print(json.dumps({"frames_seen": attack.frames_seen, "frames_delayed": attack.frames_delayed,
                      "actual_effect": actual, "ids_decisions": n_decisions, "ids_threat_decisions": n_threats,
                      "relay_stats": relay.stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
