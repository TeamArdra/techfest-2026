"""Run ONE trial of the fifth P2 live attack (downlink GNSS fix-quality degradation --
``GPS_RAW_INT.fix_type``/``satellites_visible`` rewritten below the protocol rule's thresholds
for a window; ``src/aegisflight/proxy/attacks_live.py`` ``GnssDegradationAttack``) through the
``MavlinkRelay`` against a local PX4 SITL.

    .venv/Scripts/python.exe scripts/sitl/run_p2_gnss_trial.py --px4-port 18572 \
        --seed 7001 --out artifacts/sitl/p2n_trial_001

Topology (same as ``run_p2_drop_trial.py``):
    PX4 SITL (WSL, GCS link) <-> MavlinkRelay <-down_hook=GnssDegradationAttack--
        downstream clients: this script's own IDS tap (LiveMavlinkSource over the
        relay's loopback port)

Environment: SITL. Attack: proxy-level modification of the downlink ONLY -- PX4 never receives
anything different (the relay's up_hook stays passthrough) and its estimator is untouched; the
vehicle is disarmed on the ground (no flight driver), so the downlink carries a static-vehicle
stream. Claim class: link-level detection (SITL) at most. This does NOT show GNSS jamming of
PX4, an estimator compromise, or a physical deviation, and says nothing about MAVLink signing.

Hypotheses (written BEFORE any live run, see ``expected_effect`` in the manifest and
``make_p2n_summary.py``): the unchanged protocol GNSS-fix-loss rule (min_gnss_fix_type=3,
min_gnss_satellites=5, gnss_loss_ticks=5, none overridden by ``configs/px4_sitl``) fires a
DOS-typed "GNSS fix lost" within a few seconds of onset; no such evidence before onset.

Writes, per trial: manifest.json + frames.jsonl (proxy/groundtruth.py schema, ground truth
authored by the attack hook itself, never from detector output) and ids_decisions.jsonl.
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
    FrameLogWriter,
    GnssDegradationAttack,
    Manifest,
    compute_gnss_degradation_effect,
    draw_gnss_degradation_params,
)
from aegisflight.proxy.transport import make_udp_relay
from aegisflight.sources.mavlink_live import LiveMavlinkSource, UdpMavlinkTransport


def main(argv: list[str] | None = None) -> int:
    ap = build_argparser(__doc__, default_seconds=100.0)
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not refuse_if_exists(out, (".frames.jsonl", ".manifest.json", ".ids_decisions.jsonl")):
        return 2

    px4_host = a.px4_host or wsl_ip()
    params = draw_gnss_degradation_params(a.seed, a.trial_index)

    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    attack = GnssDegradationAttack(params, frame_log=frame_log)
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

    actual = compute_gnss_degradation_effect(out.with_suffix(".frames.jsonl"))
    prov = provenance_block("Ubuntu-24.04", "/home/astryx/PX4-Autopilot",
                            {"python_version": sys.version.split()[0]})

    manifest = Manifest(
        trial_id=out.name, seed=a.seed, trial_index=a.trial_index, provenance=prov["provenance"],
        attack_type="DOS", attack_mode="gnss_fix_degradation_live",
        message_type="GPS_RAW_INT", target_system=0, target_component=0,
        injection_point="downlink", claim_class="link-level detection (SITL)", environment="SITL",
        attack_action="modified",
        parameters={"onset_s": params.onset_s, "duration_s": params.duration_s,
                   "fix_type": params.fix_type, "satellites_visible": params.satellites_visible,
                   "detector_profile": a.profile or "stage1_default", "model_choice": model_choice},
        attack_start_utc=started, attack_end_utc=datetime.now(UTC).isoformat(),
        frames_seen=attack.frames_seen, frames_modified=attack.frames_modified,
        frames_dropped=attack.frames_dropped, frames_injected=attack.frames_injected,
        expected_effect={"feature": "snapshot.gps_fix_type / snapshot.satellites",
                        "detector": "protocol (GNSS fix loss: fix<3 or sats<5 for >=5 consecutive decisions)",
                        "predicted_detection": "DOS-typed 'GNSS fix lost' evidence within seconds of onset "
                                               "(hypothesis, not asserted)"},
        actual_effect=actual, frames_skipped_signed=attack.frames_skipped_signed,
    )
    write_manifest(out, manifest, prov["full_provenance"],
                   {"decisions": n_decisions, "threat_decisions": n_threats, "source_stats": ids_stats,
                    "relay_stats": relay.stats})
    print(json.dumps({"frames_seen": attack.frames_seen, "frames_modified": attack.frames_modified,
                      "actual_effect": actual, "ids_decisions": n_decisions, "ids_threat_decisions": n_threats,
                      "relay_stats": relay.stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
