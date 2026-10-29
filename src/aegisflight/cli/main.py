"""AegisFlight command-line interface (the ``aegis`` entry point).

Subcommands:
    aegis simulate    run one telemetry session through the IDS and print results
    aegis benchmark   run the full detection benchmark -> artifacts/
    aegis train       train the anomaly model on benign flights
    aegis serve       start the FastAPI backend (live dashboard API + WebSocket)
    aegis verify-log  verify a SQLite event log's SHA-256 hash chain
    aegis version     print version

Run ``aegis <cmd> -h`` for per-command options.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path

from .. import __version__


def _cmd_simulate(args: argparse.Namespace) -> int:
    from ..benchmark.runner import run_session
    from ..config import load_config
    from ..logging import EventStore
    from ..metrics import evaluate

    cfg = load_config()
    model = None if args.no_model else args.model
    print(f"Simulating scenario='{args.attack}' seed={args.seed} route={args.route or 'default'} "
          f"model={'off' if model is None else model}")
    res = run_session(cfg, args.attack, seed=args.seed, route=args.route, model_path=model)

    alerts = [a for a in res.assessments if a.is_alert]
    scored = [r for r in res.records if r.scored]
    ev = evaluate([r.true_label for r in scored], [r.pred_label for r in scored])

    print(f"\nDecisions: {res.n_decisions}  messages: {res.n_messages}  "
          f"throughput: {res.throughput_msgs_per_s:.0f} msg/s")
    if args.attack not in ("benign", "none"):
        print(f"Attack window: {res.window[0]:.0f}-{res.window[1] if res.window[1] < 1e17 else 'end'}s"
              f"  time-to-detect: {res.time_to_detect_s}s  recall: {ev.binary.recall:.2f}")
    print(f"FPR (this session): {ev.binary.fpr:.3f}")
    print(f"\nAlerts raised: {len(alerts)}")
    for a in alerts[:8]:
        print(f"  t={a.t:6.1f}s  {a.severity.value:9} {a.attack_type.value:22} "
              f"score={a.threat_score:.2f} conf={a.confidence:.2f}")
        for e in a.evidence[:2]:
            print(f"           └─ {e}")

    if args.db:
        store = EventStore(args.db)
        run_id = f"{args.attack}-{args.seed}"
        store.start_run(run_id, label=args.attack)
        for a in alerts:
            store.log_event(a, run_id)
        cs = store.verify_chain(run_id)
        print(f"\nLogged {len(alerts)} alerts to {args.db} (run={run_id}); "
              f"chain: {'OK' if cs.ok else 'BROKEN'} ({cs.length} events)")
        store.close()
    return 0


def _cmd_benchmark(args: argparse.Namespace) -> int:
    from ..benchmark.harness import run_benchmark
    from ..config import load_config

    cfg = load_config()
    model = None if args.no_model else args.model
    result = run_benchmark(cfg, seeds=args.seeds, model_path=model, out_dir=args.out)
    b = result["binary"]
    print(f"accuracy={b['accuracy']} recall={b['recall_tpr']} FPR={b['fpr']} F1={b['f1']}")
    if not args.no_figures:
        from ..benchmark import plots
        plots.generate_all(cfg, result, "artifacts/figures")
    print(f"Artifacts -> {args.out}/")
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    # scripts/ is not an importable package, so the trainer logic is inlined
    # here (kept in sync with scripts/train_models.py).
    import platform as _pf
    from datetime import UTC, datetime
    from pathlib import Path

    import joblib
    import numpy as np
    import sklearn
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    from ..benchmark.dataset import collect_benign_dataset
    from ..config import load_config
    from ..detectors.anomaly import combined_anomaly_raw
    from ..features.extractor import ML_FEATURES

    cfg = load_config()
    acfg = cfg.detector["anomaly"]
    ds = collect_benign_dataset(cfg, n_sessions=args.sessions, seed=args.seed)
    split = ds.split_by_session(seed=args.seed)
    Xtr, Xva = split["train"], split["val"]
    scaler = StandardScaler().fit(Xtr)
    model = IsolationForest(n_estimators=int(acfg["n_estimators"]),
                            contamination=float(acfg["contamination"]),
                            random_state=args.seed, n_jobs=-1).fit(scaler.transform(Xtr))
    Xtr_s = scaler.transform(Xtr)
    iso = -model.score_samples(Xtr_s)
    maha = np.linalg.norm(Xtr_s, axis=1)
    bundle = {"model": model, "scaler": scaler, "feature_names": list(ML_FEATURES),
              "iso_mean": float(iso.mean()), "iso_std": float(iso.std() or 1e-3),
              "maha_mean": float(maha.mean()), "maha_std": float(maha.std() or 1e-3)}
    va = combined_anomaly_raw(bundle, Xva)
    bundle["score_thr"] = float(va.mean() + 3.0 * va.std())
    bundle["score_scale"] = float(max(va.std(), 1e-3))
    bundle["metadata"] = {"created": datetime.now(UTC).isoformat(),
                          "sklearn_version": sklearn.__version__,
                          "python_version": _pf.python_version(), "seed": args.seed,
                          "n_sessions": args.sessions}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.out)
    print(f"Trained on {len(Xtr)} benign vectors; saved -> {args.out}")
    return 0


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def _serve_env(spec, args: argparse.Namespace) -> dict[str, str]:
    """Every ``AEGIS_*`` key the app reads (``backend/sources.py:spec_from_env``, ``backend/app.py``), ALL set,
    so a stale variable in the operator's shell can never change the source."""
    return {
        "AEGIS_SOURCE": spec.kind, "AEGIS_SERIAL_PORT": spec.port or "", "AEGIS_BAUD": str(spec.baud),
        "AEGIS_ALLOW_URL": "1" if spec.allow_url else "0", "AEGIS_TLOG": spec.tlog or "",
        "AEGIS_REPLAY_SPEED": repr(spec.speed), "AEGIS_UDP_PORT": str(spec.udp_port or ""),
        "AEGIS_CONFIG_DIR": spec.config_dir or "", "AEGIS_ML": "",  # "" -> SourceSpec default (SIM only)
        "AEGIS_RECONNECT": "1" if spec.reconnect else "0", "AEGIS_DB": args.db or "",
        "AEGIS_SERVE_HOST": args.host,
        "AEGIS_GCS_NOTIFY": "1" if getattr(args, "gcs_notify", False) else "0",
        "AEGIS_GCS_NOTIFY_HOST": getattr(args, "gcs_notify_host", "127.0.0.1"),
        "AEGIS_GCS_NOTIFY_PORT": str(getattr(args, "gcs_notify_port", 14550)),
        "AEGIS_DEFENSE_MODE": spec.defense_mode,
    }


def _cmd_serve(args: argparse.Namespace) -> int:
    from ..backend.sources import SourceSpec

    try:  # validated before anything starts: a bad source is an error, never a silent SIM fallback
        spec = SourceSpec(kind=args.source, port=args.serial_port, baud=args.baud, allow_url=args.allow_url,
                          tlog=args.tlog, speed=args.replay_speed, udp_port=args.udp_port,
                          config_dir=args.config_dir, reconnect=not args.no_reconnect,
                          defense_mode=args.defense_mode,
                          gcs_notify=args.gcs_notify, gcs_notify_host=args.gcs_notify_host,
                          gcs_notify_port=args.gcs_notify_port,
                          signing_key_file=getattr(args, "signing_key_file", None))
        if spec.signing_key_file:
            from ..detectors.crossend import load_signing_key

            try:
                load_signing_key(spec.signing_key_file)
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"bad --signing-key-file: {exc}") from exc
    except ValueError as exc:
        print(f"aegis serve: {exc}", file=sys.stderr)
        return 2
    if spec.kind != "sim":
        if args.reload:  # the reloader restarts the worker on every edit, re-opening the source each time
            print("aegis serve: --reload is simulation-only", file=sys.stderr)
            return 2
        if args.host not in _LOOPBACK_HOSTS:  # live telemetry (possibly a real position) stays on this machine
            print(f"aegis serve: a {spec.environment} source is served on loopback only (--host 127.0.0.1)",
                  file=sys.stderr)
            return 2
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed", file=sys.stderr)
        return 1
    os.environ.update(_serve_env(spec, args))
    # kept out of _serve_env (its key set is fixed); a stale shell value is cleared when no key is given
    if spec.signing_key_file:
        os.environ["AEGIS_SIGNING_KEY_FILE"] = spec.signing_key_file
    else:
        os.environ.pop("AEGIS_SIGNING_KEY_FILE", None)
    print(f"aegis serve: source {spec.environment} ({spec.describe()['label']}) on http://{args.host}:{args.port}")
    uvicorn.run("aegisflight.backend.app:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def _cmd_ips_bridge(args: argparse.Namespace) -> int:
    """Run the inline IPS bridge between a flight controller port and a GCS/radio port."""
    import json
    import time

    from ..hal.inline_ips import InlineIpsBridge
    from ..sources.mavlink_serial import SerialMavlinkTransport

    if args.fc_port == args.gcs_port:
        print("aegis ips-bridge: --fc-port and --gcs-port must differ", file=sys.stderr)
        return 2
    try:
        fc = SerialMavlinkTransport(args.fc_port, baudrate=args.fc_baud, allow_url=args.allow_url,
                                    accept_unverified_ids=True)
        gcs = SerialMavlinkTransport(args.gcs_port, baudrate=args.gcs_baud, allow_url=args.allow_url,
                                     accept_unverified_ids=True)
    except ValueError as exc:
        print(f"aegis ips-bridge: {exc}", file=sys.stderr)
        return 2
    key = None
    if args.signing_key_file:
        try:
            raw = Path(args.signing_key_file).read_bytes()
            key = raw if len(raw) == 32 else bytes.fromhex(raw.decode("ascii").strip())
            if len(key) != 32:
                raise ValueError("key must be 32 bytes")
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            print(f"aegis ips-bridge: bad --signing-key-file: {exc}", file=sys.stderr)
            return 2
    if args.defense_mode == "active-ips" and key is None and not args.allow_unsigned:
        print("aegis ips-bridge: refusing --defense-mode active-ips without --signing-key-file: an unsigned link "
              "cannot stop a counter-tracking forger. Provision a key, or pass --allow-unsigned to accept the risk.",
              file=sys.stderr)
        return 2
    token = None
    if args.control_token_file:
        try:
            token = Path(args.control_token_file).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            print(f"aegis ips-bridge: bad --control-token-file: {exc}", file=sys.stderr)
            return 2
        if not token:
            print("aegis ips-bridge: --control-token-file is empty", file=sys.stderr)
            return 2
    import ipaddress

    status_host = args.status_host
    try:
        loopback = status_host == "localhost" or ipaddress.ip_address(status_host).is_loopback
    except ValueError:
        loopback = False
    if not loopback and token is None:
        print(f"aegis ips-bridge: refusing --status-host {status_host}: a non-loopback status API requires "
              "--control-token-file", file=sys.stderr)
        return 2
    store = None
    if args.db:
        from ..logging import EventStore

        store = EventStore(args.db)
        run_id = time.strftime("ips-%Y%m%d-%H%M%S")
        store.start_run(run_id, label="ips-bridge")
    else:
        run_id = "ips-bridge"
    bridge = InlineIpsBridge(fc, gcs, config_dir=args.config_dir, mode=args.defense_mode,
                             trusted_sysids=tuple(args.trusted_sysid) if args.trusted_sysid else None,
                             store=store, run_id=run_id, secret_key=key,
                             allow_unsigned_from_trusted=args.signing_permissive,
                             signing_max_age_s=args.signing_max_age_s, signing_state_path=args.signing_state,
                             ekf_secondary=args.ekf_secondary, crossend_interval_s=args.crossend_interval,
                             contested_policy=args.contested_policy, replay_memory=args.replay_memory,
                             on_alarm=lambda m: print(f"aegis ips-bridge: ALARM {m}", flush=True))
    fc.start()
    gcs.start()
    bridge.start()
    status_srv = None
    if args.status_port:
        from ..hal.status_server import BridgeStatusServer

        try:
            status_srv = BridgeStatusServer(
                bridge, args.status_port, host=status_host, control_token=token, signing_configured=key is not None,
                allow_unsigned=args.allow_unsigned and args.defense_mode == "active-ips").start()
            if not loopback:
                print(f"aegis ips-bridge: WARNING status API reachable from the network on {status_host}:"
                      f"{args.status_port} (posture control requires the token)", flush=True)
        except OSError as exc:
            print(f"aegis ips-bridge: cannot bind status port: {exc}", file=sys.stderr)
    print(f"aegis ips-bridge: {args.fc_port} <-> {args.gcs_port}, posture {args.defense_mode}", flush=True)
    if args.defense_mode == "active-ips" and key is None:
        print("aegis ips-bridge: NOTICE active-ips without signing acknowledged via --allow-unsigned", flush=True)
    end = None if args.seconds is None else time.monotonic() + args.seconds
    try:
        while end is None or time.monotonic() < end:
            time.sleep(min(args.status_interval, 0.5) if end is not None else args.status_interval)
            print(json.dumps(bridge.status()), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        if status_srv is not None:
            status_srv.close()
        bridge.close()
        if store is not None:
            store.close()
    return 0


def _cmd_verify_log(args: argparse.Namespace) -> int:
    from ..logging import EventStore

    store = EventStore(args.db)
    cs = store.verify_chain()
    print(f"events: {cs.length}  chain: {'OK' if cs.ok else 'BROKEN'}  {cs.detail}")
    store.close()
    return 0 if cs.ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="AegisFlight UAV IDS")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("simulate", help="run one IDS session and print results")
    s.add_argument("--attack", default="benign",
                   help="benign|gps_spoofing|mavlink_anomaly|command_injection|"
                        "telemetry_manipulation|dos|firmware_integrity")
    s.add_argument("--seed", type=int, default=42)
    s.add_argument("--route", default=None, help="survey_box|out_and_back|perimeter")
    s.add_argument("--model", default="models/isoforest.joblib")
    s.add_argument("--no-model", action="store_true")
    s.add_argument("--db", default=None, help="log alerts to this SQLite path")
    s.set_defaults(func=_cmd_simulate)

    b = sub.add_parser("benchmark", help="run the full detection benchmark")
    b.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5, 6])
    b.add_argument("--out", default="artifacts/benchmarks")
    b.add_argument("--model", default="models/isoforest.joblib")
    b.add_argument("--no-model", action="store_true")
    b.add_argument("--no-figures", action="store_true")
    b.set_defaults(func=_cmd_benchmark)

    t = sub.add_parser("train", help="train the anomaly model")
    t.add_argument("--sessions", type=int, default=24)
    t.add_argument("--out", default="models/isoforest.joblib")
    t.add_argument("--seed", type=int, default=100)
    t.set_defaults(func=_cmd_train)

    sv = sub.add_parser("serve", help="start the FastAPI backend (dashboard API + WebSocket)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--reload", action="store_true", help="SIM only")
    sv.add_argument("--source", choices=["sim", "replay", "serial", "udp"], default="sim",
                    help="telemetry source, fixed for the server's lifetime (default: sim)")
    sv.add_argument("--serial-port", default=None, help="serial: COM7, /dev/ttyAMA0 (receive-only)")
    sv.add_argument("--baud", type=int, default=115200, help="serial: must match the link (115200 on COM7)")
    sv.add_argument("--allow-url", action="store_true", help="serial: allow a socket:// virtual port (REPLAY)")
    sv.add_argument("--no-reconnect", action="store_true",
                    help="serial: a port that cannot be opened is a source error instead of being retried")
    sv.add_argument("--tlog", default=None, help="replay: repo-framed .tlog to replay")
    sv.add_argument("--replay-speed", type=float, default=1.0, help="replay: 1.0 = capture time")
    sv.add_argument("--udp-port", type=int, default=None, help="udp: listen on 127.0.0.1:<port>, passive")
    sv.add_argument("--config-dir", default=None, help="detector profile dir (default: Stage-1 configs/)")
    sv.add_argument("--db", default=None, help="event store (default: artifacts/aegisflight_live.sqlite)")
    sv.add_argument("--gcs-notify", action="store_true",
                    help="broadcast MAVLink STATUSTEXT alert notifications to GCS (UDP or active serial/UDP link)")
    sv.add_argument("--gcs-notify-host", default="127.0.0.1",
                    help="target GCS host for UDP STATUSTEXT alerts (default: 127.0.0.1)")
    sv.add_argument("--gcs-notify-port", type=int, default=14550,
                    help="target GCS UDP port for STATUSTEXT alerts (default: 14550)")
    sv.add_argument("--defense-mode", choices=["passive", "advisory", "active-ips"], default="passive",
                    help="defense engine posture: passive (IDS only, zero bytes sent), advisory (GCS alerts), active-ips (autonomous mitigation)")
    sv.add_argument("--signing-key-file", default=None,
                    help="32-byte MAVLink-2 key (raw or 64 hex chars) used to authenticate the ips-bridge cross-end summary")
    sv.set_defaults(func=_cmd_serve)

    ib = sub.add_parser("ips-bridge", help="inline IPS between a flight controller port and a GCS/radio port")
    ib.add_argument("--fc-port", required=True, help="serial port wired to the flight controller (e.g. /dev/ttyAMA0)")
    ib.add_argument("--fc-baud", type=int, default=921600)
    ib.add_argument("--gcs-port", required=True, help="serial port wired to the GCS radio (e.g. /dev/ttyUSB0)")
    ib.add_argument("--gcs-baud", type=int, default=57600)
    ib.add_argument("--allow-url", action="store_true", help="allow socket:// virtual ports (tests, SITL)")
    ib.add_argument("--defense-mode", choices=["passive", "advisory", "active-ips"], default="passive",
                    help="passive/advisory forward every frame byte-identically; active-ips filters and counter-acts")
    ib.add_argument("--trusted-sysid", type=int, action="append",
                    help="ground-station sysid allowed to command the vehicle (repeatable; default from detector.yaml)")
    ib.add_argument("--signing-key-file", default=None,
                    help="32-byte MAVLink-2 signing key (raw, or 64 hex chars). With it, control traffic must be validly "
                         "signed with an increasing timestamp; counter-frames are signed too")
    ib.add_argument("--signing-permissive", action="store_true",
                    help="rollout only: let UNSIGNED control frames from a trusted sysid through (forged or replayed "
                         "signed frames are still dropped)")
    ib.add_argument("--signing-max-age-s", type=float, default=None,
                    help="also reject signed frames older than this on the bridge clock (needs a correct clock)")
    ib.add_argument("--signing-state", default=None,
                    help="file that keeps the last timestamp per stream across restarts (closes the post-restart replay window)")
    ib.add_argument("--ekf-secondary", action="store_true",
                    help="declare that the aircraft has a configured non-GPS EKF source set; only then may active-ips "
                         "send the EKF source switch (default off: GPS faults escalate to ALT_HOLD instead)")
    ib.add_argument("--crossend-interval", type=float, default=1.0,
                    help="seconds between cross-end summaries of the last forwarded GLOBAL_POSITION_INT sent to the GCS "
                         "side only (0 = off); lets a GCS-side 'aegis serve' detect telemetry altered after the bridge")
    ib.add_argument("--contested-policy", choices=["alert", "drop-sensitive"], default="alert",
                    help="unsigned link, two transmitters on one sysid: alert = STATUSTEXT only; drop-sensitive = also drop "
                         "sensitive/control frames from that source in flight (can block the real pilot; forced disarm passes)")
    ib.add_argument("--replay-memory", type=int, default=4096,
                    help="unsigned link: number of forwarded sensitive frames remembered for the byte-identical replay filter")
    ib.add_argument("--config-dir", default=None)
    ib.add_argument("--db", default=None, help="log alerts to this SQLite hash-chain store")
    ib.add_argument("--seconds", type=float, default=None, help="run time (default: until Ctrl-C)")
    ib.add_argument("--status-interval", type=float, default=5.0)
    ib.add_argument("--status-port", type=int, default=0,
                    help="serve GET /status (bridge state as JSON) on 127.0.0.1:PORT, read-only (default: off)")
    ib.add_argument("--allow-unsigned", action="store_true",
                    help="acknowledge that active-ips without --signing-key-file cannot stop a counter-tracking forger")
    ib.add_argument("--control-token-file", default=None,
                    help="file holding a token; enables remote posture control (POST /posture) on the status API")
    ib.add_argument("--status-host", default="127.0.0.1",
                    help="bind address of the status API (default 127.0.0.1; non-loopback needs --control-token-file)")
    ib.set_defaults(func=_cmd_ips_bridge)

    v = sub.add_parser("verify-log", help="verify a SQLite event-log hash chain")
    v.add_argument("db", help="path to the SQLite event log")
    v.set_defaults(func=_cmd_verify_log)

    ver = sub.add_parser("version", help="print version")
    ver.set_defaults(func=lambda a: (print(f"aegisflight {__version__}"), 0)[1])

    return p


def main(argv: list[str] | None = None) -> int:
    # Evidence strings use unicode (≥, °, ²); ensure the console can print them
    # on Windows (cp1252 default) without crashing.
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
