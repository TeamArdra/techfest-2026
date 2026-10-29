# AegisFlight — Testing & Quality Assurance

```
        ╱ e2e (2) ╲             full slice: sim→IDS→IPS→SQLite hash chain verify
       ╱ backend (5)╲           FastAPI API + live telemetry + defense endpoints
      ╱ integration (90+)╲      20 attack modes, proxy attacks, presence policies
     ╱      unit (600+)     ╲   geo/config/simulator/codec/integrity/logging/
    ╱────────────────────────╲  fusion/mitigation/hal/serial/metrics
```
Run with the project venv; the suite must pass in full (the count grows with new
features — `pytest -q` prints it). The pyramid above shows the Stage-1 layout and its
historic counts.

**Latest full run (2026-10-29, hardware-free sprint, branch `sprint/hardware-free-20261029` from `docs/submission-readiness-20261029` d0d134b plus uncommitted sprint changes):** 907 passed, 3 skipped, 0 failed, 910 collected
(`tests/unit` 811 incl. the 8 label-independence tests, `tests/integration` 92, `tests/e2e` 2, `backend/tests` 5), 155.3 s; frontend 11 passed; saved in
`artifacts/validation/submission_rerun_20261029/test_suite_run.json`. The run below it (899 / 902) is the previous one on the same branch family.

**Previous full run (2026-10-29, branch `docs/submission-readiness-20261029`, `evidence/gps-hw-verify-20261029` c849012 plus the passive GPS-health change):** 899 passed, 3 skipped, 0 failed, 902 collected
(`tests/unit` 803, `tests/integration` 92, `tests/e2e` 2, `backend/tests` 5; the 3 skips are POSIX PTY tests in `tests/unit/test_mavlink_serial.py`), 149.6 s,
same command as below. +16 tests: `tests/unit/test_gps_health.py` (13), `tests/unit/test_run_serial_ids.py` (+3). Frontend: `npm --prefix frontend test` 10 passed (+2),
`npm --prefix frontend run build` ok. Stage-1 regression (`aegis benchmark --out <scratch> --no-figures`): 6535 / 4 / 16826 / 65, 378 of 378 non-timing cells equal.
`test_tlog_tees_the_clean_downlink_and_stays_receive_only` was flaky (it asserted the first loopback frame; passed 4 of 8 isolated runs on the **unmodified** HEAD and 5 of 8 on this tree,
because the transport purges input at open); it now tolerates up to 3 lost head frames and passes 14 of 14.

**Previous full run (2026-10-29, `main` a44dd9c plus the `--tlog` change to `run_serial_ids.py` and its 2 tests):** 883 passed, 3 skipped (POSIX PTY tests, skipped on Windows), 0 failed
(`.venv/Scripts/python.exe -m pytest -p no:cacheprovider -o addopts="" -q -rfE`, 155 s). The 2026-10-26 run on the pre-integration tree was 809 passed.
- Tree: the GPS iteration-2 tree, `HEAD` `90b9aa2` + uncommitted changes, `src`+`configs` diff sha256 `b4d434e3…7eaf`.
- Run by the lead with `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -o addopts="" -q -rfE` from the repo
  root (Windows, Python 3.13.15).
- `tests/unit/test_gps_scenarios_fused.py` collects 79 tests: 59 `GENUINE` and 20 `KNOWN LIMITATION` by first
  docstring label. One is mixed: `test_fix_degradation_…_after_the_debounce` is GENUINE after the debounce and a
  KNOWN LIMITATION inside it.
The suite covers raw serial framing and MAVLink parsing up to the SIM-only defense layer and the SQLite hash chain; `pytest -q` prints the current count.

## Test Commands
| Command | Purpose | Typical Runtime |
|---|---|---|
| `python scripts/verify_stage2.py` | Demo of the 8 defense code paths on hand-built inputs (SIM; not validation evidence) | seconds |
| `pytest tests/unit/test_mitigation.py tests/unit/test_hal.py` | Core Stage 2 autonomous defense and HAL tests | < 2 s |
| `pytest tests/unit -q` | Fast unit test suite (600+ tests) | ~15 s |
| `pytest tests/integration -q` | Multi-mode attack detection and pipeline tests | ~30 s |
| `pytest tests/e2e -q` | Full end-to-end slice with SHA-256 ledger check | ~10 s |
| `pytest` | Complete verification suite (`pytest -q` prints the count) | ~2.5 min |
| `ruff check src tests scripts` | Code quality and linting | < 1 s |

## What Each Suite Verifies

### Stage 2 Autonomous Prevention & HAL
- **`test_mitigation.py` (27 tests)**:
  - `GoldenFlightState`: dead-reckoning during GPS loss/spoofing, speed/attitude isolation during telemetry attacks, clean GPS anchoring during non-GPS attacks.
  - `FrameSanitizer`: coordinate clamping, altitude correction, CUSUM micro-drift tracking, frame dropping for quarantined sysids.
  - Command-injection playbook: mid-air disarm and mode-change provenance are flagged and reported (not blocked).
  - Command cadence check in `AttackSubModeClassifier`: flags burst and replayed commands.
  - `MitigationController`: closed-loop response generation per attack sub-mode, state machine, recovery.
- **`test_hal.py` (7 tests)**:
  - Hardware discovery across USB/serial ports (CubePilot, Pixhawk, SiK telemetry, ELRS).
  - Platform and companion compute detection (Raspberry Pi, Jetson, Rockchip).
  - Dynamic latency budgeting (15 ms to 65 ms).
  - Dual-topology routing: auto-selection of Topology B vs Topology A vs A+B.
  - `InlineBridge` packet processing and 150 ms fail-open watchdog timer.
- **`test_gcs_notifier.py` (4 tests)**:
  - MAVLink `STATUSTEXT` packet generation with severity levels and rate limiting.

### Core detection suites (Stage 1 + GPS workstream)
- **`test_geo`** — haversine/offset/bearing/wrap round-trips.
- **`test_config`** — defaults, YAML-over-defaults merge, missing-file resilience.
- **`test_simulator`** — determinism, tick count, reaches cruise & lands (all
  routes), speed bounds, position↔velocity consistency, battery reserve.
- **`test_mavlink_codec`** — all six message types encode/decode; position
  round-trips within noise; independent GPS/baro altitude channels; vehicle ids.
- **`test_integrity_and_logging`** — SHA-256 valid→tamper→detect, missing
  component; hash-chain intact, tamper detection (`broken_at`), multi-run
  independence.
- **`test_fusion_and_metrics`** — lone firmware triggers, lone weak ML doesn't,
  strong physics attributes correctly, all-benign is NORMAL; metrics maths.
- **`test_pipeline`** (integration) — benign FPR 0; each attack recall ≥ 0.85 and
  attributed to the right class (ML off, so it's a floor not the headline).
- **`test_end_to_end`** — GPS spoof → alerts with evidence → SQLite → chain OK;
  compute p95 < 50 ms.
- **`test_api`** (backend) — health/status/config; live GPS injection detected;
  unknown attack rejected (400); metrics/events.
- **`test_missing_telemetry_fused`** / **`test_gps_scenarios_fused`** — the real
  `IDSPipeline` (ML off) on synthetic MAVLink. The first file covers GPS *availability*:
  never received, fix never acquired or lost, dropout. The second covers GPS *content* on a
  moving vehicle (and on a stationary one with GNSS wander):
  - position jump, position vs velocity mismatch, GPS vs VFR speed;
  - the drift-rate floor and recovery;
  - tests marked `KNOWN LIMITATION` that pin missed slow or velocity-consistent drift, and
    the false alarms from stationary GNSS wander on a link without estimator status;
  - estimator state (`EKF_STATUS_REPORT`, gate v2): benign cases 1–8 (wander with CONST_POS,
    healthy movement, fix loss and recovery including the 2 s debounce cost, stale / missing /
    contradictory status, a same-tick burst of reports applied in arrival order, reset jumps on
    and after the transition fix) and adversarial cases 9–17 (jumps, zero-velocity divergence,
    speed mismatch, drift above, at and below the floor, velocity-consistent drift, constant
    offset, plausible GNSS quality, stripped or falsified status);
  - the review probes P1–P4 (sustained forged CONST_POS with a zero-velocity walk, a frozen
    position on a moving vehicle, a single forged report at a 500 m jump, a jump right after the
    reports stop, flag flipping, sparse reports, a split jump) and status injection on a link that
    never sent it. P1, P4 and the injection case are pinned as `KNOWN LIMITATION`;
  - rule 4 under sustained CONST_POS: a coherent moving track is quiet, a position moving against
    the velocity alerts, and an offset perpendicular to or ahead of the velocity is a pinned
    `KNOWN LIMITATION`;
  - gate-on vs gate-off decision identity without estimator status (and wherever no fix is
    gated), the exact `pos_residual_nav_m == pos_residual_m` property, `FeatureExtractor.reset()`,
    the debounce's float tolerance, the navigation line only on decisions where physics scored 0,
    and the fusion evidence order (only score-0 physics evidence moves last);
  - one ML-on `KNOWN LIMITATION` test (skipped without the git-ignored `models/isoforest.joblib`):
    the gate covers the physics rule only;
  - each test's docstring says whether it should alert, emit the degraded-navigation line, or
    stay quiet, and why. All of these are SIM;
  - two REPLAY-of-BENCH tests that run the saved Pixhawk 6X captures 008/009 when the
    git-ignored tlogs are present locally (skipped otherwise). They are in-sample: the gate was
    designed from these captures.

### Detection, Ingest & Protocols
- **`test_mavlink_codec.py` & `test_mavlink_serial.py`**: MAVLink v2 encode/decode, X.25 CRC-16 computation, framing recovery, baud rate handling, dropped byte resilience.
- **`test_proxy_*.py`**: Live proxy attack injection across 20 sub-modes (gradual drift, freeze, telemetry mutation, command injection, DoS flood).
- **`test_fusion_and_metrics.py`**: Noisy-OR evidence fusion, weighted attribution, threshold hysteresis, metric calculations.
- **`test_integrity_and_logging.py`**: SHA-256 firmware manifest verification, SQLite tamper-evident rolling block hash chain verification (`broken_at` detection).

## Pre-Release Gate
```bash
ruff check src tests scripts backend         # clean (0 errors)
pytest                                       # full suite, 0 failed
aegis benchmark --out <scratch> --no-figures # Stage-1 regression: TP/FP/TN/FN must equal artifacts/benchmarks
```
`scripts/verify_stage2.py` is a demo on hand-built inputs; it is not part of the gate.
