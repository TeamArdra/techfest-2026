# AegisFlight — Testing & Quality Assurance

```
        ╱ e2e (2) ╲             full slice: sim→IDS→IPS→SQLite hash chain verify
       ╱ backend (5)╲           FastAPI API + live telemetry + defense endpoints
      ╱ integration (90+)╲      20 attack modes, proxy attacks, presence policies
     ╱      unit (550+)     ╲   geo/config/simulator/codec/integrity/logging/
    ╱────────────────────────╲  fusion/mitigation/hal/serial/metrics
```
The test suite spans **650+ tests** covering every layer from raw serial framing and MAVLink packet inspection up to autonomous closed-loop counter-commands and SQLite hash chain forensic verification.

## Test Commands
| Command | Purpose | Typical Runtime |
|---|---|---|
| `python scripts/verify_stage2.py` | Full 8-suite Stage 2 audit (golden state, sanitizer, killswitch, cadence, CUSUM, HAL, watchdog, GCS) | ~40 ms |
| `pytest tests/unit/test_mitigation.py tests/unit/test_hal.py` | Core Stage 2 autonomous defense and HAL tests | < 2 s |
| `pytest tests/unit -q` | Fast unit test suite (550+ tests) | ~15 s |
| `pytest tests/integration -q` | Multi-mode attack detection and pipeline tests | ~30 s |
| `pytest tests/e2e -q` | Full end-to-end slice with SHA-256 ledger check | ~10 s |
| `pytest` | Complete verification suite (650+ tests) | ~1.5 min |
| `ruff check src tests scripts` | Code quality and linting | < 1 s |

## What Each Suite Verifies

### Stage 2 Autonomous Prevention & HAL
- **`test_mitigation.py` (27 tests)**:
  - `GoldenStateEstimator`: dead-reckoning during GPS loss/spoofing, speed/attitude isolation during telemetry attacks, clean GPS anchoring during non-GPS attacks.
  - `FrameSanitizer`: coordinate clamping, altitude correction, CUSUM micro-drift tracking, frame dropping for quarantined sysids.
  - `KillswitchGuard`: disarm veto in flight, emergency motor stop veto, unauthorized mode change rejection.
  - `CommandCadenceGuard` (`AF-SEC-01`): enforces 50 ms minimum inter-command interval to defeat command burst attacks.
  - `AutonomousMitigationEngine`: full closed-loop response generation, priority sorting, GCS notification banner generation.
- **`test_hal.py` (7 tests)**:
  - Hardware discovery across USB/serial ports (CubePilot, Pixhawk, SiK telemetry, ELRS).
  - Platform and companion compute detection (Raspberry Pi, Jetson, Rockchip).
  - Dynamic latency budgeting (15 ms to 65 ms).
  - Dual-topology routing: auto-selection of Topology B vs Topology A vs A+B.
  - `InlineBridge` packet processing and 150 ms fail-open watchdog timer.
- **`test_gcs_notifier.py` (4 tests)**:
  - MAVLink `STATUSTEXT` packet generation with severity levels and rate limiting.

### Detection, Ingest & Protocols
- **`test_mavlink_codec.py` & `test_mavlink_serial.py` (160+ tests)**: MAVLink v2 encode/decode, X.25 CRC-16 computation, framing recovery, baud rate handling, dropped byte resilience.
- **`test_proxy_*.py`**: Live proxy attack injection across 20 sub-modes (gradual drift, freeze, telemetry mutation, command injection, DoS flood).
- **`test_fusion_and_metrics.py`**: Noisy-OR evidence fusion, weighted attribution, threshold hysteresis, metric calculations.
- **`test_integrity_and_logging.py`**: SHA-256 firmware manifest verification, SQLite tamper-evident rolling block hash chain verification (`broken_at` detection).

## Pre-Release Gate
```bash
ruff check src tests scripts      # clean (0 errors)
python scripts/verify_stage2.py   # all 8 suites passed
pytest tests/unit -q             # all unit tests passed
```
