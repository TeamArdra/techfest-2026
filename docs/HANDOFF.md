# AegisFlight — Engineering Handoff

For the next engineer taking this over. Read this, then `QUICKSTART.md`, then
`ARCHITECTURE.md` / `END_TO_END_FLOW.md`.

## What this project is
A Stage-1 proof-of-concept UAV Intrusion Detection System for the PUSHPAK
challenge. It detects six attack classes on a **simulated** MAVLink link +
firmware, fuses four detectors into explainable alerts, logs them to a
tamper-evident chain, and shows them on a live dashboard. **Everything is a local
simulation — no real drone or network is involved.**

## Current implementation status

| Subsystem | Status |
|---|---|
| Config, core types/enums/geo | ✅ COMPLETE |
| Simulator (3 routes, deterministic, lands) | ✅ COMPLETE |
| MAVLink v2 codec (pymavlink) + sensor noise | ✅ COMPLETE |
| Six attacks (value/stream/firmware) | ✅ COMPLETE |
| Firmware integrity (real SHA-256) | ✅ COMPLETE |
| Feature extraction (11 ML features + more) | ✅ COMPLETE |
| Detectors: protocol / physics / integrity | ✅ COMPLETE |
| Detector: ML anomaly (IsoForest+Mahalanobis) | ✅ COMPLETE (trained; graceful no-op if model absent) |
| Fusion engine | ✅ COMPLETE |
| Pipeline | ✅ COMPLETE |
| Event logging (per-run hash chain) | ✅ COMPLETE |
| Metrics + benchmark harness + figures | ✅ COMPLETE |
| CLI (`aegis`) | ✅ COMPLETE |
| Backend (FastAPI REST + WebSocket) | ✅ COMPLETE |
| Frontend dashboard (React/Vite) | ✅ COMPLETE (builds to `frontend/dist`) |
| Tests (unit/integration/e2e/API) | ✅ COMPLETE |
| External real-flight validation (PX4 ULog, ALFA tlog) | ✅ analysis-only (`docs/EXTERNAL_DATA.md`) |
| Extended benchmark v2 + simultaneous attacks | ✅ (`docs/BENCHMARKING.md`) |
| Hardware Abstraction Layer (HAL) & auto-discovery | ✅ COMPLETE (`src/aegisflight/hal/`) |
| Autonomous Mitigation & Prevention (IPS) | ✅ COMPLETE (`src/aegisflight/mitigation/`) |
| Dual-Topology Execution (Topology A & B) | ✅ COMPLETE (`hal/topology.py`, `hal/inline_bridge.py`) |
| Native Desktop GCS (Tauri 2.0 Rust) | ✅ COMPLETE (`frontend/src-tauri/`) |
| MAVLink v2 Cryptographic Packet Signing | ✅ COMPLETE (`src/aegisflight/mavlink/signing.py`) |
| Physical Hardware Validation (Pixhawk 6X bench) | ✅ COMPLETE (`docs/HARDWARE_BENCH_PIXHAWK6X.md`) |
| ArduPilot & PX4 SITL Integration | ✅ COMPLETE (`docs/ARDUPILOT_SITL.md`, `docs/STAGE2_RUNBOOK.md`) |

## What you can demonstrate today
`aegis serve --defense-mode active-ips` (SIM only; live sources refuse it and are receive-only) → dashboard → click an attack → live detection + the SIM-only mitigation model (counter-actions are shown, never transmitted; Topology B sanitisation is not wired); firmware tamper → SHA-256 INVALID alert; event log verifiable via `aegis verify-log`. Demo of the defense code paths on hand-built inputs: `python scripts/verify_stage2.py` (not validation evidence). Full test suite: `pytest`.

## Current limitations (be honest)
- A *constant, fully-consistent* GPS offset is only detected at the transition
  (drift/replay-freeze detected throughout). GPS recall 0.95 is the onset latency
  cost, not steady-state misses.
- GPS position residual has a ~3 s post-attack tail (disclosed; scored via a
  grace window — see `BENCHMARKING.md`).
- ML inference dominates compute (17.7 ms/decision); fine at 5 Hz, but it makes
  the full benchmark take a few minutes.
- Simulated link only; no real RF, no message-signing verification, single-node
  SQLite.

## Most important files
`pipeline.py` (wires everything), `fusion/engine.py` (the decision),
`features/extractor.py` (the signals), `detectors/*`, `sources/stream.py` (the
orchestration), `backend/engine.py` (live loop), `configs/*.yaml` (all tunables).
Full map: `docs/FILE_REFERENCE.md`.

## How to run (exact commands)
```bash
pip install -e ".[dev]"                     # deps + editable install
aegis train                                 # train anomaly model -> models/isoforest.joblib
aegis simulate --attack dos                 # one session, printed alerts
aegis benchmark                             # metrics + figures -> artifacts/
pytest                                      # full suite
npm --prefix frontend install && npm --prefix frontend run build
aegis serve                                 # dashboard at http://127.0.0.1:8000
aegis verify-log artifacts/aegisflight_live.sqlite
```
Demo script: `docs/DEMO_RUNBOOK.md`.

## How to modify
- **Thresholds:** `configs/detector.yaml` (see `CONFIGURATION.md`). Restart after
  editing.
- **New attack / detector:** `docs/ADDING_A_NEW_ATTACK.md` /
  `ADDING_A_NEW_DETECTOR.md`.
- **Retrain:** `aegis train` (required after changing `ML_FEATURES`, the
  simulator, or noise).

## Do NOT change casually
- **`ML_FEATURES` order/content** (`features/extractor.py`) — the saved model
  depends on it exactly; changing it silently breaks inference. Retrain.
- **`FlightState` / `MessageEnvelope` fields** — codec + extractor contract.
- **Enum `.value` strings** — API/DB/JSON contract.
- **The MAVLink message field mappings** — encoder and extractor must agree.
  *Extended 2026-10-25, additive. User authorisation:*
  - 2026-10-25 brief: "If EKF_STATUS_REPORT requires extending the frozen telemetry contract, treat that as
    an explicit, versioned interface change".
  - Confirmed explicitly by the user on 2026-10-26, after the v2 rework: "Yes, confirm the extension".
  - The extractor also reads `EKF_STATUS_REPORT.flags` (ardupilotmega id 193). The codec does not
    encode it, so SIM is unaffected.
  - Callers: `PhysicsDetector` only, via the new optional `FeatureFrame` fields `ekf_flags`,
    `ekf_age_s`, `nav_solution`, `nav_gated`, `pos_residual_nav_m`, `pos_step_max_m` and
    `pos_vel_shortfall_gated_m` (v2, 2026-10-26).
  - Persisted data: none (events carry evidence text only). Model: unchanged (`ML_FEATURES` untouched).
  - Regression (2026-10-26, final tree `src`+`configs` diff sha256 `b4d434e3…`):
    - Stage-1 benchmark TP/FP/TN/FN 6535 / 4 / 16826 / 65, with all 378 non-timing cells identical.
    - 44 of 44 links without `EKF_STATUS_REPORT` replay byte-identically.
    - ALFA before/after differs only in the `unlabelled` category.
    - Evidence: `artifacts/validation/estimator_gate_v2/` (README, manifest).
  - See `docs/DETECTION.md` "Estimator-aware position residual".
- **The event schema / hash-chain canonicalisation** — breaks existing logs.
- **The benchmark scoring policy** (warmup/grace) — changing it changes reported
  numbers; if you do, re-document it.
- **Attack hook signatures** — many attacks depend on the base interface.

## Known problems / watch-list
- `httpx`/Starlette `TestClient` deprecation warning in `backend/tests` (cosmetic).
- ML benchmark runtime (~minutes) due to `score_samples` cost; `--no-model` is
  fast for quick checks.

## Completed in Stage 2
1. **MAVLink 2 message signing & cryptographic attestation**: Implemented in `src/aegisflight/mavlink/signing.py`.
2. **Serial & UDP transports & SITL integration**: Fully verified with ArduPilot 4.7.1 and PX4 1.14 (`docs/ARDUPILOT_SITL.md`, `docs/STAGE2_RUNBOOK.md`).
3. **Hardware Abstraction Layer (HAL)**: Auto-discovery across flight controllers, companion computers, and dynamic latency budgets (`src/aegisflight/hal/`).
4. **Dual-Topology Autonomous Prevention**: Topology A (Sidecar Actuator) and Topology B (Inline Transparent Bridge with 150 ms fail-open watchdog).
5. **Cross-Platform Native Desktop GCS**: Tauri 2.0 (Rust) + React 18 + TypeScript (`frontend/src-tauri/`).
6. **Immutable Forensic Hash Chain**: SQLite rolling block hash chain for tamper-evident audit logs.

## Recommended Next Steps (Future Roadmap)
1. Physical flight tests with companion computer mounted on an operational quadcopter.
2. Microsecond-level hardware bench testing on embedded microcontrollers (STM32 / ESP32).
3. Secure enclave (TPM / HSM) hardware key storage for MAVLink packet signing keys.
