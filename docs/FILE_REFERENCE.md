# AegisFlight — File Reference

Every meaningful source/config/script/test file, what it does, its key symbols,
and what depends on it. Derived from the actual code. Status legend: **CORE**
(hot-path library), **SUPPORT**, **CONFIG**, **SCRIPT**, **TEST**, **DOC**,
**GENERATED**.

---

## `src/aegisflight/core/` — shared vocabulary (CORE)

### `core/types.py`
Dataclasses that flow through the pipeline. Symbols: `FlightState` (clean
ground truth), `MessageEnvelope` (decoded MAVLink + link metadata),
`TelemetrySnapshot` (observed telemetry reconstructed by the IDS),
`DetectorResult` (one detector's output), `ThreatAssessment` (fused decision, with
`to_dict()`). Used by: essentially every module. **Dangerous to change:**
`FlightState`/`MessageEnvelope` field names — the encoder, extractor and tests
depend on them.

### `core/enums.py`
`AttackType` (BENIGN + 6 attacks, `.is_attack`), `Severity` (ladder + `.rank`),
`DetectorName`, `IntegrityStatus`, `FlightPhase`. Plain `(str, Enum)` for clean
JSON/SQLite serialisation. **Dangerous:** enum `.value` strings are the API/DB
contract.

### `core/geo.py`
Dependency-free geodesy: `haversine_m`, `offset_latlon`, `bearing_deg`,
`wrap_deg_180`. Used by simulator, encoder, extractor, benchmark. Tested by
`tests/unit/test_geo.py`.

---

## `src/aegisflight/config.py` (CORE)
Typed `AegisConfig` (simulation / message_rates / detector / attacks) with
`load()`/`load_config()` doing YAML-over-defaults deep-merge. Built-in defaults
mirror `configs/*.yaml` so the package works with no YAML present. Used by
everything that needs tunables. Tested by `tests/unit/test_config.py`.

---

## `src/aegisflight/simulator/` (CORE)

### `simulator/flight.py`
`SimulatorConfig` (`.from_config`, `.dt`, `.n_ticks`) and `FlightSimulator`
(`run()`/`run_list()`). Coordinated-turn point-mass integrator: takeoff → route
→ RTL → latched landing. Emits clean `FlightState`. Routes via
`_route_waypoints` (survey_box/out_and_back/perimeter). Deterministic given
`seed`. Consumed by `SimulatedTelemetrySource`, benchmark dataset. Tested by
`tests/unit/test_simulator.py`. **Config:** `simulation.*`.

### `simulator/__init__.py`
Re-exports `FlightSimulator`, `SimulatorConfig`. (This is the module whose
missing `.flight` import marked the crash point during recovery.)

---

## `src/aegisflight/mavlink/` (CORE)

### `mavlink/codec.py`
`MavlinkEncoder` (`encode_tick`, `encode_as`, `encode_command_long`; adds sensor
noise + per-session baro bias; per-source seq counters), `MavlinkDecoder`
(`decode` → `MessageEnvelope[]`), `RawPacket`, `COPTER_MODES`/`MODE_NAMES`,
`command_name_from_id`. Uses `pymavlink.dialects.v20.common`. Tested by
`test_mavlink_codec.py`. **Dangerous:** the six message field mappings are also
read by the extractor — change both together.

---

## `src/aegisflight/attacks/` (CORE)

### `attacks/base.py`
`Attack` base (hooks: `active`, `label`, `before_encode`, `perturb_state`,
`perturb_packets`, `integrity_status`, `window`), `AttackContext`, `NoAttack`.

### `attacks/scenarios.py`
The six scenarios: `GpsSpoofingAttack`, `TelemetryManipulationAttack`,
`MavlinkAnomalyAttack`, `CommandInjectionAttack`, `DosAttack`,
`FirmwareIntegrityAttack`. See `docs/ATTACKS.md`. **Config:** `attacks.*`.

### `attacks/__init__.py`
`ATTACK_REGISTRY`, `TYPE_TO_KEY`, `build_attack(name, cfg, rng, **kwargs)`.
Used by sources, backend, benchmark, CLI.

---

## `src/aegisflight/integrity/` (CORE)

### `integrity/verifier.py`
`FirmwareVerifier` (`write_fixture`, `build_manifest`, `ensure_fixture`,
`tamper`, `verify`, `restore`), `IntegrityReport`, `sha256_file`. Deterministic
5-component firmware fixture. Real SHA-256. Used by the firmware attack and the
integrity detector. Tested by `test_integrity_and_logging.py`.

---

## `src/aegisflight/sources/` (CORE)

### `sources/stream.py`
`TelemetryTick` (messages + hidden ground truth) and
`SimulatedTelemetrySource.stream()` — the one place that runs
sim → perturb_state → encode → perturb_packets → decode. `attack` is swappable
at runtime (the backend does this live). Used by pipeline consumers, backend,
benchmark, dataset.

---

## `src/aegisflight/features/` (CORE)

### `features/extractor.py`
`FeatureExtractor` (`update(msg)`, `extract(t)`, `clear_window_counts()`),
`FeatureFrame`, `CommandEvent`, `ML_FEATURES` (11-feature schema),
`_position_residual` (bounded sliding-window). See `docs/FEATURES.md`.
**Dangerous:** `ML_FEATURES` order/content — the saved model depends on it
exactly; changing it requires retraining.

---

## `src/aegisflight/detectors/` (CORE)

- `detectors/base.py` — `Detector` base + `ramp()` helper.
- `detectors/protocol.py` — `ProtocolDetector` (rate/seq/rogue/liveness/command).
- `detectors/physics.py` — `PhysicsDetector` (pos residual, alt/speed/att, battery).
- `detectors/anomaly.py` — `AnomalyDetector` + `combined_anomaly_raw()` +
  `FEATURE_ATTACK_MAP` (IsolationForest+Mahalanobis ensemble; graceful no-model).
- `detectors/integrity.py` — `IntegrityDetector` (wraps `FirmwareVerifier`).

See `docs/DETECTION.md`. **Config:** `detector.{protocol,physics,anomaly}`.
Tested by `test_fusion_and_metrics.py`, `test_pipeline.py`.

---

## `src/aegisflight/fusion/engine.py` (CORE)
`FusionEngine.fuse(...)` — noisy-OR with max-normalised weights → threat score;
weighted-vote attribution; severity bands; cooldown dedup + clear hysteresis.
Produces `ThreatAssessment`. See `docs/DETECTION.md#fusion`. **Config:**
`detector.fusion`.

---

## `src/aegisflight/pipeline.py` (CORE)
`IDSPipeline` — owns extractor, 4 detectors, `FirmwareVerifier`, fusion; runs at
the decision cadence, measures per-decision latency, emits `ThreatAssessment`.
Entry points: `process_tick(tick)`, `run(ticks)`, `reset()`. Used by backend and
benchmark.

---

## `src/aegisflight/logging/store.py` (CORE)
`EventStore` (SQLite): `start_run`, `log_event` (per-run SHA-256 chain),
`get_events`, `count_events`, `verify_chain`, `list_runs`; `ChainStatus`. See
`docs/EVENT_LOGGING.md`. Tested by `test_integrity_and_logging.py`.

---

## `src/aegisflight/metrics/` (SUPPORT)
- `metrics/scoring.py` — `evaluate(y_true, y_pred, latencies)` → `Evaluation`
  (`BinaryStats`, per-class `ClassScore`, confusion, `to_dict()`).
- `metrics/resources.py` — `ResourceSampler` (CPU% / RSS via psutil).

Tested by `test_fusion_and_metrics.py`.

---

## `src/aegisflight/benchmark/` (SUPPORT)
- `benchmark/runner.py` — `run_session(...)` → `SessionResult` with labelled
  `DecisionRecord`s; scoring policy (warmup + post-attack grace). See
  `docs/BENCHMARKING.md`.
- `benchmark/dataset.py` — `collect_benign_dataset(...)` → `BenignDataset`
  (`split_by_session`). Feeds ML training.
- `benchmark/harness.py` — `run_benchmark(...)` → results dict + `results.json`
  / `results.csv` / `summary.md`.
- `benchmark/plots.py` — the six figures (`generate_all`).

---

## `src/aegisflight/mitigation/` — Autonomous Prevention & IPS (CORE Stage 2)

- `mitigation/controller.py` — `MitigationController`: 4-state FSM (`NOMINAL`, `AUTO_MITIGATING`, `SAFE_HOLD`, `GCS_TAKEOVER`), posture gating (`PASSIVE`, `ADVISORY`, `ACTIVE_IPS`), per-attack playbooks, recovery after clean ticks. Counter-frames are reported, never transmitted on a live source.
- `mitigation/types.py` — `DefenseMode`, `MitigationState`, `AttackSubMode`, `AttackParameters`, `MitigationAction`.
- `mitigation/submode_classifier.py` — `AttackSubModeClassifier`: maps an assessment to a sub-mode; command cadence / mid-air disarm provenance check; vector CUSUM micro-drift tracker.
- `mitigation/parameter_estimator.py` — `ParameterEstimator`: quantifies the active attack (offsets, drift rate, biases, rogue sysids).
- `mitigation/golden_state.py` — `GoldenFlightState`: trusted-state anchor and dead-reckoning used by the dashboard twin.
- `mitigation/sanitizer.py` — `FrameSanitizer`: coordinate / altitude clamping and rogue-sysid quarantine model. Statistics only: no relay uses it (Topology B is not wired).
- `mitigation/actuator.py` — `MavlinkActuator`: encodes counter-commands (set mode, EKF source switch, STATUSTEXT) as MAVLink bytes; encoding only, never sent on a live source.

---

## `src/aegisflight/hal/` — Hardware Abstraction Layer (CORE Stage 2)

- `hal/discovery.py` — Auto-discovery across serial/USB devices (CubePilot, Pixhawk 6X/4/2.4.8, SiK Telemetry, ExpressLRS, Holybro).
- `hal/identify.py` — Host platform & companion compute detection (Raspberry Pi 4/5/Zero, NVIDIA Jetson, Rockchip) + dynamic latency budgets (15–65 ms).
- `hal/profiles.py` — Autopilot firmware detection & parameter adaptation (ArduPilot Copter/Plane/Rover vs PX4 Autopilot).
- `hal/link_graph.py` — Live topology graph builder (`TelemetryLinkGraph`), node identification, routing path resolution.
- `hal/topology.py` — Topology selector: selects optimal topology (`TOPOLOGY_B`, `TOPOLOGY_A`, `TOPOLOGY_A_PLUS_B`, `IDS_ONLY`) with human-readable rationale.
- `hal/inline_bridge.py` — `InlineBridge`: dual-port transparent serial bridge with wire-speed frame sanitization and 150 ms fail-open hardware watchdog.

---

## `rust/aegis_fastpath/` — Native Fastpath Engine (CORE Stage 2)

- `rust/aegis_fastpath/src/lib.rs` — Zero-allocation MAVLink v2 CRC-16 (X.25) table lookup, in-place coordinate sanitization (`GLOBAL_POSITION_INT`), sub-microsecond frame inspection.

---

## `frontend/src-tauri/` — Native Desktop GCS (CORE Stage 2)

- `src-tauri/src/main.rs` — Tauri 2.0 Rust desktop wrapper providing native OS windowing, hardware acceleration, and cross-platform desktop distribution.

---

## `src/aegisflight/backend/` (CORE for demo)
- `backend/engine.py` — `LiveEngine`: real-time async sim+IDS loop, runtime
  attack injection, WebSocket subscribers, status/metrics snapshots.
- `backend/app.py` — FastAPI app: `/health`, `/api/*`, simulation controls,
  `/ws/telemetry`; serves `frontend/dist`. See `docs/API.md`.

---

## `src/aegisflight/cli/` (SUPPORT)
`cli/main.py` — `aegis` entry point (`simulate`, `benchmark`, `train`, `serve`,
`verify-log`, `version`). `cli/__main__.py` enables `python -m aegisflight.cli`.

---

## `configs/*.yaml` (CONFIG)
`simulation.yaml`, `detector.yaml`, `attacks.yaml` — every tunable with inline
rationale. See `docs/CONFIGURATION.md`.

## `scripts/` (SCRIPT)
- `train_models.py` — train + calibrate + save the anomaly model; sanity-checks.
- `benchmark.py` — run the benchmark grid + figures → `artifacts/`.
- `run_demo.py` — scripted headless demo (see `docs/DEMO_RUNBOOK.md`).

## `frontend/` (CORE for demo)
Vite + React + TS dashboard. `src/hooks/useLiveData.ts` (WS + REST),
`src/services/api.ts`, `src/components/*`, `src/types/index.ts`. See
`docs/FRONTEND.md`.

## `tests/`, `backend/tests/` (TEST)
Unit (geo/config/simulator/codec/integrity/logging/fusion/metrics), integration
(all six attacks), e2e (full slice + hash chain), backend (API). See
`docs/TESTING.md`.

## `artifacts/` (GENERATED, committed as evidence)
`benchmarks/results.{json,csv}`, `benchmarks/summary.md`, `figures/*.png`.
Regenerate with `aegis benchmark`. `models/isoforest.joblib` is GENERATED and
gitignored (regenerate with `aegis train`).
