# AegisFlight — Components

One section per subsystem: purpose, I/O, key classes, config, tests, extension
points, and current limitations. See `docs/FILE_REFERENCE.md` for file-level
detail and `docs/CODEBASE_MAP.md` for dependency directions.

| Subsystem | Purpose | In → Out | Key classes | Config | Tests | Limitations |
|---|---|---|---|---|---|---|
| **Core** | Shared types/enums/geo | — | `FlightState`, `MessageEnvelope`, `TelemetrySnapshot`, `DetectorResult`, `ThreatAssessment`, `AttackType`, `Severity` | — | `test_geo` | Plain dataclasses (speed over validation) |
| **Config** | Typed tunables | YAML → `AegisConfig` | `AegisConfig` | `configs/*.yaml` | `test_config` | Not hot-reloaded |
| **Simulator** | Deterministic flight | `SimulatorConfig` → `FlightState[]` | `FlightSimulator` | `simulation.*` | `test_simulator` | Point-mass kinematics (not full 6-DoF) |
| **MAVLink** | Genuine v2 codec + noise | `FlightState` → bytes → `MessageEnvelope` | `MavlinkEncoder`, `MavlinkDecoder` | `message_rates`, `noise` | `test_mavlink_codec` | 6 telemetry types + COMMAND_LONG |
| **Attacks** | 6 safe simulations | `FlightState`/packets → perturbed | `*Attack`, `build_attack` | `attacks.*` | `test_pipeline` | Local sim only; no real RF |
| **Integrity** | Firmware SHA-256 | dir → `IntegrityReport` | `FirmwareVerifier` | — | `test_integrity_and_logging` | Assumes trusted manifest |
| **Sources** | Wire orchestration | sim+attack → `TelemetryTick` | `SimulatedTelemetrySource` | — | (integration) | In-proc + swappable attack |
| **Features** | Online feature extraction | `MessageEnvelope` → `FeatureFrame` | `FeatureExtractor` | windows | (integration) | 11 ML features |
| **Detectors** | 4 detection layers | `FeatureFrame` → `DetectorResult` | `Protocol/Physics/Anomaly/Integrity Detector` | `detector.*` | `test_fusion_and_metrics`, `test_pipeline` | ML weak on out-of-training-range (mitigated by ensemble) |
| **Fusion** | Combine + attribute | `DetectorResult[]` → `ThreatAssessment` | `FusionEngine` | `detector.fusion` | `test_fusion_and_metrics` | Heuristic confidence (not calibrated prob.) |
| **Pipeline** | Wire the stack | `TelemetryTick` → `ThreatAssessment` | `IDSPipeline` | — | (integration/e2e) | — |
| **Logging** | Tamper-evident log | `ThreatAssessment` → SQLite | `EventStore` | — | `test_integrity_and_logging` | SQLite (single-node) |
| **Metrics** | Scoring + resources | labels → `Evaluation` | `evaluate`, `ResourceSampler` | — | `test_fusion_and_metrics` | — |
| **Benchmark** | Authoritative metrics | grid → results+figures | `run_session`, `run_benchmark` | — | (drives all) | ~min-scale runtime (ML inference) |
| **Mitigation** | Autonomous closed-loop IPS | `ThreatAssessment` → `MitigationPlan` | `AutonomousMitigationEngine`, `GoldenStateEstimator`, `FrameSanitizer`, `KillswitchGuard` | `mitigation.*` | `test_mitigation` | Posture-gated execution |
| **HAL** | Hardware auto-discovery & bridge | Serial/USB/OS → Link Topology | `HALDiscovery`, `InlineBridge`, `TopologySelector`, `PlatformProfile` | `hal.*` | `test_hal` | Requires OS serial port access |
| **Desktop GCS** | Native Operator Console | WS/REST → Tauri UI | Tauri 2.0 Rust wrapper, MapPanel, DefensePanel | — | (manual) | Native desktop / web |
| **Backend** | Live API + WS | HTTP/WS ↔ `LiveEngine` | `LiveEngine`, FastAPI app | — | `backend/tests` | Single engine instance |
| **Frontend** | Dashboard | WS/REST → UI | React components | — | (manual) | No auth (local demo) |
| **CLI** | Operator entry | argv → actions | `aegis` | — | (manual) | — |

**Extension points:** new attack (`docs/ADDING_A_NEW_ATTACK.md`), new detector
(`docs/ADDING_A_NEW_DETECTOR.md`), new feature (`features/extractor.py` +
retrain), new route (`simulator/flight.py:_route_waypoints`).
