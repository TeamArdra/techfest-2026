# AegisFlight — Documentation Index

Start here. AegisFlight is a Stage-1 proof-of-concept UAV Intrusion Detection
System (all activity is **local simulation**). This set documents the *actual*
implementation.

## Reading path
```
QUICKSTART  →  HANDOFF  →  ARCHITECTURE  →  END_TO_END_FLOW  →  FILE_REFERENCE
```

## Getting started
- [QUICKSTART.md](QUICKSTART.md) — clone → running dashboard.
- [installation.md](installation.md) — install steps (Windows / Linux / macOS).
- [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) — record the demonstration.
- [HANDOFF.md](HANDOFF.md) — status, what works, what not to touch, next steps.

## Understanding the system
- [ARCHITECTURE.md](ARCHITECTURE.md) — components, boundaries, cadences.
- [END_TO_END_FLOW.md](END_TO_END_FLOW.md) — one tick, traced through the code.
- [CODEBASE_MAP.md](CODEBASE_MAP.md) — directories + dependency rules.
- [FILE_REFERENCE.md](FILE_REFERENCE.md) — every meaningful file.
- [COMPONENTS.md](COMPONENTS.md) — subsystem-by-subsystem table.
- [DATA_FLOW.md](DATA_FLOW.md) — object lifecycles (`FlightState` → event row).

## Security & detection
- [THREAT_MODEL.md](THREAT_MODEL.md) — the six attack scenarios.
- [ATTACKS.md](ATTACKS.md) — attack implementation.
- [DETECTION.md](DETECTION.md) — the four detectors + fusion.
- [FEATURES.md](FEATURES.md) — feature catalogue.
- [ML_PIPELINE.md](ML_PIPELINE.md) — training, leakage avoidance, inference.
- [EVENT_LOGGING.md](EVENT_LOGGING.md) — SQLite schema + hash chain.

## Interfaces
- [API.md](API.md) — REST + WebSocket.
- [FRONTEND.md](FRONTEND.md) — dashboard structure & data flow.
- [CONFIGURATION.md](CONFIGURATION.md) — every config field.

## Quality & evaluation
- [BENCHMARKING.md](BENCHMARKING.md) — how metrics are produced + results (baseline, ML-off ablation, extended v2).
- [EXTERNAL_DATA.md](EXTERNAL_DATA.md) — public real-flight datasets, feature compatibility, external validation.
- [VALIDATION_EVIDENCE.md](VALIDATION_EVIDENCE.md) — real evidence vs simulation-only vs future work; overclaim audit.
- [REPORT_ALIGNMENT.md](REPORT_ALIGNMENT.md) — Stage-1 report sections ↔ files/artifacts; TC-01…TC-06.
- Stage 2 (hardware path), 2026-10-10: [HARDWARE_BENCH_PIXHAWK6X.md](HARDWARE_BENCH_PIXHAWK6X.md) — physical Pixhawk 6X, passive
  (`BENCH`); [ARDUPILOT_SITL.md](ARDUPILOT_SITL.md) — ArduCopter 4.7.1 integration, benign baseline, one pre-registered link-level
  attack (`SITL`); [ONBOARD_DEPLOYMENT.md](ONBOARD_DEPLOYMENT.md) — readiness assessment and blockers;
  [SERIAL_TRANSPORT.md](SERIAL_TRANSPORT.md) — the serial transport.
- [TESTING.md](TESTING.md) — the 44-test suite.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — symptom → fix.

## Contributing
- [DEVELOPMENT.md](DEVELOPMENT.md) — conventions & boundaries.
- [ADDING_A_NEW_ATTACK.md](ADDING_A_NEW_ATTACK.md)
- [ADDING_A_NEW_DETECTOR.md](ADDING_A_NEW_DETECTOR.md)

## Competition & history
- [technical_proposal.md](technical_proposal.md) — the Stage-1 proposal.
- [REFERENCES.md](REFERENCES.md)
- [CHANGELOG.md](CHANGELOG.md)
- Recovery: [RECOVERY_AUDIT.md](RECOVERY_AUDIT.md),
  [RECOVERY_FAILURES.md](RECOVERY_FAILURES.md),
  [RECOVERY_PRIORITY.md](RECOVERY_PRIORITY.md)

## Diagrams
`diagrams/*.mmd` (Mermaid): system-architecture, end-to-end-flow, attack-flow,
detection-flow, logging-flow, deployment.

---
*Naming:* most docs use `UPPER_CASE.md`. Competition-facing deliverables named in
the brief are provided as lower-case files: `technical_proposal.md`,
`installation.md`, `detection_methodology.md` → [DETECTION.md](DETECTION.md), and
`dataset_strategy.md` → [ML_PIPELINE.md](ML_PIPELINE.md). (Architecture, threat
model, benchmarking and references are the UPPER_CASE canonical files above; on a
case-insensitive filesystem the lower-case and upper-case names are the same
file.) No document claims a feature that isn't implemented and tested.
