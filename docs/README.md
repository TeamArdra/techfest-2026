# AegisFlight — Documentation Index

Start here. AegisFlight is a production-grade, hybrid UAV Intrusion Detection and
Autonomous Prevention System (IDS/IPS) for the **PUSHPAK Grand Challenge 2026-27
(IIT Bombay Techfest) — Security of Drones, Objective 2**.

## Reading path
```
QUICKSTART  →  HANDOFF  →  ARCHITECTURE  →  END_TO_END_FLOW  →  FILE_REFERENCE
```

## Getting started
- [QUICKSTART.md](QUICKSTART.md) — clone → running dashboard and desktop GCS.
- [installation.md](installation.md) — install steps (Windows / Linux / macOS).
- [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) — record the Stage 2 demonstration.
- [HANDOFF.md](HANDOFF.md) — status, what works, architectural contracts, next steps.

## Understanding the system
- [ARCHITECTURE.md](ARCHITECTURE.md) — end-to-end architecture, dual-topology execution (Topology A vs Topology B), HAL, and cadences.
- [END_TO_END_FLOW.md](END_TO_END_FLOW.md) — one tick traced through the ingest, feature extraction, fusion, and mitigation pipeline.
- [CODEBASE_MAP.md](CODEBASE_MAP.md) — directories + dependency rules.
- [FILE_REFERENCE.md](FILE_REFERENCE.md) — every meaningful file across IDS, IPS, HAL, and Desktop GCS.
- [COMPONENTS.md](COMPONENTS.md) — subsystem-by-subsystem reference table.
- [DATA_FLOW.md](DATA_FLOW.md) — object lifecycles (`FlightState` → `FeatureFrame` → `ThreatAssessment` → `MitigationCommand`).

## Security, detection & autonomous mitigation
- [THREAT_MODEL.md](THREAT_MODEL.md) — the 20 attack sub-modes across 6 threat vectors.
- [ATTACKS.md](ATTACKS.md) — attack implementations and injection mechanisms.
- [DETECTION.md](DETECTION.md) — the four detectors + evidence fusion.
- [FEATURES.md](FEATURES.md) — feature catalogue and mathematical definitions.
- [ML_PIPELINE.md](ML_PIPELINE.md) — training, leakage avoidance, inference, and calibration.
- [EVENT_LOGGING.md](EVENT_LOGGING.md) — SQLite schema + tamper-evident SHA-256 rolling block hash chain.
- [REDTEAM_AUDIT_STAGE2.md](REDTEAM_AUDIT_STAGE2.md) — withdrawn self-assessment (reasons inside).
- [RISK_REGISTER.md](RISK_REGISTER.md) — risk analysis, residual likelihoods, and mitigations.

## Interfaces & hardware deployment
- [API.md](API.md) — REST + WebSocket telemetry & defense endpoints.
- [FRONTEND.md](FRONTEND.md) — React dashboard structure, mode-segregated HUD, and data flow.
- [CONFIGURATION.md](CONFIGURATION.md) — every config field and tunable.
- [SERIAL_TRANSPORT.md](SERIAL_TRANSPORT.md) — serial transport, framing, and virtual/hardware ports.
- [HARDWARE_BENCH_PIXHAWK6X.md](HARDWARE_BENCH_PIXHAWK6X.md) — physical Pixhawk 6X + Raspberry Pi companion bench validation.
- [ONBOARD_DEPLOYMENT.md](ONBOARD_DEPLOYMENT.md) — companion computer deployment guide and operational topology selection.

## Quality, verification & competition deliverables
- [BENCHMARKING.md](BENCHMARKING.md) — how metrics are produced + results (baseline, ablation, extended v2).
- [EXTERNAL_DATA.md](EXTERNAL_DATA.md) — public real-flight datasets (40 PX4 logs + 41 ALFA logs), feature compatibility, external validation.
- [VALIDATION_EVIDENCE.md](VALIDATION_EVIDENCE.md) — empirical validation table (TC-01…TC-06) + evidence levels.
- [REPORT_ALIGNMENT.md](REPORT_ALIGNMENT.md) — competition report mapping & compliance matrix.
- [STAGE2_PROGRESS.md](STAGE2_PROGRESS.md) — Stage 2 engineering ledger and implementation progress.
- [STAGE2_RUNBOOK.md](STAGE2_RUNBOOK.md) — SITL integration, automated verification, and regression test suites.
- [stage2_report_draft.md](stage2_report_draft.md) — withdrawn report draft; rebuild from VALIDATION_EVIDENCE.md.
- [SKILLS_REGISTRY.md](SKILLS_REGISTRY.md) — catalogue of optional third-party agent skills (human-installed only).
- [TESTING.md](TESTING.md) — the test suite and the pre-release gate.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — symptom → diagnostic → fix.

## Contributing
- [DEVELOPMENT.md](DEVELOPMENT.md) — conventions & boundaries.
- [ADDING_A_NEW_ATTACK.md](ADDING_A_NEW_ATTACK.md)
- [ADDING_A_NEW_DETECTOR.md](ADDING_A_NEW_DETECTOR.md)

## Competition & history
- [technical_proposal.md](technical_proposal.md) — the original proposal.
- [REFERENCES.md](REFERENCES.md) — academic literature, standards (RTCA DO-326A, NIST SP 800-82, MAVLink v2 spec).
- [CHANGELOG.md](CHANGELOG.md) — version history from Stage 1 to Stage 2.

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
