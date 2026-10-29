# AegisFlight — Recovery / Continuation Priority

Ranked work plan produced after the audit. Because the project was recovered at
foundation stage, "recovery" and "continuation" collapse into one ordered
build. Work proceeds strictly in priority order; each item is tested before the
next begins.

## P0 — blocks the demo (the minimum working vertical slice)

1. **Simulator** (`simulator/flight.py`) — deterministic UAV flight producing
   `FlightState` ground truth + noisy sensor emulation.
2. **MAVLink codec** (`mavlink/`) — encode `FlightState` → real MAVLink messages
   (pymavlink), decode back to `MessageEnvelope`.
3. **Sources** (`sources/`) — in-process and UDP telemetry ingestors.
4. **Attack engine** (`attacks/`) — perturb telemetry/stream for the 6 scenarios.
5. **Feature extraction** (`features/`) — network / navigation / sensor / command.
6. **Detectors** (`detectors/`) — protocol, physics, anomaly (IsoForest), integrity.
7. **Fusion** (`fusion/`) — weighted evidence fusion → `ThreatAssessment`.
8. **Pipeline + CLI** (`pipeline.py`, `cli/`) — wire it end-to-end, runnable.
9. **Logging** (`logging/`) — SQLite event store with tamper-evident hash-chain.
10. **API + WebSocket** (`backend/`) — `/health`, `/api/*`, live telemetry/alerts.
11. **Dashboard** (`frontend/`) — connect to live backend, show telemetry + alerts.

## P1 — required for Stage 1

12. **All six attack scenarios** working (not just representative ones).
13. **Metrics + benchmark** (`metrics/`, `benchmark/`) — accuracy, precision,
    recall, F1, FPR, per-attack recall, confusion matrix, latency, throughput —
    from real runs.
14. **Isolation Forest training** (`scripts/train_model.py`) — benign-only,
    session-split, versioned artifact.
15. **Tests** — unit (geo, features, detectors), integration (pipeline),
    e2e (attack→detection).
16. **Installation instructions** (`docs/installation.md`) + `scripts/validate.py`.
17. **Technical proposal** (`docs/technical_proposal.md`) — from real numbers.
18. **README** reflecting actual implementation.

## P2 — polish

19. Dashboard UX: map, timeline, evidence panel, severity styling.
20. Architecture / threat-model / methodology / benchmarking docs + diagrams.
21. Demo script + reproducible scenario runner.

## P3 — explicitly out of scope for Stage 1

- Real hardware / SITL (ArduPilot/PX4) integration.
- Cloud deployment, Kubernetes, auth systems.
- Deep neural networks (IsoForest is the right lightweight choice here).
- 3D drone visualisation.

These are named in the technical proposal's *Future Work* as the deployment
path, but are **not** built now — a reliable local PoC is worth more.

## Official vs. our engineering choices

**Official Stage-1 deliverables** (from the PUSHPAK brief): 6–8 page technical
proposal, software architecture, working PoC simulation, source code,
installation instructions, demonstration video.

Everything else here (SQLite hash-chain, Isolation Forest, the specific fusion
weights, the FastAPI/React split) is **our engineering choice**, documented as
such in the proposal so evaluators can distinguish requirement from decision.
