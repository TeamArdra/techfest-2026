# AegisFlight — Next State Ledger (`next_state.md`)

> **Status note (integration review):** this page is a design description. What is implemented, measured or only modelled is
> recorded in `docs/VALIDATION_EVIDENCE.md` and the README. In particular: the defense layer is report-only on every live or
> recorded source; Topology B (`InlineBridge`, `FrameSanitizer`, `rust/aegis_fastpath`) and the 150 ms fail-open watchdog are
> not wired into any relay and have no measured figure; nothing has been measured on a companion computer; the measured decision
> compute is 17.7 ms mean / 23.6 ms p95 with ML on (`artifacts/benchmarks/summary.md`, SIM).
> Forward-looking milestone roadmap, prioritized execution queue, and submission targets. Strict Token Budget: < 1500 tokens.

## 1. Prioritized Objectives Queue

### [P0] Screen Recording & Demo Runbook Validation
- **Objective**: Execute automated walkthrough demonstrating live attack injection, 4-stage IPS recovery, and forensic verification.
- **Target Assets**:
  - Run `scripts/run_demo.py` headless and verify scripted output narrative.
  - Video capture sequence:
    1. Baseline nominal flight at 10 Hz.
    2. Subtle GPS gradual drift injection (0.8 m/s) -> Sub-mode classifier triggers -> Secondary EKF engages -> Sanitized coordinates stabilize vehicle.
    3. Unauthorized Disarm injection -> Actuator override blocks command -> Alert recorded in SQLite.
    4. GCS cryptographic verification -> Single-click SHA-256 chain validation & JSON forensic export.
- **Target Completion**: Ready for screen capture recording.

### [P1] Stage 2 Final Report Document Alignment (`docs/stage2_report_draft.md`)
- **Objective**: Sync final measured performance benchmarks into the IIT Bombay Techfest Stage 2 report template.
- **Key Benchmarks to Embed**:
  - Detection latency: 17.7 ms mean / 23.6 ms p95 with ML on (SIM, `artifacts/benchmarks/summary.md`).
  - Computational footprint: not measured on a companion computer; do not quote a figure until it is.
  - Recovery: SIM twin only; no measured recovery time exists.
  - Zero-false-action guarantee: `PASSIVE` mode strictly outputs $0$ bytes over telemetry link.
  - Cryptographic tamper localization: SHA-256 block invalidation pinpoints exact block index.

### [P2] Physical Drone Hardware & Companion Deployment Testing
- **Objective**: Connect real drone hardware (Pixhawk / Cube autopilot + Raspberry Pi / Jetson + SiK/ELRS radio) and verify the Hardware Abstraction Layer (`src/aegisflight/hal/`).
- **Deliverables**:
  - Auto-discover connected serial devices (`HardwareDiscovery.scan_serial_ports()`).
  - Auto-fingerprint flight controller firmware & sensors (`EndpointIdentifier`).
  - Execute `TopologyPlanner.decide()` on live hardware: verifies Topology B (inline bridge) or Topology A (sidecar actuator) selection.
  - Test fail-open watchdog in `InlineBridge`: verify transparent hardware bypass if companion compute is unpowered or halted.

### [P3] Clean Package Archive & Submission Polish
- **Objective**: Ensure the submission tarball/repo is reproducible with a single command.
- **Deliverables**:
  - `python scripts/verify_stage2.py` serves as the official 1-second evaluator quick-check.
  - Clean build verification: `npm run build` generates production `frontend/dist`.
  - Cargo clean & release build for standalone Tauri binary (`aegisflight-gcs`).

## 2. Risk & Contingency Matrix
| Risk Vector | Probability | Impact | Mitigation Strategy |
|---|---|---|---|
| UART buffer overflow during high-Hz flood | Low | Med | Ring-buffer with drop-oldest policy & DMA flow control. |
| Subtle GPS drift false-positive during high-wind gusts | Low | High | Doppler-inertial cross-check window requires 3 consecutive frames before triggering EKF switch. |
| Judge running on non-Unix system | Low | Med | Windows PowerShell & cross-platform bash scripts fully supported in `scripts/`. |

## 3. Autonomous JIT Skill Trigger Criteria
- Activate **`hardware-security`** if tuning UART DMA serial interrupts.
- Activate **`wireshark-analysis`** if analyzing live binary PCAP captures from bench tests.
- Activate **`react-best-practices`** if adding 3D WebGL trajectory visualizers.
*All skills will be pruned immediately after subtask completion to preserve context window.*
