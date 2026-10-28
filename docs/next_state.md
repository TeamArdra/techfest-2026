# AegisFlight — Next State Ledger (`next_state.md`)
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
- **Key Benchmarks to Embed** (corrected 2026-10-29; the earlier list — 1.0 / 3.2 ms, < 45 MB, < 18 % CPU on a Cortex-A53, 1.2 s recovery — had no artifact behind it; the draft `docs/stage2_report_draft.md` already uses the values below):
  - Decision compute: 17.7 ms mean / 23.6 ms p95 (ML on, SIM, host; `artifacts/benchmarks/summary.md`); 0.349 ms mean / 0.748 ms p99 (ML off, live runner on a laptop, BENCH stream; `live_capture/summary.json`). Time to alert: mean 0.361 s / p95 1.40 s (SIM).
  - Computational footprint: host only, 60.7 MB peak RSS and 2.78 % of one core (live runner, ML off). **Companion computer: not measured.**
  - Recovery time: **not measured** (the 4-stage state machine is a SIM model).
  - `PASSIVE` mode outputs 0 bytes over the telemetry link: pinned by tests and observed as `bytes_sent` 0 on every physical capture.
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
