# AegisFlight — Current State Ledger (`current_state.md`)
> Authoritative system status snapshot for PUSHPAK Stage 2 (IIT Bombay Techfest). Strict Token Budget: < 1500 tokens.

## 1. System Identity & Physical Constraints
- **Target Hardware Profile**: Hybrid Companion Computer (`Raspberry Pi Zero 2W`, Quad-Core Cortex-A53 @ 1.0 GHz, 512 MB LPDDR2 RAM) coupled to Autopilot (`Pixhawk 6X`, STM32H753 @ 480 MHz).
- **Physical Link**: Full-duplex UART (`TELEM2` on Pixhawk <-> `/dev/ttyAMA0` on RPi) @ 115,200 baud with hardware RTS/CTS flow control and DMA ring-buffer. Supports standard Pixhawk/SITL SysIDs `(1, 3)` and GCS SysIDs `(253, 254, 255)` with single-source auto-learning for custom fleet IDs.
- **Strict Bench Budgets**:
  - Detection Latency: $\le 45\text{ ms}$ (measured: $< 3.2\text{ ms}$ full pipeline, $< 1.0\text{ ms}$ audit suite).
  - Telemetry Bandwidth Overhead: $\le 8\%$ (mitigation packets throttled to 1–2 Hz, 44B unsigned / 57B MAVLink-2 signed).
  - Resident Memory (RSS): $\le 45\text{ MB}$ footprint.

## 2. Runtime Daemons & Active Ports
- **Backend Service (Task: task-3140)**:
  - Command: `aegis serve --port 8008 --defense-mode active-ips`
  - Endpoints: REST API (`http://127.0.0.1:8008/api`), WebSocket telemetry stream (`ws://127.0.0.1:8008/ws/telemetry`), Forensic bundle (`/api/events/forensic`), Topology control (`/api/topology`).
  - Hardened Control Plane: Localhost/Tauri CORS & `Origin` lockdown + optional constant-time HMAC `X-Aegis-Token` / `Bearer` authentication (`AEGIS_API_TOKEN`).
- **Frontend Dashboard (Task: task-1878)**:
  - Vite dev server listening at `http://localhost:5173`.
  - Tactical HUD with real-time Leaflet flight tracks, subtle drift sliders, sub-mode selector, deployment topology switcher (`Auto`, `Top-B`, `Top-A`, `Top-A+B`, `IDS`), and SHA-256 hash-chain audit viewer.
  - Mode-Segregated Display (`PASSIVE / IDS` vs `ADVISORY` vs `ACTIVE_IPS`): GCS UI strictly adapts to active mode, showing zero-emission audit in IDS, STATUSTEXT guidance in Advisory, and closed-loop counter-actuation in IPS.
- **Desktop Application (Task: task-2793)**:
  - Native Tauri 2.0 Rust client (`aegisflight-gcs`) running locally, consuming IPC backend streams with zero-latency WebView rendering.

## 3. Detection & Autonomous Mitigation Engine (Dual-Posture: IDS & IPS)
- **Closed-Loop Cyber-Physical Simulation Twin (`LiveEngine._step_cyber_physical_twin`)**:
  - Simulates genuine physical vehicle dynamics under attack:
    - `mode_flip`: enters `LAND`, decelerates to 0 m/s, descends at -3.0 m/s.
    - `gcs_replay`: enters `RTL`, veers towards Home (19.1334, 72.9133) at 11 m/s.
    - `arm_disarm_burst`: disarms mid-flight (`armed=False`), stalls and plummets at -7.5 m/s.
    - `rogue_command`: enters `GUIDED`, veers SW (225°) at 10.5 m/s.
    - `gradual_drift` / `sudden_offset`: follows spoofed coordinates off-mission.
    - `rogue_sysid`: offsets NW from conflicting position frames.
  - Seamless `PASSIVE` -> `ACTIVE_IPS` recovery: seeds from hijacked position without teleportation and steers cleanly back onto the survey track at 12 m/s.
  - Topology-aware physical divergence:
    - **Topology B (Inline Bridge)**: `FrameSanitizer` drops rogue frames inline before reaching FC; 0.0 m detour.
    - **Topology A (Sidecar Actuator)**: Brief reaction detour (~0.4s) before `MavlinkActuator` counter-command restores `AUTO` at 12 m/s.
- **Hardware Abstraction Layer (`src/aegisflight/hal/`)**:
  - `discovery.py`: Auto-scans serial ports, USB VIDs (CubePilot, Pixhawk, ArduPilot, FTDI, CP210x, CH340), companion compute (Raspberry Pi model, Jetson, CPU count, latency budget).
  - `identify.py`: Fingerprints endpoints from `HEARTBEAT` & `AUTOPILOT_VERSION` (ArduPilot vs PX4, Copter vs Plane, GPS, Optical Flow, RFD900/SiK RSSI).
  - `profiles.py`: Translates counter-commands per firmware (ArduPilot Copter/Plane mode numbers, PX4 bitshift mode numbers, EKF switch commands; non-compliant firmware falls back to IDS).
  - `link_graph.py` & `topology.py`: Graph-based topology resolver (`decide()`) enforcing conservative fallback, low-CPU step-down, and in-flight armed lockouts.
  - `inline_bridge.py`: Bidirectional bridge with 150ms fail-open watchdog thread to prevent pilot link severing.
- **Enhanced Flight Track & Altitude Profile (`MapPanel.tsx`)**:
  - Context-aware attack and protected labels (`FORCED LAND (BLOCKED)`, `REPLAYED RTL (BLOCKED)`, `ROGUE GUIDED (BLOCKED)`, `DISARM DROP (VETOED)`, `SPOOFED GPS (REJECTED)`, etc.).
  - Real-time vehicle head badge: `[MODE · SPEED m/s · ALT m]`.
  - 44px SVG **Vertical Altitude Profile Strip (`0-100 m`)** plotting `rawAlt` vs `effAlt` with 60m survey baseline.
- **Multi-Layer Defense**:
  - Rule-Based & Protocol (`ProtocolDetector`): Boundary invariants, multi-source provenance, and State-Aware Command Cadence Guard catching duplicate/mid-air disarms (`AF-SEC-01`).
  - Stateful Physical Kinematics (`PhysicsDetector`): 3-axis acceleration, jerk bounds, Doppler vs GPS velocity residuals, plus 2D Isotropic Vector CUSUM Integrator (`CusumDriftIntegrator`) catching ultra-stealth micro-drift ($0.15\text{–}0.30\text{ m/s}$) while cancelling zero-mean turbulence (`AF-SEC-02`).
  - ML Anomaly Detector: Isolation Forest (`isoforest.joblib`) with calibrated anomaly scores (`ML_FEATURES` 11-feature contract preserved).
  - Cryptographic Attestation & Link Signing: SHA-256 firmware hash validation + MAVLink-2 13-byte packet signing (`MAVLINK_IFLAG_SIGNED = 0x01`, 48-bit $10\,\mu\text{s}$ monotonic timestamp $\tau_{\text{frame}} > \tau_{\text{last}}$, 48-bit truncated SHA-256 MAC) in `src/aegisflight/mavlink/signing.py`.
- **Mode-Gated Sanitization & Telemetry Restoration**:
  - `ACTIVE_IPS`: Clamps MSL/AGL altitude, locks groundspeed during speed mismatches, filters voltage spikes, and commands EKF Source 2 / AUTO mode restore with dual map tracks.
  - `PASSIVE / ADVISORY`: Strictly bypassed (`sanitized_telemetry == telemetry`, 0B TX, single raw vehicle track, no override actuation buttons).
- **Complete Dataset Injection Alignment & Resilience**:
  - All 20 dataset injection scenarios (`aegisflight.benchmark.extended.MODES`) verified: `gps_spoofing:replay_freeze`, `mavlink_anomaly:rogue_sysid`, `command_injection:rogue_command`, `dos:latency`, etc.
  - Bidirectional packet quarantine: drops hostile uplink commands and spoofed downlink telemetry from quarantined SysIDs.
  - Dual MSL & AGL (`relative_alt`) coordinate sanitization prevents baro/terrain desync.
  - Crosswind-aware dead reckoning: blends ground velocity with nose yaw within $\pm 25^\circ$, eliminating crab-angle false positives.
- **16 Tactical Sub-Modes & 4-Stage IPS State Machine**:
  - `NOMINAL` -> `AUTO_MITIGATING` (EKF source switch, coordinate sanitization, signed MAVLink overrides, `REPLAY_GUARD`, `VETO_DISARM`, `RATE_LIMIT`, `LINK_WATCHDOG`) -> `SAFE_HOLD` -> `GCS_TAKEOVER`.
- **Mode Invariant**: `PASSIVE` (IDS) mode detects and logs all sub-modes while strictly guaranteeing `bytes_sent = 0` (`counter_frames == []`, `sanitize_gps == False`).

## 4. Cryptographic Integrity & Forensics
- **Tamper-Evident Hash Chain**: SQLite event log with SHA-256 rolling block hashes; immediate tamper detection on single-byte modification.
- **Actuator Parity**: MAVLink v2 binary packing with X.25 CRC recomputation over `incompat_flags` (`0x3D59` unsigned / 57-byte signed verified).

## 5. Verification & Test Metrics
- Unit & Integration: **27/27 mitigation unit tests** (`tests/unit/test_mitigation.py`), **7/7 HAL unit tests** (`tests/unit/test_hal.py`), and **100% pass rate across the full test suite** (all 280+ tests in `tests/`).
- Stage 2 Audit Suite: `scripts/verify_stage2.py` passing **8/8 suites** in ~40 ms (including `AF-SEC-01`, `AF-SEC-02`, Control-Plane Auth/CORS, and Closed-Loop Dual-Topology A vs B verification).
- Benchmark Suites: 9 verified suites (6 Core Seeds, 20 Extended Sub-Modes, Stage 2 Hardening, P2I Driver, CMU ALFA, PX4 Review, SITL Logs, IEEE T-ITS 2023, and mIDS-UAV).
- Static & Build Analysis: `ruff check src tests scripts` 0 errors; `npm --prefix frontend run build` 0 TypeScript errors (259 ms); `cargo check` 0 errors.

## 6. JIT Skills Sheet Protocol (`docs/SKILLS_REGISTRY.md`)
- Status: **IDLE** (`security-auditor` invoked JIT for red-team audit, executed, and pruned to maintain minimum context tokens).
