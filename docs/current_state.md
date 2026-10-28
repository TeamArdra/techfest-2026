# AegisFlight — Current State Ledger (`current_state.md`)
> Authoritative system status snapshot for PUSHPAK Stage 2 (IIT Bombay Techfest). Strict Token Budget: < 1500 tokens.

## 1. System Identity & Physical Constraints
- **Target Hardware Profile (design target, not tested)**: companion computer (e.g. Raspberry Pi Zero 2W) with a Pixhawk 6X autopilot.
- **Physical Link (bench, as tested)**: Pixhawk 6X telemetry over USB/radio on COM7, receive-only (`docs/HARDWARE_BENCH_PIXHAWK6X.md`). A companion UART link is a design target, not tested.
- **Strict Bench Budgets**:
  - Detection compute (host, SIM, ML on): 17.7 ms mean / 23.6 ms p95 (`artifacts/benchmarks/summary.md`); not measured on a companion computer.
  - Telemetry bandwidth overhead: 0 on live sources (nothing is transmitted; `bytes_sent` 0 on every physical capture). The SIM defense model's packet sizes (44 B unsigned / 57 B signed) are design figures, not measurements.
  - Resident memory (RSS): **measured 60.7 MB peak** for the live runner on the host (ML off, `artifacts/hardware/gps_hw_verify_20261029/live_capture/summary.json`; 154.7 MB mean in the ML-on benchmark). The earlier "≤ 45 MB" budget is not met on the host and was never measured on a companion computer.

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
  - `inline_bridge.py`: in-process bidirectional frame bridge with a 150 ms software "fail-open" flag. It is exercised only by `tests/unit/test_hal.py`; it is not wired to a physical serial bridge, and a software flag cannot keep a link alive if the process dies, so it is **not** a hardware fail-open.
- **Enhanced Flight Track & Altitude Profile (`MapPanel.tsx`)**:
  - Context-aware attack and protected labels (`FORCED LAND (BLOCKED)`, `REPLAYED RTL (BLOCKED)`, `ROGUE GUIDED (BLOCKED)`, `DISARM DROP (VETOED)`, `SPOOFED GPS (REJECTED)`, etc.).
  - Real-time vehicle head badge: `[MODE · SPEED m/s · ALT m]`.
  - 44px SVG **Vertical Altitude Profile Strip (`0-100 m`)** plotting `rawAlt` vs `effAlt` with 60m survey baseline.
- **Multi-Layer Defense**:
  - Rule-Based & Protocol (`ProtocolDetector`): Boundary invariants, multi-source provenance, and State-Aware Command Cadence Guard catching duplicate/mid-air disarms (`AF-SEC-01`).
  - Stateful Physical Kinematics (`PhysicsDetector`): 3-axis acceleration, jerk bounds, Doppler vs GPS velocity residuals, plus a 2D vector CUSUM integrator (`CusumDriftIntegrator`) aimed at micro-drift of $0.15\text{–}0.30\text{ m/s}$ (`AF-SEC-02`). It is unit-tested as a class only; `cusum_enabled` is **off by default** (no `cusum` key in `configs/detector.yaml`) and it is in no benchmark, so micro-drift detection is **not** claimed (`docs/VALIDATION_EVIDENCE.md` §3).
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
- Unit & Integration: `pytest -q` prints the current count; the last integration-candidate run is recorded in `docs/GPS_WORKSTREAM_PROGRESS.md`.
- `scripts/verify_stage2.py`: a demo on hand-built inputs (SIM); not validation evidence.
- Benchmarks and external replays: see `docs/VALIDATION_EVIDENCE.md` (no IEEE T-ITS or mIDS-UAV results exist in this repository).
- Static & Build Analysis: `ruff check src tests scripts` 0 errors; `npm --prefix frontend run build` 0 TypeScript errors (259 ms); `cargo check` 0 errors.

## 6. Third-party agent skills
- Optional, installed only by a person after review (`docs/SKILLS_REGISTRY.md`); agents never install packages on their own.
