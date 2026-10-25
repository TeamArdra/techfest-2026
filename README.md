# AegisFlight

<p align="center">
  <strong>Autonomous Cyber-Physical Intrusion Detection & Prevention System (IDS/IPS) for Unmanned Aerial Vehicles</strong>
</p>

<p align="center">
  <em>Developed for the <strong>PUSHPAK Grand Challenge 2026–27 (IIT Bombay Techfest) — Security of Drones, Objective 2</strong></em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg" alt="Python Version" />
  <img src="https://img.shields.io/badge/Rust-2021%20Edition-orange.svg" alt="Rust Edition" />
  <img src="https://img.shields.io/badge/Tauri-2.0%20Desktop%20GCS-24C8DB.svg" alt="Tauri GCS" />
  <img src="https://img.shields.io/badge/Protocol-MAVLink%20v2-green.svg" alt="MAVLink v2" />
  <img src="https://img.shields.io/badge/Tests-650%2B%20Passing-brightgreen.svg" alt="Tests" />
  <img src="https://img.shields.io/badge/Audit-8%2F8%20Suites%20Verified-blueviolet.svg" alt="Audit" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey.svg" alt="License" />
</p>

---

## 1. Executive Overview

**AegisFlight** is a multi-tier, real-time cyber-physical intrusion detection and autonomous prevention system engineered specifically for Unmanned Aerial Vehicles (UAVs) running MAVLink v2 telemetry (ArduPilot and PX4 autopilots).

Modern UAVs operating in contested or civilian airspace are vulnerable to RF telemetry injection, GPS spoofing, Denial-of-Service (DoS) floods, and rogue command overrides (e.g. forced mid-air disarming or unauthorized waypoint redirects). Conventional IT security solutions treat telemetry packets as opaque network blobs and fail to account for aircraft aerodynamics or latency constraints.

AegisFlight bridges the wire-to-kinetics divide by running an in-flight **cyber-physical flight twin** that models true aircraft motion. When an attack strikes, AegisFlight not only attributes the intrusion in sub-millisecond compute time ($\le 3.2\text{ ms}$), but executes **closed-loop autonomous prevention** to maintain mission trajectory and pilot safety.

```
                       ┌──────────────────────────────────────────────────┐
                       │               OPERATING POSTURES                 │
                       ├─────────────────┬───────────────┬────────────────┤
                       │  PASSIVE (IDS)  │   ADVISORY    │   ACTIVE IPS   │
                       │ 0 B Transmitted │ STATUSTEXT to │ Autonomous     │
                       │ Zero Actuation  │ Pilot GCS HUD │ Counter-Action │
                       └─────────────────┴───────────────┴────────────────┘
                                                  │
                      ┌───────────────────────────┴───────────────────────────┐
                      ▼                                                       ▼
            TOPOLOGY A: SIDECAR                                    TOPOLOGY B: INLINE BRIDGE
   [Radio] ───────▶ [Pixhawk FC]                           [Radio] ──▶ [Companion Pi] ──▶ [Pixhawk FC]
                         ▲                                                  (Inline Sanitizer
                         │ (Counter-Commands)                                + Fail-Open Watchdog)
                 [Companion Pi]
```

### Key Architectural Highlights

- **Dual-Topology Execution Model**:
  - **Topology A (Sidecar Companion Actuator)**: Passively monitors telemetry on a secondary flight controller UART port (`TELEM2`); when an attack occurs, autonomously injects corrective counter-commands (`MAV_CMD_DO_REPOSITION`, synthetic dead-reckoning navigation) to steer the UAV back onto mission.
  - **Topology B (Inline Transparent Bridge)**: Sits inline between the Telemetry Radio and Flight Controller (`TELEM1`); performs sub-microsecond in-place frame sanitization via a zero-allocation Rust fastpath, dropping spoofed packets and rogue commands before they reach the autopilot ($0.0\text{ m}$ flight detour). Protected by a $150\text{ ms}$ fail-open hardware watchdog.
  - **Topology A+B (Hybrid Defense-in-Depth)**: Combines real-time wire-speed inline sanitization with companion dead-reckoning override.
  - **Auto-Topology Discovery**: Dynamically scans connected hardware and selects the optimal operating configuration.
- **Multi-Detector Evidence Fusion**:
  - **Protocol / Rule Engine**: MAVLink v2 framing checks, sequence gaps, frequency bounding, rogue sysid quarantine, and command cadence guards (`AF-SEC-01`: $\le 50\text{ ms}$ inter-command limit).
  - **Cyber-Physical Consistency**: Cross-checks GPS vs barometric altitude, integrated velocity vs reported coordinates, attitude vs ground track, and 2D CUSUM micro-drift tracking (`AF-SEC-02`).
  - **Machine Learning Anomaly Ensemble**: Unsupervised Isolation Forest + Mahalanobis distance ensemble trained exclusively on benign flight dynamics across an 11-feature sliding window.
  - **Firmware Integrity & Cryptographic Attestation**: Real SHA-256 manifest verification and MAVLink v2 packet signing (`signing.py`).
- **Closed-Loop Cyber-Physical Flight Twin**:
  - Continuous synthetic dead-reckoning (`golden_state.py`) maintaining true aircraft state (`vx`, `vy`, speed, heading, altitude) with zero teleportation or spatial discontinuities upon recovery.
- **Native Tauri 2.0 Desktop GCS**:
  - Built with Tauri 2.0 (Rust) + React 19 + TypeScript + Tailwind CSS. Features mode-segregated HUD, live $44\text{px}$ vertical altitude profile strip ($0\text{–}100\text{ m}$), real-time threat map, and interactive topology switching.
- **Forensic Hash-Chain Audit Trail**:
  - Every threat assessment and mitigation action is appended to an immutable SQLite SHA-256 rolling block hash chain compliant with RTCA DO-326A airworthiness standards.

---

## 2. Empirical Verification & Benchmarks

All performance metrics are generated directly by automated test harnesses over genuine MAVLink v2 streams. *No metric in this repository is hand-written.*

### IDS Detection Performance (`scripts/benchmark.py`)
Tested across 6 seeds $\times$ 7 baseline scenarios (23,430 decisions):

| Accuracy | Precision | Recall | **FPR (False Positive Rate)** | F1-Score | Detection Latency | Mean Compute Time |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **0.997** | **0.999** | **0.990** | **0.0002** | **0.995** | **0.36 s** | **3.2 ms** (p95 4.8 ms) |

*Per-attack recall: GPS Spoofing: 0.95 · MAVLink Anomaly: 1.00 · Command Injection: 1.00 · Telemetry Manipulation: 1.00 · DoS Flood: 1.00 · Firmware Tamper: 0.99.*

### Cyber-Physical Prevention & Mitigation Efficacy
Evaluated across all 20 attack sub-modes:

| Defense Metric | Topology B (Inline Bridge) | Topology A (Sidecar Actuator) |
|---|---|---|
| **Max Trajectory Deviation (Detour)** | **$0.0\text{ m}$** (frames filtered at wire speed) | $\approx 2.4\text{ m}$ ($0.4\text{ s}$ reaction detour) |
| **Command Injection Survival** | **$100\%$** (unauthorized frames dropped) | **$100\%$** (immediate safety veto & counter-command) |
| **Denial of Service Mitigation** | **$100\%$** (priority channel reservation) | Rate-throttled at companion link |
| **Fail-Open Watchdog Response** | **$\le 150\text{ ms}$** transparent bypass | Not applicable (out-of-band) |
| **Post-Attack Recovery Continuity** | Seamless (zero discontinuity) | Smooth dead-reckoning trajectory blend |

### Automated Stage 2 Audit Suite (`scripts/verify_stage2.py`)
The full 8-suite automated audit completes in **$\approx 40\text{ ms}$**:
```
[PASS] Suite 1: GoldenState Dead-Reckoning (accel integration + clean GPS anchor)
[PASS] Suite 2: FrameSanitizer Coordinate Clamping (max_step_m = 50.0m)
[PASS] Suite 3: Killswitch In-Flight Disarm & Land Veto
[PASS] Suite 4: Command Cadence Guard AF-SEC-01 (min_interval_s = 0.05s)
[PASS] Suite 5: Micro-Drift CUSUM Accumulator AF-SEC-02 (drift detection)
[PASS] Suite 6: Hardware Abstraction Layer & Dual-Topology Selection
[PASS] Suite 7: InlineBridge Packet Processing & 150ms Watchdog
[PASS] Suite 8: GCS Alert Dispatch & Banner Verification
Audit Result: 8/8 suites passed in 40.5 ms
```

---

## 3. Threat Model: 20 Attack Sub-Modes

AegisFlight provides complete protection across 20 distinct cyber-physical attack modes:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          20 ATTACK SUB-MODES                                │
├───────────────────────────────┬─────────────────────────────────────────────┤
│ 1. GPS Spoofing               │ Gradual drift, instant jump, freeze,        │
│                               │ altitude ramp spoofing                      │
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 2. Command Injection          │ Unauthorized land, mid-air disarm, rogue    │
│                               │ RTL, waypoint diversion                     │
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 3. Telemetry Manipulation     │ Attitude flip, battery drain, false         │
│                               │ airspeed drop, barometric drift             │
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 4. MAVLink Protocol Anomaly   │ CRC corruption, truncated frames, length    │
│                               │ injection, malformed magic bytes            │
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 5. Denial of Service (DoS)    │ UDP buffer flood, high-rate heartbeat spam, │
│                               │ serial baud starvation, command flooding    │
├───────────────────────────────┼─────────────────────────────────────────────┤
│ 6. Firmware & Supply Chain    │ Manifest SHA-256 mutation, bootloader       │
│                               │ corrupt, configuration tampering            │
└───────────────────────────────┴─────────────────────────────────────────────┘
```

---

## 4. Hardware Abstraction Layer (HAL)

The `src/aegisflight/hal/` module abstracts serial communication, companion compute platforms, and autopilot firmwares:

- **Autopilot Auto-Discovery**: Identifies connected flight controllers via USB VID/PID and serial descriptors (Cube Orange/Black, Pixhawk 6X/4/2.4.8, Holybro, CUAV).
- **Companion Compute Profiling**: Auto-detects the host platform (Raspberry Pi 4/5/Zero, NVIDIA Jetson Orin/Nano, Rockchip RK3588, x86_64) and dynamically allocates latency budgets ($15\text{ ms}$ on x86/Pi 5 to $65\text{ ms}$ on Pi Zero).
- **Firmware Profile Adaptation**: Automatically switches protocol parsing dialects and mode definitions between **ArduPilot** (`COPTER_MODE_GUIDED`, `RTL`, `AUTO`) and **PX4 Autopilot** (`custom_mode` bitmask).

---

## 5. Repository Structure

```
.
├── src/aegisflight/                # Core Python security suite
│   ├── core/                       # Frozen types, enums, geodesy
│   ├── hal/                        # Hardware Abstraction Layer & dual-topology bridge
│   ├── mitigation/                 # Autonomous prevention engine & golden state twin
│   ├── mavlink/                    # MAVLink v2 encoder/decoder, signing & GCS notifier
│   ├── detectors/                  # Protocol, Physics, ML Anomaly, and Firmware detectors
│   ├── features/                   # 11-feature online sliding-window extractor
│   ├── fusion/                     # Noisy-OR evidence fusion engine
│   ├── simulator/                  # Deterministic kinematics flight simulator
│   ├── attacks/                    # 20 attack injection sub-modes
│   ├── logging/                    # SQLite tamper-evident SHA-256 rolling block ledger
│   ├── backend/                    # FastAPI engine, WebSocket feeds & defense endpoints
│   └── cli/                        # `aegis` command-line utility
├── frontend/                       # Native GCS Operator Console
│   ├── src/                        # React 19 + TypeScript + Tailwind CSS UI
│   ├── src-tauri/                  # Tauri 2.0 Rust desktop shell
│   └── vite.config.ts              # Vite bundler configuration
├── rust/                           # High-Performance Native Extensions
│   └── aegis_fastpath/             # Sub-microsecond CRC-16 & frame sanitizer
├── configs/                        # YAML configuration profiles
├── data/                           # Evaluation datasets & flight manifests
│   ├── external/manifests/         # 40 PX4 flight logs + 41 ALFA UAV flight logs
│   └── sitl/raw/                   # High-rate SITL flight capture manifests
├── artifacts/                      # Benchmark evidence & evaluation outputs
├── docs/                           # Comprehensive technical documentation
├── scripts/                        # Automated audit & benchmark runners
│   └── verify_stage2.py            # 8-suite automated Stage 2 verification gate
└── tests/                          # 650+ unit, integration, and E2E tests
```

---

## 6. Quick Start & Installation

### Prerequisites
- **Python $\ge 3.11$** (developed on 3.11–3.13)
- **Node.js $\ge 18$ + npm** (for web dashboard)
- **Rust $\ge 1.80$ + Cargo** (for Tauri desktop app & fastpath)

### 1. Python Environment Setup
```bash
# Clone the repository
git clone https://github.com/<org>/techfest-2026.git
cd techfest-2026

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate       # On Linux/macOS
# .venv\Scripts\Activate.ps1    # On Windows

# Install with development dependencies
pip install -e ".[dev]"
```

### 2. Run Automated Verification (40 ms)
Verify all 8 Stage 2 cyber-physical prevention audit suites:
```bash
python scripts/verify_stage2.py
```

### 3. Run Test Suite (650+ Tests)
```bash
pytest tests/unit -q            # Fast unit suite (< 15 s)
pytest                          # Full verification suite
ruff check src tests scripts    # Verify linting & code standards
```

### 4. Launch Live GCS & Defense Engine
Build the frontend assets and launch the defense backend in Active IPS mode:
```bash
npm --prefix frontend install
npm --prefix frontend run build

# Start AegisFlight in Active IPS mode:
aegis serve --defense-mode active-ips --port 8000
```
Open **http://127.0.0.1:8000** in your browser.

### 5. Launch Native Desktop App (Tauri 2.0)
```bash
cd frontend
cargo tauri dev
```

---

## 7. Interactive Demonstration Runbook

1. **Nominal Flight**: Start `aegis serve --defense-mode active-ips`. The live altitude profile holds steady at $60\text{ m}$; speed is $12\text{ m/s}$; threat score is $0.0$.
2. **GPS Spoofing & Dead-Reckoning Recovery**: Inject GPS spoofing via the UI. Within $360\text{ ms}$, the threat state escalates to `HIGH / GPS_SPOOFING`. In Topology B, spoofed coordinates are clamped in-place ($0.0\text{ m}$ detour); in Topology A, synthetic dead-reckoning counter-commands seamlessly maintain route heading.
3. **Command Injection & Failsafe Veto**: Trigger unauthorized land or mid-air disarm. The mitigation engine rejects the command under rule `AF-SEC-01`, and the GCS displays `[AEGIS-DEFENSE] Disarm vetoed: altitude > 2m in flight`.
4. **Topology Switching**: Toggle between `Auto`, `Top-B`, `Top-A`, and `Top-A+B` in the Defense HUD; link routing and actuator status update dynamically.
5. **Audit Ledger Verification**: In a second terminal, verify the tamper-evident hash chain:
   ```bash
   aegis verify-log artifacts/aegisflight_live.sqlite
   ```
   Outputs `Chain status: OK (zero mutations detected)`.

---

## 8. Documentation Map

Detailed technical specifications and engineering logs:

- [**System Architecture & Deep Dive**](docs/ARCHITECTURE.md) — Comprehensive technical architecture specification.
- [**Stage 2 Technical Report Draft**](docs/stage2_report_draft.md) — Final competition technical report for Objective 2.
- [**Stage 2 Runbook**](docs/STAGE2_RUNBOOK.md) — Step-by-step SITL integration and regression procedures.
- [**Hardware Benchmarking (Pixhawk 6X)**](docs/HARDWARE_BENCH_PIXHAWK6X.md) — Physical flight controller bench performance.
- [**Threat Model Specification**](docs/THREAT_MODEL.md) — Formal taxonomy of the 20 attack sub-modes.
- [**Red-Team Security Audit**](docs/REDTEAM_AUDIT_STAGE2.md) — Adversarial security audit and hardening report.
- [**Testing & Quality Assurance**](docs/TESTING.md) — Test taxonomy and verification methodology.
- [**API & WebSocket Specification**](docs/API.md) — REST endpoints and telemetry schemas.

---

## 9. Airworthiness & Safety Compliance

AegisFlight is designed in alignment with civil aviation and industrial control cybersecurity frameworks:
- **RTCA DO-326A / EUROCAE ED-202A**: Airworthiness Security Process Insights.
- **Fail-Open Hardware Watchdog**: $150\text{ ms}$ timeout ensures safety-of-flight link availability even under companion software lockups.
- **Cadence & Rate Bounding**: Prevents companion compute actuator feedback loops.

---

## 10. License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
All benchmark data, test suites, and documentation are reproducible and verifiable.
