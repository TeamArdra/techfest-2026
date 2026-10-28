# AegisFlight — Stage 2 Demonstration Runbook

For demonstrating the Stage 2 UAV Intrusion Detection & Autonomous Prevention
System (IDS/IPS) for **PUSHPAK Grand Challenge 2026-27 (IIT Bombay Techfest) — Security of Drones, Objective 2**.
A teammate can run this without the original author.

## Pre-demo checklist
```bash
pip install -e ".[dev]"                       # deps installed
aegis train                                   # models/isoforest.joblib exists
npm --prefix frontend install && npm --prefix frontend run build   # frontend/dist exists
python scripts/verify_stage2.py               # 8/8 automated verification suites passing
pytest tests/unit/test_mitigation.py tests/unit/test_hal.py -q   # 34 tests passing
```
- Close other apps using port 8000.
- Have `aegis verify-log` ready in a second terminal.

## Startup
```bash
aegis serve --defense-mode active-ips         # http://127.0.0.1:8000
```
Or launch the native desktop GCS:
```bash
cd frontend && cargo tauri dev
```
The GCS displays:
- **● ACTIVE IPS** (Autonomous Mitigation Enabled)
- **● Connected** (10 Hz WebSocket telemetry)
- **Topology: Auto (Top-B: Inline Transparent Bridge)**
- **Live Vehicle Head Pill**: `[COPTER_MODE_GUIDED · 12.0 m/s · 60.0 m]`
- **44px Vertical Altitude Profile Strip**: showing real-time 0–100 m elevation track.

## Segment 1 — Benign Flight Baseline (~20 s)
- Point out the nominal survey pattern on the satellite map.
- Altitude strip holds flat at 60 m cruise; speed is 12 m/s.
- Threat score sparkline remains flat at 0.0 (below 0.45 threshold); 0 false alarms.

## Segment 2 — GPS Spoofing & Synthetic Navigation Recovery
- Click **GPS Spoofing**.
- **Detection**: Within 360 ms, Physics + Anomaly detectors trigger (`HIGH / GPS_SPOOFING`).
- **Autonomous Mitigation**:
  - In **Topology B** (Inline): `FrameSanitizer` drops/clamps spoofed coordinates in-place before reaching the autopilot (0.0 m flight detour).
  - In **Topology A** (Sidecar): `GoldenFlightState` dead-reckoning supplies trusted coordinates and the dashboard shows the counter-command (EKF source switch / mode restore) the actuator would encode; nothing is transmitted.
- Notice the vehicle track continues smoothly along the planned trajectory without jumping or diverging.

## Segment 3 — Command Injection & Failsafe Veto
- Click **Command Injection** (e.g., unauthorized land or forced disarm).
- **Veto Execution**: Mitigation engine detects cadence/provenance violation (`AF-SEC-01`), rejects the rogue command, and notifies the GCS via `STATUSTEXT` banner: `[AEGIS-DEFENSE] Disarm vetoed: altitude > 2m in flight`.
- Vehicle remains airborne and continues mission uninterrupted.

## Segment 4 — Denial of Service & High-Rate Flood
- Click **Denial of Service**.
- Threat state escalates to `CRITICAL / DOS`.
- `FloodMitigator` isolates the rogue telemetry stream; heartbeat and critical attitude frames are preserved on priority channels.

## Segment 5 — Hardware Abstraction Layer & Topology Switching
- In the **Defense HUD**, switch topology selector between:
  - **Auto**: Discovers serial ports/VIDs and selects best topology.
  - **Top-B (Inline Bridge)**: 0.0 m detour, zero-allocation frame filtering.
  - **Top-A (Sidecar Actuator)**: Secondary companion telemetry override.
  - **Top-A+B (Hybrid)**: Maximum resilience (inline filter + companion actuator).
  - **IDS Only (Passive)**: Monitoring and forensic logging only.
- Point out dynamic routing status cards updating instantly.

## Segment 6 — Tamper-Evident Hash Chain Forensics
- In the second terminal:
  ```bash
  aegis verify-log artifacts/aegisflight_live.sqlite
  ```
- Terminal outputs: `Chain status: OK (N events verified, zero mutations)`.
- Explains the SHA-256 hash chain over alerts (`aegis verify-log`); no airworthiness compliance is claimed.

## Segment 7 — Automated Verification Benchmarks
- Run the full automated verification audit:
  ```bash
  python scripts/verify_stage2.py
  ```
- 8/8 suites pass in ~40 ms:
  1. GoldenState dead-reckoning test
  2. FrameSanitizer coordinate clamping test
  3. Killswitch disarm & land veto test
  4. Command cadence guard test
  5. Micro-drift CUSUM test
  6. HAL discovery & topology test
  7. InlineBridge watchdog test
  8. GCS alert dispatch test

## Shutdown
`Ctrl-C` the server. Clean shutdown leaves SQLite ledger verified.
