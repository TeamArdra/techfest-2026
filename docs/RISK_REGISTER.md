# AegisFlight Intrusion Detection System — Formal Risk Register

**Project:** PUSHPAK Grand Challenge 3: Security of Drones, Objective 2  
**Document:** Stage 2 Mandatory Deliverable — Risk Register (Report Section 10)  
**Classification:** Technical & Operational Engineering Document  
**Version:** 2.0 (Post-Hardware Benchmarking & GCS Integration)  
**Last Updated:** October 2026  

---

## 1. Overview & Risk Assessment Methodology

The AegisFlight Intrusion Detection System (IDS) is designed to operate onboard a drone (running on a companion computer such as a Raspberry Pi Zero 2W or Raspberry Pi 4 paired with a Pixhawk 6X flight controller) or at a Ground Control Station (GCS). Because an onboard cybersecurity system operates within physical proximity to flight-critical avionics, the primary design imperative is **non-interference with flight safety** (`bytes_sent = 0` passive tap principle).

Risks are assessed using a standard qualitative risk matrix based on **Likelihood** (1–5) and **Severity** (1–5):

### Likelihood Scale
- **1 (Rare):** Highly improbable; not observed in testing or bench trials.
- **2 (Unlikely):** Unlikely under standard operations; possible under edge-case flight conditions.
- **3 (Possible):** Feasible under specific environmental or operational conditions.
- **4 (Likely):** Anticipated to occur occasionally without active countermeasures.
- **5 (Almost Certain):** Inevitable under continuous long-duration operations unless mitigated.

### Severity / Impact Scale
- **1 (Negligible):** Minor log artifact or cosmetic display anomaly; zero impact on detection or flight.
- **2 (Minor):** Localized detection delay (<500 ms) or transient false indicator; no impact on flight stability.
- **3 (Moderate):** Temporary loss of secondary detection capability or elevated operator alert load; flight remains safe.
- **4 (Major):** Degradation of primary detection capabilities or failure of tamper-evidence under attack.
- **5 (Catastrophic):** Interference with flight control, telemetry link failure, or total silent compromise of IDS.

### Risk Score Matrix
$$\text{Risk Score} = \text{Likelihood} \times \text{Severity}$$
- **Low (1–5):** Acceptable with standard operating controls.
- **Medium (6–11):** Mitigations required; residual risk actively monitored.
- **High (12–19):** Stringent architectural or hardware mitigations mandatory.
- **Critical (20–25):** Unacceptable; requires fail-safe architectural redesign.

---

## 2. Risk Register Matrix

| Risk ID | Category | Risk Description & Root Cause | Pre-Mit. L×S | Score | Mitigation Strategy in AegisFlight | Residual L×S | Res. Score | Verification & Traceability |
|:---|:---|:---|:---:|:---:|:---|:---:|:---:|:---|
| **RSK-01** | Avionics Safety | **Accidental Transmission / Bus Contention:** IDS TX line transmits data onto the flight controller's telemetry UART port, causing frame collision, GCS disconnect, or autopilot command lockup. | 4 × 5 | **20 (Crit)** | **Physical Hardware Isolation:** Hardware harness physically cuts/disconnects the companion TX pin. Only the RX wire and ground are attached to the Pixhawk TELEM port. Software enforces `bytes_sent = 0`. Active notifications (`--gcs-notify`) default to OFF and, when enabled, route exclusively via a dedicated secondary network (Ethernet/UDP) or secondary telemetry radio, never the primary C2 bus. | 1 × 5 | **5 (Low)** | `scripts/hardware/run_serial_ids.py`, `src/aegisflight/mavlink/gcs_notifier.py`, `docs/SERIAL_TRANSPORT.md` |
| **RSK-02** | Electrical / Power | **Companion Power Brownout:** High motor throttle or battery voltage sag drops the companion computer's 5V rail below brownout threshold (~4.63V on Raspberry Pi), causing abrupt crash or filesystem corruption. | 4 × 4 | **16 (High)** | **Isolated Dedicated BEC:** Onboard BOM specifies a dedicated 5V 3A DC-DC step-down buck converter (BEC) tapped directly from the main PDB, isolated from flight controller servo rails. Filesystem uses read-only overlay root with append-only write-ahead log (`WAL`) using synchronous `fdatasync()`. | 1 × 3 | **3 (Low)** | `docs/ONBOARD_DEPLOYMENT.md`, `tests/unit/test_event_store.py` |
| **RSK-03** | Performance / Compute | **Compute & Thermal Exhaustion (DoS Flood):** High MAVLink frame bursts (500+ Hz DoS attack or telemetry storm) saturate companion CPU, leading to thread lockup, thermal throttling, and dropped frames. | 4 × 3 | **12 (High)** | **Bounded Buffers & O(1) Sliding Windows:** Ring buffers bounded to 1,000 frames (8 MiB memory cap). Fast C-based pymavlink frame parser. Protocol and physics detectors operate strictly at $O(1)$ per message. Benchmarked compute footprint is <15% single-core on Pi Zero 2W and <5% on Pi 4. | 1 × 2 | **2 (Low)** | `src/aegisflight/sources/mavlink_live.py`, `tests/benchmarks/test_throughput.py`, `artifacts/benchmarks/summary.md` |
| **RSK-04** | Operational / Usability | **Operator Alert Fatigue (False Alarms):** Dynamic maneuvers, aerodynamic turbulence, or urban canyon GPS noise trigger false intrusion alarms, causing the pilot to dismiss legitimate attacks or abort missions. | 4 × 3 | **12 (High)** | **Multi-Detector Noisy-OR Fusion & Persistence Gating:** Single-frame outliers are filtered via sliding-window persistence thresholds ($N \ge 3$ consecutive frames). Multi-detector noisy-OR fusion suppresses single-sensor glitches. Poisson 95% false-alarm upper bound is proven at $\le 0.20/\text{hr}$ on real flight datasets. Plaintext telemetry evidence strings accompany every alert. | 2 × 2 | **4 (Low)** | `src/aegisflight/core/fusion.py`, `docs/VALIDATION_EVIDENCE.md`, `tests/unit/test_fusion.py` |
| **RSK-05** | Detection Capability | **Adversarial Evasion via Subtle Gradual Drift:** Attacker injects slowly ramping GPS coordinates or telemetry offsets ($<0.05\,\text{m/s}^2$) designed to remain below single-frame anomaly thresholds. | 3 × 4 | **12 (High)** | **Cumulative Kinematic Integration:** Physics detector tracks integrated displacement using the Haversine formula against cumulative integrated GPS ground velocity vector ($\int \vec{v}_{\text{ground}}\,dt$). As drift accumulates over 2–5 seconds, the divergence $\Delta d$ triggers a deterministic physics violation. | 2 × 2 | **4 (Low)** | `src/aegisflight/detectors/physics.py`, `tests/unit/test_physics_detector.py`, `artifacts/benchmarks/summary.md` |
| **RSK-06** | Detection Capability | **GCS Masquerading & Packet Replay:** Attacker spoofs GCS system ID (`sysid = 255`) and injects malicious mode change (`RTL`, `LAND`) or disarm commands with matching system IDs. | 4 × 4 | **16 (High)** | **Sequence Discontinuity & MAVLink-2 Signature Inspection:** Protocol detector tracks strict monotonically increasing sequence counters per system/component pair. Out-of-window packet sequences, replay packet bursts, and duplicate packet IDs are flagged immediately. Pluggable hook for MAVLink-2 cryptographic signature verification. | 2 × 2 | **4 (Low)** | `src/aegisflight/detectors/protocol.py`, `src/aegisflight/proxy/hooks.py`, `tests/unit/test_protocol_detector.py` |
| **RSK-07** | Operational / Environment | **GPS RF Multipath & Foliage Shading:** Dense vegetation or reflective building structures cause legitimate satellite signal degradation (HDOP degradation, loss of lock), simulating spoofing characteristics. | 3 × 3 | **9 (Med)** | **Dual-State Protocol Gating:** Detector inspects `GPS_RAW_INT` satellite count (`fix_type`, `satellites_visible`). If HDOP rises while satellite count drops, signal degradation is classified as benign environment noise. If position jumps abruptly while satellite count remains artificially pristine (`fix_type=3`, `satellites_visible \ge 12`, `eph < 100`), spoofing alarm triggers. | 2 × 2 | **4 (Low)** | `src/aegisflight/detectors/physics.py`, `src/aegisflight/detectors/protocol.py` |
| **RSK-08** | Security / Audit | **Log Tampering & Incident Concealment:** An adversary gaining root access to the companion computer modifies or deletes stored alert logs to erase evidence of intrusion. | 3 × 4 | **12 (High)** | **Cryptographic Rolling Hash-Chain:** Every telemetry frame, decision, and alert is serialized to canonical JSON and hashed with SHA-256 in a rolling hash-chain ($H_i = \text{SHA-256}(H_{i-1} \parallel E_i)$). Any insertion, deletion, or modification invalidates the chain; verifiable offline with zero external dependencies. | 1 × 3 | **3 (Low)** | `src/aegisflight/core/event_store.py`, `tests/unit/test_event_store.py` |
| **RSK-09** | Physical / Hardware | **UART Framing Errors & Baud Rate Drift:** Thermal fluctuations or clock oscillator drift between Pixhawk and companion computer cause bit slippage and frame synchronization loss. | 3 × 3 | **9 (Med)** | **Magic-Byte Resynchronization:** Serial parser scans for MAVLink v2 `0xFD` (or v1 `0xFE`) magic bytes on every byte drop; incomplete or framing-corrupted frames are discarded safely without buffer growth or process crash. | 1 × 2 | **2 (Low)** | `src/aegisflight/sources/mavlink_live.py`, `tests/unit/test_mavlink_live.py` |
| **RSK-10** | Algorithmic Integrity | **Sim-to-Real Distribution Shift in Machine Learning:** Supervised or uncalibrated anomaly detection models trained on simulation produce high false alarms when exposed to real-world flight dynamics. | 4 × 3 | **12 (High)** | **Decoupled Architecture & Safe Serial Default:** Uncalibrated ML models are explicitly disabled on live serial hardware streams by default. Real-time hardware detection is anchored on deterministic Protocol and Physics detectors. ML requires per-vehicle baseline calibration using benign flight data before activation. | 1 × 2 | **2 (Low)** | `scripts/hardware/run_serial_ids.py`, `docs/CALIBRATION_PX4.md`, `tests/unit/test_ml_pipeline.py` |
| **RSK-11** | Integration / Network | **GCS Notification Flooding & HUD Congestion:** In the event of a sustained attack or high alert volume, MAVLink `STATUSTEXT` broadcaster overwhelms the GCS message console. | 3 × 3 | **9 (Med)** | **Strict 1.0s Deduplication Cooldown:** The `GcsNotifier` implements a mandatory 1.0-second cooldown per attack class. Redundant alerts within the cooldown window are suppressed from GCS transmission while remaining logged in the local tamper-evident event store. | 1 × 2 | **2 (Low)** | `src/aegisflight/mavlink/gcs_notifier.py`, `tests/unit/test_gcs_notifier.py` |
| **RSK-12** | Firmware Security | **Firmware Attestation False Mismatch:** Legitimate flight controller firmware update or parameter reload is flagged as malicious tampering. | 2 × 3 | **6 (Med)** | **Operator-Controlled Manifest Baseline:** Firmware manifest (`manifest.json`) stores SHA-256 hashes of authorized builds and parameter sets. Manifest updates require explicit cryptographic re-signing by the ground station operator during maintenance mode. | 1 × 2 | **2 (Low)** | `src/aegisflight/detectors/firmware.py`, `tests/unit/test_firmware_detector.py` |

---

## 3. High-Priority Risk Mitigation Deep Dives

### 3.1 Non-Interference Safety Architecture (RSK-01)
To satisfy the competition mandate that the IDS must not disturb normal flight operations under any failure mode:
1. **Physical Layer:** The telemetry harness connects only Pixhawk `TX` to Companion `RX`, and `GND` to `GND`. The Pixhawk `RX` pin remains completely unconnected.
2. **Electrical Layer:** Even if the companion computer suffers complete hardware failure, short-circuit, or power brownout, no voltage can back-feed into the autopilot telemetry UART.
3. **Software Layer:** The serial ingest loop runs in read-only mode (`serial.Serial(..., timeout=0.1)`), never issuing writes to the port.

```mermaid
flowchart LR
    subgraph Pixhawk6X["Pixhawk 6X Autopilot"]
        TX_PIN["TELEM2 TX Pin"]
        RX_PIN["TELEM2 RX Pin (Floating / No Wire)"]
        GND_PIN["Ground Pin"]
    end

    subgraph Companion["Raspberry Pi Zero 2W"]
        PI_RX["GPIO 15 (UART RX)"]
        PI_GND["GND"]
    end

    TX_PIN -->|Physical Wire Only| PI_RX
    GND_PIN --- PI_GND
    RX_PIN -.x|PHYSICALLY CUT WIRE| Companion
```

### 3.2 Power Supply & Vibration Hardening (RSK-02)
- **Power:** Standard 5V BECs supplied with flight controllers often share rails with servo outputs, which suffer inductive voltage spikes during hard motor reversals. AegisFlight mandates a dedicated 5V 3A buck regulator wired to the main battery power distribution board (PDB).
- **Vibration:** Companion boards are mounted on silicone anti-vibration damping standoffs ($4\times M2.5$ silicone bobbins) to eliminate microphonic sensor noise and prevent connector fatigue during high-RPM flight.

### 3.3 Subtle Attack Kinematic Accumulator (RSK-05)
To defeat slowly ramping coordinate drift attacks that bypass single-frame threshold checks:
$$\Delta \vec{p}_{\text{residual}}(t) = \|\vec{p}_{\text{GPS}}(t) - \vec{p}_{\text{integrated}}(t)\|$$
$$\vec{p}_{\text{integrated}}(t) = \vec{p}_{\text{GPS}}(t_0) + \int_{t_0}^{t} \vec{v}_{\text{ground}}(\tau)\,d\tau$$
When $\Delta \vec{p}_{\text{residual}}(t) > \epsilon_{\text{drift}}$ (configured to $5.0\,\text{m}$ for multirotors over a 3.0s window), a `PHYSICS_DISCREPANCY` alert is asserted with severity `CRITICAL`.

---

## 4. Maintenance, Review & Audit Protocol

1. **Pre-Flight Inspection Checklist:**
   - [ ] Verify physical TX wire isolation on TELEM2 harness.
   - [ ] Verify dedicated 5V BEC voltage is within $5.05\text{V} \pm 0.15\text{V}$.
   - [ ] Confirm SD card write speed $\ge 20\,\text{MB/s}$ (Class 10 / U3).
   - [ ] Verify SHA-256 firmware manifest matches installed autopilot build.
2. **Post-Flight Audit Checklist:**
   - [ ] Extract tamper-evident event log from companion `/var/log/aegisflight/events.jsonl`.
   - [ ] Execute `scripts/verify_event_chain.py` to confirm hash-chain integrity.
   - [ ] Review any generated alerts against Mission Planner / QGC telemetry logs.
   - [ ] Log any unexplained warnings in this Risk Register under revision history.

---

## 5. Risk Assessment Sign-off

| Role | Responsibility | Status |
|:---|:---|:---:|
| **Security Lead** | Attack coverage & evasion vulnerability assessment | **Approved** |
| **Avionics Lead** | Electrical isolation, bus safety & telemetry non-interference | **Approved** |
| **Systems Engineer** | Compute budget, thermal stability & buffer bounds | **Approved** |
| **Flight Test Pilot** | Operator HUD usability & alert fatigue evaluation | **Approved** |
