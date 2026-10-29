# AegisFlight Intrusion Detection System — Formal Risk Register

> Status (2026-10-27 integration review): a design-intent register. Mitigations describe intended practice;
> anything measured cites its artifact. Nothing here has been tested on a companion computer or in flight.
> Corrected 2026-10-29 (`docs/SUBMISSION_READINESS_AUDIT.md` §4): RSK-02, RSK-05 and RSK-07 described mitigations that
> are not in the code and are rewritten with their residual risk raised; the sign-offs in §5 were removed because no review took place.
> **The remaining "Residual" scores (RSK-01, 03, 04, 08, 09–12) are design-intent estimates, not evidence-based:** e.g. RSK-01 describes a
> TX-cut harness that was never built; RSK-04 sits against 100 % threat rate on real ALFA logs with the Stage-1 config and 5.5–93 % physics
> trigger rates on PX4 Flight Review logs (`artifacts/external/`); RSK-08's unsigned chain can be rewritten by a host-level attacker.

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
| **RSK-01** | Avionics Safety | **Accidental Transmission / Bus Contention:** IDS TX line transmits data onto the flight controller's telemetry UART port, causing frame collision, GCS disconnect, or autopilot command lockup. | 4 × 5 | **20 (Crit)** | **Physical Hardware Isolation:** Hardware harness physically cuts/disconnects the companion TX pin. Only the RX wire and ground are attached to the Pixhawk TELEM port. Software enforces `bytes_sent = 0` (`run_serial_ids.py` exits 3 otherwise; live sources refuse `active-ips`). Notifications (`--gcs-notify`) default to OFF and, when enabled, go only to a loopback UDP target, never the vehicle link (`tests/unit/test_defense_safety.py`). | 1 × 5 | **5 (Low)** | `scripts/hardware/run_serial_ids.py`, `src/aegisflight/mavlink/gcs_notifier.py`, `docs/SERIAL_TRANSPORT.md` |
| **RSK-02** | Electrical / Power | **Companion Power Brownout:** High motor throttle or battery voltage sag drops the companion computer's 5V rail below brownout threshold (~4.63V on Raspberry Pi), causing abrupt crash or filesystem corruption. | 4 × 4 | **16 (High)** | **Dedicated BEC (proposal):** a dedicated 5V 3A DC-DC converter tapped from the main PDB, isolated from servo rails, is a design proposal; **no BOM, harness or kit exists in this repository**. A read-only overlay root and an append-only write-ahead log with synchronous `fdatasync()` are **proposals only**: no such configuration exists in this repository, and nothing here was tested on a companion computer, so the risk is treated as unmitigated. | 4 × 4 | **16 (High)** | `docs/ONBOARD_DEPLOYMENT.md` (design target; nothing measured) |
| **RSK-03** | Performance / Compute | **Compute & Thermal Exhaustion (DoS Flood):** High MAVLink frame bursts (500+ Hz DoS attack or telemetry storm) saturate companion CPU, leading to thread lockup, thermal throttling, and dropped frames. | 4 × 3 | **12 (High)** | **Bounded Buffers & O(1) Sliding Windows:** Ring buffers bounded to 1,000 frames (8 MiB memory cap). Fast C-based pymavlink frame parser. Protocol and physics detectors operate strictly at $O(1)$ per message. Compute on a companion computer has **not been measured** (`docs/ONBOARD_DEPLOYMENT.md`); host figures are in `artifacts/benchmarks/summary.md` (SIM). | 1 × 2 | **2 (Low)** | `src/aegisflight/sources/mavlink_live.py`, `artifacts/benchmarks/summary.md` |
| **RSK-04** | Operational / Usability | **Operator Alert Fatigue (False Alarms):** Dynamic maneuvers, aerodynamic turbulence, or urban canyon GPS noise trigger false intrusion alarms, causing the pilot to dismiss legitimate attacks or abort missions. | 4 × 3 | **12 (High)** | **Multi-Detector Noisy-OR Fusion & Persistence Gating:** Single-frame outliers are filtered via sliding-window persistence thresholds ($N \ge 3$ consecutive frames). Multi-detector noisy-OR fusion suppresses single-sensor glitches. Real-log false-alarm results (per decision, environment-tagged) are in `docs/VALIDATION_EVIDENCE.md`; no per-hour bound is claimed. Plaintext telemetry evidence strings accompany every alert. | 2 × 2 | **4 (Low)** | `src/aegisflight/fusion/engine.py`, `docs/VALIDATION_EVIDENCE.md`, `tests/unit/test_fusion_and_metrics.py` |
| **RSK-05** | Detection Capability | **Adversarial Evasion via Subtle Gradual Drift:** Attacker injects slowly ramping GPS coordinates or telemetry offsets ($<0.05\,\text{m/s}^2$) designed to remain below single-frame anomaly thresholds. | 3 × 4 | **12 (High)** | **Windowed position-vs-velocity residual:** the physics detector compares the last 15 position fixes with the integrated reported velocity (12 m threshold). Drift of roughly 4 m/s or more is caught within seconds in `SIM` and on ArduPilot SITL (+2.69 s); on PX4 SITL it was detected **only at release**, not during the drift. **Not covered:** slower drift (0.5 and 2 m/s were tested and are not flagged) and velocity-consistent drift. A CUSUM micro-drift integrator exists, but `cusum_enabled` is off by default and it is not in any benchmark (`docs/VALIDATION_EVIDENCE.md` §3). | 3 × 4 | **12 (High)** | `src/aegisflight/detectors/physics.py`, `tests/unit/test_gps_scenarios_fused.py` (pinned `KNOWN LIMITATION` cases) |
| **RSK-06** | Detection Capability | **GCS Masquerading & Packet Replay:** Attacker spoofs GCS system ID (`sysid = 255`) and injects malicious mode change (`RTL`, `LAND`) or disarm commands with matching system IDs. | 4 × 4 | **16 (High)** | **Sequence Discontinuity & MAVLink-2 Signature Inspection:** Protocol detector tracks per-source sequence gaps. A one-shot replay from the expected GCS id is a **known gap** (`command_injection:gcs_replay`, `docs/VALIDATION_EVIDENCE.md`); In PX4 SITL (disarmed, one command) an unsigned forged command was rejected by PX4 and flagged by the IDS rule 10/10 once signing was bootstrapped; a replay of a *signed* frame was not tested, and an informed unsigned impersonator evades detection 0/10 (`artifacts/sitl/P4_signing_summary.md`, `P2_gcs_impersonation_summary.md`). | 4 × 4 | **16 (High)** | `src/aegisflight/detectors/protocol.py`, `src/aegisflight/proxy/hooks.py`, `tests/unit/test_missing_telemetry.py` |
| **RSK-07** | Operational / Environment | **GPS RF Multipath & Foliage Shading:** Dense vegetation or reflective building structures cause legitimate satellite signal degradation (HDOP degradation, loss of lock), simulating spoofing characteristics. | 3 × 3 | **9 (Med)** | **Fix-loss rule only:** `fix_type` / `satellites_visible` below `min_gnss_fix_type` (3) / `min_gnss_satellites` (5) raise a persistence-gated "GNSS fix lost" `DOS` alert; a receiver that never acquired a fix is reported as "never acquired". **There is no rule that judges HDOP/`eph` or that separates multipath from spoofing** (an earlier version of this row described a "≥ 12 satellites, `eph` < 100" spoofing rule that does not exist), and a spoofer can report a clean fix. The vehicle's own "no horizontal solution" / "GPS unhealthy" state is shown passively (`navigation_health`), never alerted. | 3 × 3 | **9 (Med)** | `src/aegisflight/detectors/protocol.py` (fix-loss rule), `src/aegisflight/core/gps_health.py`, `tests/unit/test_gps_health.py` |
| **RSK-08** | Security / Audit | **Log Tampering & Incident Concealment:** An adversary gaining root access to the companion computer modifies or deletes stored alert logs to erase evidence of intrusion. | 3 × 4 | **12 (High)** | **Cryptographic Rolling Hash-Chain:** Every alert is serialized to canonical JSON and hashed with SHA-256 in a rolling hash-chain ($H_i = \text{SHA-256}(H_{i-1} \parallel E_i)$). Any insertion, deletion, or modification invalidates the chain; verifiable offline with zero external dependencies. | 1 × 3 | **3 (Low)** | `src/aegisflight/logging/store.py`, `tests/unit/test_integrity_and_logging.py` |
| **RSK-09** | Physical / Hardware | **UART Framing Errors & Baud Rate Drift:** Thermal fluctuations or clock oscillator drift between Pixhawk and companion computer cause bit slippage and frame synchronization loss. | 3 × 3 | **9 (Med)** | **Magic-Byte Resynchronization:** Serial parser scans for MAVLink v2 `0xFD` (or v1 `0xFE`) magic bytes on every byte drop; incomplete or framing-corrupted frames are discarded safely without buffer growth or process crash. | 1 × 2 | **2 (Low)** | `src/aegisflight/sources/mavlink_live.py`, `tests/unit/test_mavlink_live.py` |
| **RSK-10** | Algorithmic Integrity | **Sim-to-Real Distribution Shift in Machine Learning:** Supervised or uncalibrated anomaly detection models trained on simulation produce high false alarms when exposed to real-world flight dynamics. | 4 × 3 | **12 (High)** | **Decoupled Architecture & Safe Serial Default:** Uncalibrated ML models are explicitly disabled on live serial hardware streams by default. Real-time hardware detection is anchored on deterministic Protocol and Physics detectors. ML requires per-vehicle baseline calibration using benign flight data before activation. | 1 × 2 | **2 (Low)** | `scripts/hardware/run_serial_ids.py`, `docs/CALIBRATION_PX4.md`, `tests/unit/test_run_serial_ids.py` |
| **RSK-11** | Integration / Network | **GCS Notification Flooding & HUD Congestion:** In the event of a sustained attack or high alert volume, MAVLink `STATUSTEXT` broadcaster overwhelms the GCS message console. | 3 × 3 | **9 (Med)** | **Strict 1.0s Deduplication Cooldown:** The `GcsNotifier` implements a mandatory 1.0-second cooldown per attack class. Redundant alerts within the cooldown window are suppressed from GCS transmission while remaining logged in the local tamper-evident event store. | 1 × 2 | **2 (Low)** | `src/aegisflight/mavlink/gcs_notifier.py`, `tests/unit/test_gcs_notifier.py` |
| **RSK-12** | Firmware Security | **Firmware Attestation False Mismatch:** Legitimate flight controller firmware update or parameter reload is flagged as malicious tampering. | 2 × 3 | **6 (Med)** | **Operator-Controlled Manifest Baseline:** Firmware manifest (`manifest.json`) stores SHA-256 hashes of authorized builds and parameter sets. The manifest itself is not signed; updating it is a manual operator step (`src/aegisflight/integrity/verifier.py`). | 1 × 2 | **2 (Low)** | `src/aegisflight/detectors/integrity.py`, `tests/unit/test_integrity_and_logging.py` |

---

## 3. High-Priority Risk Mitigation Deep Dives

### 3.1 Non-Interference Safety Architecture (RSK-01)
To satisfy the competition mandate that the IDS must not disturb normal flight operations under any failure mode:
1. **Physical Layer:** The telemetry harness connects only Pixhawk `TX` to Companion `RX`, and `GND` to `GND`. The Pixhawk `RX` pin remains completely unconnected.
2. **Electrical Layer:** Even if the companion computer suffers complete hardware failure, short-circuit, or power brownout, no voltage can back-feed into the autopilot telemetry UART.
3. **Software Layer:** The serial monitor never writes to the port, and a run fails (exit 3) if `bytes_sent` is non-zero.

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
- **Power (design proposal; nothing built):** Standard 5V BECs supplied with flight controllers often share rails with servo outputs, which suffer inductive voltage spikes during hard motor reversals. AegisFlight would require a dedicated 5V 3A buck regulator wired to the main battery power distribution board (PDB).
- **Vibration:** Companion boards are mounted on silicone anti-vibration damping standoffs ($4\times M2.5$ silicone bobbins) to eliminate microphonic sensor noise and prevent connector fatigue during high-RPM flight.

### 3.3 Subtle Attack Kinematic Accumulator (RSK-05)
Design formulation for catching ramping coordinate drift that bypasses single-frame threshold checks. The implemented rule is a 15-fix windowed residual and does **not** catch drift below ~4 m/s (see RSK-05 and `docs/VALIDATION_EVIDENCE.md` §3):
$$\Delta \vec{p}_{\text{residual}}(t) = \|\vec{p}_{\text{GPS}}(t) - \vec{p}_{\text{integrated}}(t)\|$$
$$\vec{p}_{\text{integrated}}(t) = \vec{p}_{\text{GPS}}(t_0) + \int_{t_0}^{t} \vec{v}_{\text{ground}}(\tau)\,d\tau$$
When $\Delta \vec{p}_{\text{residual}}(t) > \epsilon_{\text{drift}}$ (`physics.gps_pos_residual_m`, `configs/detector.yaml`), the physics detector votes `GPS_SPOOFING`.

---

## 4. Maintenance, Review & Audit Protocol

1. **Pre-Flight Inspection Checklist:**
   - [ ] Verify physical TX wire isolation on TELEM2 harness.
   - [ ] *(Future: applies once a companion harness exists.)* Verify dedicated 5V BEC voltage is within $5.05\text{V} \pm 0.15\text{V}$.
   - [ ] Confirm SD card write speed $\ge 20\,\text{MB/s}$ (Class 10 / U3).
   - [ ] Verify SHA-256 firmware manifest matches installed autopilot build.
2. **Post-Flight Audit Checklist:**
   - [ ] Extract tamper-evident event log from companion the run's `events.sqlite`.
   - [ ] Run `aegis verify-log <events.sqlite>` to confirm hash-chain integrity.
   - [ ] Review any generated alerts against Mission Planner / QGC telemetry logs.
   - [ ] Log any unexplained warnings in this Risk Register under revision history.

---

## 5. Risk Assessment Sign-off

| Role | Responsibility | Status |
|:---|:---|:---:|
| **Security Lead** | Attack coverage & evasion vulnerability assessment | Not signed: `[TBD — team to review]` |
| **Avionics Lead** | Electrical isolation, bus safety & telemetry non-interference | Not signed: no harness was built or tested |
| **Systems Engineer** | Compute budget, thermal stability & buffer bounds | Not signed: nothing measured on a companion computer |
| **Flight Test Pilot** | Operator HUD usability & alert fatigue evaluation | Not signed: no flight or usability evaluation has taken place |
