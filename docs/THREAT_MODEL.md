# AegisFlight — Threat Model

**Scope.** AegisFlight is a Stage-1 proof-of-concept IDS for the MAVLink
telemetry/command link of a small UAV. It monitors the security-relevant
information carried on that link and the vehicle's firmware attestation.

> **All six scenarios are safe, local SIMULATIONS.** Attacks perturb simulated
> telemetry, the local MAVLink byte stream, or a scratch firmware directory.
> Nothing in this project touches a real network, radio, or airframe, and it
> performs no real-world intrusion.

## Assumptions
- The IDS sits on the GCS side (or a companion computer) and observes the full
  MAVLink 2 stream plus a firmware manifest.
- The legitimate vehicle is sysid 1 / autopilot compid 1; legitimate ground
  stations are sysid 254/255. (Configurable in `detector.yaml`.)
- The attacker can inject/modify/drop MAVLink frames on the link and can tamper
  with on-board firmware files, but cannot forge a valid firmware SHA-256.

## The six scenarios

| # | Attack | Concept | How simulated | What the IDS sees | Expected detector / evidence |
|---|---|---|---|---|---|
| 1 | **GPS spoofing** | Falsified GNSS position | `perturb_state` shifts lat/lon (gradual drift / sudden offset / replay freeze); velocity left truthful | reported position track diverges from velocity-implied track | Physics: `pos_residual_m > 12 m` |
| 2 | **MAVLink anomaly** | Rogue node / malformed stream | `perturb_packets`/`before_encode`: inject rogue-sysid telemetry, rate spike, sequence scramble, packet loss | unexpected sysid, seq gaps, rate change | Protocol: rogue source, seq gap |
| 3 | **Command injection** | Unauthorised commands | inject `COMMAND_LONG` from a rogue GCS id (arm/disarm burst, mode flip, rogue command) | commands from an unexpected source; sensitive/burst | Protocol: command provenance |
| 4 | **Telemetry manipulation** | Falsified sensor readouts | `perturb_state`: altitude bias / speed mismatch / battery jump / frozen attitude | cross-channel inconsistency (GPS vs baro, GPS vs VFR, attitude vs course) | Physics: alt/speed/att/battery |
| 5 | **Denial of service** | Link saturation / blackout | `perturb_packets`: flood (×N), blackout (drop), latency (jitter) | rate spike / heartbeat & GPS dropout / seq gaps | Protocol: rate, liveness, gaps |
| 6 | **Firmware integrity** | Tampered firmware | flip a byte in a component file in the shared firmware dir | SHA-256 mismatch vs manifest (unsigned in PoC) | Integrity: INVALID + component name |

Each attack's ground-truth window (`Attack.label(t)`) is used **only** by the
benchmark to score detections — never by the detectors.

## Detection coverage vs. limitations
- **Strong, physics-grounded coverage** for spoofing/telemetry (cyber-physical
  cross-checks) and protocol/DoS (transport rules) — these need no training and
  degrade gracefully.
- **A constant, established GPS offset** with perfectly consistent (also
  spoofed) velocity is only detectable at the transition — see
  `docs/FEATURES.md`. Sustained gradual drift and replay-freeze are detected
  throughout.
- The firmware check assumes a trustworthy manifest (it is **not signed** in the PoC —
  signing is future work) and read access to
  the components.
- **Position-stream suppression from link-up** (P1/P2 policy, 2026-10-15): with the default
  `protocol.require_global_position: false`, a `GLOBAL_POSITION_INT` stream that is absent from the
  moment the IDS starts observing (e.g. filtered by an in-path adversary, including across an IDS
  restart or `pipeline.reset()` while it is already filtered) is reported only as a score-0 coverage
  condition, and the rule-based position-dependent physics checks do not run: position residual and
  acceleration (the `GPS_SPOOFING` votes) have no input, and the GPS/VFR speed rule is gated off until
  `GLOBAL_POSITION_INT` has been received. With ML enabled the ML detector still sees the raw features
  (one uncommitted synthetic scratch run with ML on alerted; not measured, not evidence). Suppression after the stream was seen is still a DOS
  alert, but with the protocol rule as the only contributor it becomes a fused threat only after
  ≈ 4 s of absence (detector-level from `gps_dropout_s` = 2 s); a restart or `reset()` inside that
  window leaves only the coverage line. Profiles where position is expected must set
  `require_global_position: true`; no shipped profile does (`configs/detector.yaml` and
  `configs/px4_sitl/` both leave it `false`). Only `scripts/hardware/run_serial_ids.py` persists the
  condition (`telemetry_coverage` in `summary.json` / `health.jsonl`); it is not hash-chained and not
  shown on the dashboard. See `docs/DETECTION.md`.
- **No `GPS_RAW_INT` staleness check** (pre-existing): the GNSS fix-loss rule reads the last
  `GPS_RAW_INT` received. If an in-path adversary drops it, the last fix stays frozen and a real GNSS
  loss is masked; if it never arrives, the rule is silently inactive (no evidence line). A
  `GPS_RAW_INT` age/presence rule is proposed, not implemented.
- **Presence is not source-checked**: HEARTBEAT, `GLOBAL_POSITION_INT` and `GPS_RAW_INT` count as
  received from any sysid/compid. A forged or other-source frame can therefore establish "seen", and a
  GCS heartbeat can mask loss of the vehicle heartbeat (latent; not observed in any capture).
  Per-source liveness is proposed, not implemented.
- This is a PoC over a *simulated* link; real-RF, multi-vehicle, and
  hardware-in-the-loop coverage are future work (see the technical proposal).
