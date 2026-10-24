# AegisFlight — Attack Implementation

All attacks live in `src/aegisflight/attacks/` and are **safe local
simulations**. See `docs/THREAT_MODEL.md` for the conceptual catalogue; this doc
is the implementation reference.

## The `Attack` interface (`attacks/base.py`)

```python
class Attack:
    attack_type: AttackType
    def active(self, t) -> bool                      # inside [start_s, start_s+duration_s)
    def label(self, t) -> AttackType                 # ground truth (benchmark only)
    def labels(self, t) -> frozenset[AttackType]     # multi-label truth (composites)
    def window(self) -> tuple[float, float]
    # perturbation hooks (default = identity):
    def before_encode(self, t, tick, encoder)        # tamper encoder state (seq)
    def perturb_state(self, t, state) -> FlightState # value attacks (pre-encode)
    def perturb_packets(self, t, packets, ctx) -> list[RawPacket]  # stream attacks
    def integrity_status(self, t) -> IntegrityStatus # firmware
```

`AttackContext` gives `perturb_packets` the current `tick`, the `MavlinkEncoder`
(to synthesise frames), a seeded `rng`, and the clean `state` (for
impersonation). `NoAttack` is the benign case.

`build_attack(name, attacks_cfg, rng, **kwargs)` (in `attacks/__init__.py`) reads
the per-attack block from `configs/attacks.yaml` and instantiates the class from
`ATTACK_REGISTRY`.

## Per-attack detail

| Attack | Class | Hook | Modes (config `mode`) | Changes | Leaves truthful |
|---|---|---|---|---|---|
| GPS spoofing | `GpsSpoofingAttack` | `perturb_state` | `gradual_drift`*, `sudden_offset`, `replay_freeze` | lat/lon | velocity (→ residual) |
| Telemetry manip. | `TelemetryManipulationAttack` | `perturb_state` | `altitude_bias`*, `speed_mismatch`, `battery_jump`, `frozen_attitude` | one reported channel | the cross-check channel |
| MAVLink anomaly | `MavlinkAnomalyAttack` | `perturb_packets` / `before_encode` | `rogue_sysid`*, `rate_spike`, `seq_scramble`, `packet_loss` | the frame stream | payload values |
| Command injection | `CommandInjectionAttack` | `perturb_packets` | `rogue_command`*, `mode_flip`, `arm_disarm_burst`, `gcs_replay` (new, **known gap**) | injects COMMAND_LONG from rogue id (or replays one from the *legitimate* GCS id) | vehicle telemetry |
| DoS | `DosAttack` | `perturb_packets` / `perturb_state` | `flood`*, `blackout`, `latency`, `gnss_jamming` (new) | duplicates/drops/delays frames; GNSS fix loss | payload values / dead-reckoned position |
| Firmware | `FirmwareIntegrityAttack` | `integrity_status` | (n/a; open-ended from `start_s`) | flips a byte in a component file | the manifest |

\* = default mode in `configs/attacks.yaml`.

Notes:
- **GPS `gradual_drift`** injects `drift_rate_ms · elapsed` metres along
  `bearing_deg`; **`replay_freeze`** pins lat/lon at attack onset.
- **Telemetry `altitude_bias`** biases GPS/EKF altitude but not the baro channel
  → `gps_baro_alt_diff`. **`frozen_attitude`** freezes yaw while the course
  keeps turning → `yaw_course_diff`.
- **MAVLink `rogue_sysid`** uses `encoder.encode_as(state, rogue_sysid, …)` to
  emit vehicle-like telemetry from a rogue node. **`seq_scramble`** jumps the
  encoder's per-source seq counter in `before_encode` (frames stay CRC-valid but
  sequence-anomalous).
- **DoS `flood`** replays the tick's frames ×`flood_multiplier`; the duplicated
  seq stream also inflates `max_seq_gap`.
- **Firmware** shares its firmware directory with the pipeline's
  `FirmwareVerifier`; at `start_s` it flips a byte in `tamper_component` and the
  verifier's next `verify()` returns INVALID (genuine SHA-256).

- **DoS `gnss_jamming`** (new) models RF denial of the *GNSS* channel: GPS_RAW_INT reports
  fix_type 1, 0–3 satellites, HDOP 99.99 while GLOBAL_POSITION_INT keeps streaming the
  dead-reckoned estimate. Detected by the new protocol rule *GNSS fix lost* (fix_type < 3 or
  satellites < 5 for ≥ 5 consecutive decisions), or *GNSS fix never acquired* if no valid fix
  (fix_type ≥ 3 and satellites ≥ 5) was seen since start/`reset()`; SIM and SITL jamming start after a
  fix, so they read *lost*. Scored under the **DOS** class (denial of the
  navigation channel); a dedicated GPS_JAMMING class would need enum/dashboard changes.
  Position-stream suppression from link-up and GPS_RAW_INT-only suppression are not implemented
  attacks (the live proxy `DropAttack` drops both streams together, onset 35–45 s, after they were
  seen); their detection limits are in `docs/THREAT_MODEL.md` (detection coverage vs. limitations).
- **Command `gcs_replay`** (new) re-sends a legitimate `MAV_CMD_DO_SET_MODE` *from the real GCS
  identity* (sysid 255 / compid 190). Nothing on an unsigned MAVLink link distinguishes it from
  the operator, so the provenance rule cannot fire — it is benchmarked as a documented
  **known gap** (MAVLink-2 message signing with timestamps is the fix; future work).

## Simultaneous attacks (`attacks/composite.py`)

`build_attack("gps_spoofing+mavlink_anomaly", …)` returns a `CompositeAttack`: every hook
is chained through the components, so a combination is literally both attacks at once.
Ground truth is **multi-label** (`labels(t)` → every active class; carried on
`TelemetryTick.labels` and `DecisionRecord.true_set`). The IDS still emits **one primary
class** plus `secondary_indicators` (classes with ≥ 25 % of the primary vote); the extended
benchmark scores whether *all* active classes appear in primary ∪ secondary. Multi-label
*attribution* is therefore partial by design — see `docs/BENCHMARKING.md` (v2).

## Coverage by threat category

| Category (challenge wording) | Current attacks / modes | Observable signature | Status |
|---|---|---|---|
| Communication | MAVLink anomaly (rogue sysid, rate spike, seq scramble, packet loss); DoS (flood, blackout, latency) | protocol rules (rate, seq gaps, sources, liveness) | implemented, simulated |
| Navigation | GPS spoofing (gradual drift, sudden offset, replay-freeze); **GNSS jamming** | position residual, fix loss | implemented, simulated (constant offset only caught at the jump) |
| Telemetry | altitude bias, speed mismatch, battery jump, frozen attitude | cross-channel consistency | implemented, simulated |
| Command & control | rogue command, mode flip, arm/disarm burst; **GCS replay** | command provenance | implemented; replay from legit id **not detectable** without signing |
| Firmware | byte flip in a component | SHA-256 manifest mismatch | implemented; manifest is **unsigned** in the PoC |
| System-level | combinations of the above (`CompositeAttack`) | fused evidence | small multi-attack suite; no OS/process-level monitoring |

## Adding a new attack
See `docs/ADDING_A_NEW_ATTACK.md`.
