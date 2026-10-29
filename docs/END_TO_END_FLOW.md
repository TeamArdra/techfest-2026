# AegisFlight — End-to-End Flow

One telemetry tick, traced through the real code. (Diagram:
`docs/diagrams/end-to-end-flow.mmd`.)

1. **Generate ground truth.**
   `simulator/flight.py` → `FlightSimulator.run()` yields a clean `FlightState`
   for tick *k*.

2. **Apply value-attacks (if any).**
   `sources/stream.py` → `SimulatedTelemetrySource.stream()` calls
   `attack.perturb_state(t, state)` (and `attack.before_encode(...)`).
   e.g. `GpsSpoofingAttack.perturb_state` shifts lat/lon.

3. **Encode to genuine MAVLink 2 (+ sensor noise).**
   `mavlink/codec.py` → `MavlinkEncoder.encode_tick(state, k)` builds the due
   messages (HEARTBEAT/GLOBAL_POSITION_INT/ATTITUDE/VFR_HUD/SYS_STATUS/
   GPS_RAW_INT) as `RawPacket[]`, adding position/velocity/attitude/baro noise.

4. **Apply stream-attacks (if any).**
   `attack.perturb_packets(t, packets, ctx)` may drop/duplicate/delay/re-id or
   inject packets (e.g. `DosAttack` flood, `CommandInjectionAttack` COMMAND_LONG
   from a rogue id). Packets are then ordered by `send_time`.

5. **Decode to transport-neutral envelopes.**
   `MavlinkDecoder.decode(pkt.data, pkt.send_time)` → `MessageEnvelope[]`
   (sysid, compid, seq, signed, fields…). Emitted on `TelemetryTick.messages`
   alongside hidden ground truth (`truth_state`, `label`).

6. **Ingest & update features.**
   `pipeline.py` → `IDSPipeline.process_tick(tick)` calls
   `FeatureExtractor.update(msg)` for each message (updates the
   `TelemetrySnapshot`, sequence/rate/command state, and the sliding-window
   position residual).

7. **At a decision tick (5 Hz), extract features.**
   `FeatureExtractor.extract(t)` → `FeatureFrame` (network/nav/sensor/command).

8. **Run the four detectors.**
   `ProtocolDetector.process`, `PhysicsDetector.process`,
   `AnomalyDetector.process`, `IntegrityDetector.process` → four
   `DetectorResult`s (score, `attack_votes`, `evidence`).

9. **Fuse.**
   `fusion/engine.py` → `FusionEngine.fuse(...)`: noisy-OR combine → threat
   score; weighted-vote attribution; severity band; cooldown/clear hysteresis →
   `ThreatAssessment` (with `latency_ms` stamped by the pipeline).

10. **Autonomous Mitigation & Prevention (Stage 2).**
    If posture is `ACTIVE_IPS`, `mitigation/controller.py` (`MitigationController.step`) evaluates the `ThreatAssessment`.
    - In **Topology B** (Inline): `FrameSanitizer` drops rogue frames or clamps coordinates before they reach the autopilot ($0.0\text{ m}$ detour).
    - In **Topology A** (Sidecar): `GoldenFlightState` dead-reckoning provides trusted coordinates and `MavlinkActuator` encodes counter-commands (set mode, EKF source switch). Modelled in SIM only; nothing is transmitted on a live source.
    - Safety-critical vetoes: `AttackSubModeClassifier` flags a mid-air disarm or a command-cadence violation and the controller records it (`REPLAY_GUARD` / `VETO_DISARM`). It is reported, not blocked: no code path drops the command before the autopilot.
    - Pilot GCS notification: `gcs_notifier.py` dispatches `STATUSTEXT` alert banners.

11. **Persist alerts.**
    If `is_alert`, `logging/store.py` → `EventStore.log_event(a, run_id)` appends
    a row to the per-run SHA-256 rolling block hash chain (live backend / `aegis simulate --db`).

12. **Expose over REST.**
    `backend/app.py` → `/api/status`, `/api/events`, `/api/metrics`, `/api/topology` (read-only, detected), `/api/defense-mode` read and control the engine + store.

13. **Publish live.**
    `backend/engine.py` → `LiveEngine._loop` broadcasts an update
    `{telemetry, threat, attack_active, topology, topologyReasons, altHistory, sim:true}` to every WebSocket subscriber.

14. **Render.**
    `frontend/src/hooks/useLiveData.ts` receives the message and updates the
    threat panel, defense HUD, position track, 44px vertical altitude profile strip,
    detector contribution bars, and event history.

**Benchmark path** (instead of 10–14): `benchmark/runner.py` →
`run_session` records a labelled `DecisionRecord` per decision; `metrics/scoring.py`
→ `evaluate` aggregates the confusion matrix and metrics.
