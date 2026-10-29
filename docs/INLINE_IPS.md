# Inline IPS bridge (Topology B)

`aegis ips-bridge` puts AegisFlight in the wire between a flight controller and its GCS link, so that hostile
frames can be dropped *before* the autopilot sees them. Before this, the IPS could only send a corrective command
after the fact (`FrameSanitizer` and `InlineBridge` were not wired to anything).

```
FC <-- serial -->  [ aegis ips-bridge ]  <-- serial -->  GCS radio
                    forwarder: frame -> InlinePolicy -> other side
                    tap:       copy of every ORIGINAL frame -> IDS pipeline -> MitigationController
                    controller state -> policy (quarantine / rewrite / QoS); counter-frames -> FC
```

```bash
aegis ips-bridge --fc-port /dev/ttyAMA0 --fc-baud 921600 --gcs-port /dev/ttyUSB0 --gcs-baud 57600 \
                 --defense-mode active-ips --db artifacts/ips.sqlite
```

Code: `src/aegisflight/mitigation/inline_policy.py` (rules), `src/aegisflight/hal/inline_ips.py` (bridge),
`mitigation/sanitizer.py` (downlink rewrite). Tests: `tests/unit/test_inline_ips.py` (synthetic frames, fake
transports, and one run over real transports on loopback sockets).

## Postures
| Posture | Behaviour |
|---|---|
| `passive` (default) / `advisory` | every frame is forwarded byte-identically in both directions; nothing is dropped or sent |
| `active-ips` | static uplink rules + controller-driven downlink rules + counter-frames to the FC |

The operator chooses the posture (`--defense-mode`, or `InlineIpsBridge.set_mode`); leaving `active-ips` clears all enforcement.

## What `active-ips` does to the wire
**Static uplink rules (no detector needed):**
- control traffic (`SET_MODE`, sensitive `COMMAND_LONG`/`COMMAND_INT`, mission and parameter writes, position-target,
  attitude-target, RC override) from a sysid that is not a trusted ground station is dropped;
- a plain disarm in flight is dropped (the autopilot refuses it anyway); a *forced* disarm (magic 21196) is dropped
  unless it comes from a trusted ground station, so the pilot's emergency kill is never blocked;
- a byte-identical sensitive command repeated within 50 ms is dropped (burst of one frame).

**Dynamic downlink rules (from the mitigation controller):** quarantine of a rogue sysid (never the vehicle or a trusted
GCS), QoS shedding in a flood, GPS / altitude rewrite with a valid CRC. They apply only while the analyser keeps them
fresh (3 s); a stalled analyser means transparent forwarding, not a stale rewrite. Signed frames are never modified.

**Counter-frames** (EKF source switch, mode restore, SAFE_HOLD ALT_HOLD) go to the flight controller only.

## Per attack class
| Class | Inline effect |
|---|---|
| Command injection from a rogue sysid (mode flip, rogue command, disarm burst, RC/mission/param writes) | dropped before the FC |
| Rogue sysid telemetry / MAVLink anomaly | dropped after the controller quarantines the sysid |
| Flood / rate spike | non-critical messages shed, critical rate capped |
| GPS spoofing / altitude bias on the downlink | GPS / altitude corrected in transit; EKF switch sent to the FC |
| Telemetry manipulation (speed, battery) | detected; no inline correction exists |
| Firmware tamper | detected; pre-arm lock only when known disarmed |
| `gcs_replay` / any attack using the real GCS sysid | stopped only with `--signing-key-file`; on an unsigned link it is indistinguishable from the pilot |

## MAVLink-2 signing (closes `gcs_replay` and sysid spoofing)
```bash
aegis ips-bridge ... --defense-mode active-ips --signing-key-file gcs.key --signing-state /var/lib/aegis/sig.json
```
`gcs.key` is the same 32-byte key the GCS and the flight controller use (raw bytes or 64 hex characters; keep it out of the repo).
With a key, in `active-ips`:
- every control message and sensitive command on the uplink must carry a valid signature with a strictly increasing
  timestamp per (link, sysid, compid) stream. A forged sysid fails the MAC, a replayed frame fails the timestamp, an unsigned
  frame is dropped. A valid signature, not the sysid, is what makes a sender trusted;
- `--signing-state` keeps the last timestamp per stream across restarts, so a restart does not reopen a replay window;
- `--signing-max-age-s N` also rejects signed frames older than N s on the bridge clock (stops a captured frame that was
  held back and released later). Use it only if the companion's clock is correct (no RTC means a wrong clock);
- `--signing-permissive` is for rollout only: unsigned control frames from a trusted sysid pass, forged or replayed signed
  frames still do not;
- the bridge's own counter-frames are signed with the same key, and the IDS side verifies signatures too (`sig_invalid`).

Not covered: signing must be enabled on the GCS and the flight controller (`SETUP_SIGNING`; PX4 and ArduPilot accept the
first key from whoever sends it first, so provision on a trusted link). Signed downlink telemetry cannot be rewritten
(GPS correction does not apply to it). Rules are only checked for control traffic, not for every frame. The verifier matches
pymavlink's signer (tested), but has not been run against a real autopilot's signing implementation.

## Fix made while building this
`FrameSanitizer` skipped any `GLOBAL_POSITION_INT` shorter than 40 bytes. MAVLink 2 trims trailing zero bytes (`vz`,
`hdg` are often 0), so such frames were never corrected. It now restores the full 28-byte payload, patches the fields and
recomputes the CRC; if nothing needs changing it forwards the original bytes.

## What is and is not established
- Tested: the rules on synthetic MAVLink 2 frames, forwarding fidelity (PASSIVE/ADVISORY byte-identical; benign traffic
  never dropped in ACTIVE), and a run over real `SerialMavlinkTransport` instances on loopback sockets.
- Host micro-benchmark (this PC, no real I/O, 15,000 frames through the policy): p50 ~3 us, p95 ~4 us per frame.
  That is policy cost only. Serial latency, the analyser's decision time (17.7 ms mean with ML on) and anything on a
  companion computer are **not measured**.
- **Not tested against a real flight controller, a radio or SITL.** Do the first run with the aircraft restrained.
- **No hardware bypass.** Both ports end in this process; if the companion loses power or the process dies the link is
  cut. A relay or splitter that connects FC and radio directly when the companion is down is required for flight.
- Without a signing key, trust is by sysid and an attacker who claims sysid 255 passes; use signing and set
  `--trusted-sysid` to the ground stations you actually use.
- The vehicle's mode restore only works for ArduCopter mode names; PX4 modes are never guessed.

## GPS response ladder

In `active-ips`, a GPS spoofing or GNSS jamming episode is handled in software only, per episode, on decision ticks:

1. Confirm after 2 consecutive threat ticks; send a STATUSTEXT warning.
2. Without a declared secondary source (default): if the fault persists 3 s after confirmation and the vehicle is armed in a position-dependent mode (AUTO, GUIDED, LOITER, RTL, POSHOLD, ... or unknown), send one `ALT_HOLD`. The controller never sends AUTO/RTL/LOITER/GUIDED/POSHOLD/LAND during an episode.
3. With `--ekf-secondary` (operator declares a configured non-GPS EKF source set): send the EKF source switch at confirmation; if the fault persists 4 s later, fall back to `ALT_HOLD`. Sensor messages never enable this automatically.
4. A pilot mode command (DO_SET_MODE, RTL, LAND) from a trusted sysid after confirmation cancels the ladder for the episode.
5. Recovery needs the clean-tick count and a position residual below 6 m. The EKF primary is restored only if we switched; the trusted flight mode is not restored (the pilot resumes). Command-injection episodes still restore the trusted mode.

PASSIVE and ADVISORY never send control frames. `bridge.status()["analyser"]["ekf_secondary"]` shows the declared capability.

## Cross-end check

Detects telemetry altered AFTER the bridge (radio link, GCS-side injection) while the drone flies normally.
Once per `--crossend-interval` seconds (default 1.0, `0` = off) the bridge sends the GCS side one MAVLink 2
`MEMORY_VECT` (sysid 1, compid 191, fixed marker) holding the exact integer fields (`time_boot_ms, lat, lon, alt,
relative_alt, vx, vy`) of the last `GLOBAL_POSITION_INT` it forwarded (after any rewrite). It is built on the
analyser thread, never in the per-frame hook, and goes to the GCS transport only (not the FC, not the tap).
With `--signing-key-file` the frame is signed and carries a truncated HMAC tag in the payload.

A GCS-side `aegis serve --source serial|udp [--signing-key-file K]` runs `CrossEndMonitor`
(`detectors/crossend.py`), merged into the PROTOCOL detector. A summary whose `time_boot_ms` matches a received
frame must match every field exactly; a difference scores 0.9 (`TELEMETRY_MANIPULATION`). Summaries that stop for
more than 5 s, or a bad/absent authentication when a key is set, give 0.3 (`MAVLINK_ANOMALY`) evidence. Without any
summary seen the monitor is inert.

Limits: sampled at 1 Hz, so a forged frame with a different `time_boot_ms` is never compared; without a key the
summary itself can be forged; it works only if the GCS-side IDS sees the bridge summary on the same link.
Not measured on hardware.

## Status endpoint

`aegis ips-bridge --status-port N` (default off) starts a read-only HTTP server on `127.0.0.1:N` (loopback only).
`GET /status` returns the same JSON as the periodic status line (`mode`, `state`, `frames`, `latency_us`, `policy`,
`analyser`, `last_error`) plus `"crossend": {"sent": n}`. Only GET is served (other methods: 405); there are no write
endpoints. CORS echoes the `Origin` only for the dashboard's allowed origins (localhost dev ports, Tauri).

## SITL evidence (ArduCopter SITL, loopback; environment tag `SITL`)
One scenario, one run per posture, on this PC (`scripts/ardupilot/inline_demo/`, profile `configs/ardupilot_copter/`): The profile enables `protocol.auto_rate_baseline` and sets `physics.yaw_course_enabled: false` (this disables the frozen-attitude telemetry check for that profile; see docs/DETECTION.md).
a simulated ArduCopter took off to 30 m and flew a rectangle in GUIDED, with the bridge between the flight controller
and a loopback "radio" hub; a rogue sysid 66 then sent a forged LAND (`DO_SET_MODE` and `SET_MODE`), two bursts.

| | `passive` | `active-ips` |
|---|---|---|
| vehicle after the attack | switched to LAND (mode 9) and descended to 0 m | stayed in GUIDED at 30 m (44 of 44 samples) |
| hostile frames reaching the FC | all | 0 (20 dropped as untrusted control) |
| legitimate GCS frames forwarded | 35 of 35 | 15 of 15 |
| downlink frames forwarded / dropped | 23,473 / 0 | 23,793 / 0 |
| per-frame forwarding time (p50 / p95 / max, socket sends included) | 15.6 / 48 / 2,170 us | 16.4 / 49 / 1,213 us |
| attack detected | yes, `COMMAND_INJECTION` from sys66 | yes |
| cross-end check at the GCS-side IDS | 164 matched, 0 mismatches | 164 matched, 0 mismatches |
| hash-chain log | intact | intact |

What this does not show: a real flight controller, radio or companion computer; signed traffic (all frames unsigned);
an attacker using the real GCS sysid; more than one run per posture. Findings from the run:
- The Stage-1 thresholds raised about 50 false `DOS` alarms (message rate) on this link in `passive`; the profile above
  removed them. Rate alarms must not drive actuation without a per-link profile.
- The multirotor heading-vs-course rule raised 4 false `TELEMETRY_MANIPULATION` alarms in GUIDED (documented limit).
- In `active-ips`, 4 redundant set-mode counter-frames (back to GUIDED) were sent after the blocked attack.
- SITL needs a client on SERIAL0 before it opens SERIAL1, and streams nothing extra on other ports until a GCS asks.

## Unsigned-link provenance (no signing key)

When no `signing_key` is configured, a sysid is only a claim: anyone on the radio link can forge sysid 255 or replay a
captured genuine frame. `InlinePolicy` therefore adds a best-effort, software-only check (`provenance=True`,
`provenance_window=16`; active only with enforcement on and no key; with a key the signature rules decide and this
tracker is bypassed).

- **Sequence tracker.** Every uplink frame updates a per-(sysid, compid) `SeqProvenance`. After 3 frames the 8-bit
  counter is "known". A frame is consistent if `(seq - last) mod 256` is 1..16 (tolerates radio loss); a duplicate or a
  jump/behind is inconsistent. Inconsistent frames never move `last_seq`, so a forger cannot drag the real counter.
- **Decision.** A sensitive command or control message from a trusted sysid with a known but inconsistent counter is
  dropped while armed or in flight (`dropped_provenance`); on the ground it passes and is counted
  (`suspect_provenance`). An unknown counter passes. Existing rules (untrusted sysid, in-flight plain disarm, burst)
  are unchanged.
- **Resync.** Three consecutive inconsistent frames that follow each other (+1..16) replace the learned counter
  (`resyncs`), e.g. a GCS restart. Worst-case lockout of a genuine pilot: the first 2 frames after the counter jumps
  (the third is accepted and resyncs); the same applies after more than 16 consecutive lost frames.
- **Replay.** A byte-identical (sysid, compid, seq, payload) repeat of an already forwarded sensitive frame within 5
  minutes (bounded to 512 entries) is dropped (`dropped_replay_unsigned`) once that source's counter is known. Re-sending
  the same command with a new seq is not a replay.
- **Counters** in `stats()`: `provenance_known_sources`, `dropped_provenance`, `suspect_provenance`,
  `dropped_replay_unsigned`, `resyncs`.

**Limits.** This does not stop an attacker who can see the link and tracks the real counter, nor a forger whose frames
happen to fall in the +1..16 window. Only MAVLink-2 signing closes those.
