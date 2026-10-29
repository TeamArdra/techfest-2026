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

**Counter-frames** (EKF source switch, mode restore, SAFE_HOLD ALT_HOLD) go to the flight controller only; the GPS-ladder STATUSTEXT warning goes to the GCS side only (found in SITL: sent to the FC it never reached the pilot).

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

## Detected topology

The dashboard does not offer a topology selector. `status()` (and `GET /status`) carries a `topology` object of kind
`A+B`: the FC and GCS link `connected` flags come from the two transports (`null` if a transport does not report
one). `uplink_visible` is true once frames were seen from the GCS side or the GCS link is connected;
`can_block_frames` needs `active-ips` with both links up; `can_send_counter_commands` needs `active-ips` with the FC
link up. A single-port `aegis serve` sidecar is reported as kind `A` (cannot block frames). See `docs/API.md`.

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
  (`resyncs`), e.g. a GCS restart, but only when the learned counter has seen no consistent frame for 2 s
  (`SeqProvenance.quiet_s`). A live genuine stream therefore keeps the counter: a forger that sends its own
  consecutive sequence next to the pilot cannot take it over (found in SITL, see below). Worst-case lockout of a genuine
  pilot after a restart: its first 2 frames, and at least 2 s after its previous frame; the same applies after more than
  16 consecutive lost frames.
- **Replay.** A byte-identical (sysid, compid, seq, payload) repeat of an already forwarded sensitive frame within 5
  minutes (bounded to 512 entries) is dropped (`dropped_replay_unsigned`) once that source's counter is known. Re-sending
  the same command with a new seq is not a replay.
- **Counters** in `stats()`: `provenance_known_sources`, `dropped_provenance`, `suspect_provenance`,
  `dropped_replay_unsigned`, `resyncs`.

**Limits.** This does not stop an attacker who can see the link and tracks the real counter, nor a forger whose frames
happen to fall in the +1..16 window. Only MAVLink-2 signing closes those.

## SITL evidence: signing and unsigned smart attacker

Same rig as above (ArduCopter SITL, loopback hub, `configs/ardupilot_copter`-style profile, GUIDED flight at 30 m;
scripts in `scripts/ardupilot/inline_demo/`: `run_signing.sh`, `run_unsigned.sh`). Two runs per active scenario, one
passive run each. Single runs, one simulated autopilot, loopback only: no radio, no real GCS software.

**Scenario A, MAVLink-2 signing** (random 32-byte key provisioned with `SETUP_SIGNING` over SERIAL0, SITL restarted,
`ips-bridge --signing-key-file --signing-state`, pilot and GCS-side `aegis serve` with the same key). Per active run
(two runs, identical counters):

| check | result |
|---|---|
| signed pilot: GUIDED, arm, takeoff 30 m, leg, signed LOITER then GUIDED | all succeeded; `signed_ok` 16 |
| unsigned forged LAND, sysid 66 and sysid 255, MAVLink 2 and MAVLink 1 (10 frames each) | 40 `dropped_unsigned`; mode stayed GUIDED |
| LAND signed with a wrong key (sysid 255, 10 frames) | 10 `dropped_bad_signature`; GUIDED |
| byte-identical replay (3x) of a captured signed SET_MODE(LOITER) | 3 `dropped_replay`; GUIDED, no second LOITER |
| uplink frames | 70 in, 17 forwarded, 53 dropped (= 40 + 10 + 3); no pilot command failed |
| downlink | 24,386 and 24,524 frames forwarded, 0 dropped |
| GCS-side cross-end check | 168 and 169 matched, 0 mismatches |
| IDS inside the bridge | 4 `TELEMETRY_MANIPULATION` (the known heading/course false alarm in GUIDED) and no alerts for the dropped attack frames, which never reach the tap; 4 counter-frames sent |
| `passive`, same key | all 70 uplink frames forwarded; the flight controller itself rejected every unsigned, wrong-key and replayed frame (mode stayed GUIDED); the IDS reported the same 4 heading/course alerts and nothing about the attacks; cross-end 165 matched, 0 mismatches |

Not shown: the FC rejecting these in passive is inferred from its mode, not read from its log; the replay is dropped by
the bridge and would also be refused by the FC's own timestamp check, so "FC does not act twice" is not isolated from
the bridge; no wrong-sysid-with-valid-signature case; no key rotation or clock skew.

**Scenario B, smart attacker on an unsigned link** (no key anywhere; sysid 255 / compid 190 forged; the pilot sends a
1 Hz heartbeat and a benign DO_SET_MODE(GUIDED) every 5 s as probe of lock-out). `passive` is the control.

| attack | `passive` (run 1) | `active-ips` (2 runs after the fix) |
|---|---|---|
| (1) forged LAND, own counter, 10 frames | vehicle went to LAND | 10 `dropped_provenance`, no LAND (before the fix: 5 dropped, 2 `resyncs`, LAND reached the FC) |
| (2) replay of the pilot's captured SET_MODE(LOITER), 3x | vehicle went to LOITER | 3 dropped (counted as `dropped_provenance`: the replayed seq is behind the counter; `dropped_replay_unsigned` stayed 0); no LOITER |
| (3) counter-tracking forged LAND (next expected seq, 10 attempts) | vehicle went to LAND | PASSED: LAND reached the FC in both runs (1 and 2 frames `dropped_provenance` in that stage) |
| (4) pilot restarts its counter at 0 | first LOITER command accepted | first command dropped, second accepted 3.4 s and 3.5 s after the restart (1 `resync`); GUIDED restored |
| `dropped_untrusted_control` / `suspect_provenance` / `dropped_replay_unsigned` | 0 / 0 / 0 | 0 / 0 / 0 |
| totals over the run | 214 of 214 uplink frames forwarded | `dropped_provenance` 15 and 16, `resyncs` 1; 206 and 204 forwarded |

Legitimate frames dropped: 1 per run at the pilot restart (the lock-out above); in the second active run one benign
probe (BEAT 11) got no acknowledgement during the tracking stage, which may have been a duplicate-seq collision with the
attacker; the drops in the tracking stage were not attributed to sender. All other probes were acknowledged.

What this shows: with a key, every forged, wrongly-keyed and replayed uplink frame in these runs was dropped and the
pilot kept working. Without a key the software check stops a naive forger and naive replay, and does nothing against an
attacker that can read the real pilot's counter (3); that remains the case until signing is on. What it does not show:
a real radio, a real GCS (QGroundControl and others behave differently on restart and heartbeat), other attackers'
timing, or more than the stated number of runs.

**Bug found and fixed.** The unsigned resync rule let a forger take over the counter: 3 consecutive own-counter frames
next to the live pilot replaced the learned counter (first run: LAND reached the FC after 5 drops, and the pilot's
own frames were then treated as inconsistent). `SeqProvenance` now resyncs only after the learned counter has been quiet
for 2 s. Regression tests: `test_forger_consecutive_counter_next_to_live_pilot_cannot_take_over` and
`test_seq_provenance_quiet_period_gates_resync` in `tests/unit/test_inline_provenance.py`. No bug was found in the
signing path.

## SITL evidence: wrap-around replay and contested source

Unsigned link, `active-ips`, ArduCopter SITL on loopback through `scripts/ardupilot/inline_demo/` (`run_wrap.sh`,
`run_contested.sh`, `fly_wrap.py`, `attack_wrap.py`, `watch_alarm.py`; the pilot is a pymavlink script as sysid 255).

**Replay memory.** The byte-identical replay set is now count-bounded (`replay_memory`, default the last 4096 forwarded
sensitive/control frames, `--replay-memory`), with no time limit and no need for the source counter to be known. An exact
(sysid, compid, seq, payload) forwarded once is never forwarded again. Cost: a GCS that legitimately sends the same
control frame with the same seq after exactly 256 frames (rare) is dropped once.

**Wrap-around replay (1 run).** The pilot sent a genuine DO_SET_MODE(GUIDED) at seq 104 (hub capture), went back to
LOITER, sent 247 filler heartbeats at about 20/s (15 s) until its counter was at 101, then the attacker replayed the
captured bytes (seq 104 is inside the +1..16 window, so the provenance check alone would accept it). Result:
`dropped_replay_unsigned` +1, `dropped_provenance` 0, vehicle stayed in LOITER (5); the pilot's next legitimate
DO_SET_MODE(GUIDED) (new seq) was forwarded and acked (ack 0, mode 4). Whole run: 374 uplink frames, 1 dropped.

**Counter-tracking attacker (1 run per mode, 10 forged DO_SET_MODE(LAND) each, sent with the pilot's next seq).**
- `alert`: every attempt produced a same-seq/different-payload event (`contested_events` 10), one rate-limited alarm
  (`contested_alarms` 1); the STATUSTEXT (severity 4) was seen at the GCS side and the console printed an ALARM line.
  The attack was NOT stopped: 1 forged frame dropped by provenance, 9 forwarded, vehicle went to LAND (9); the pilot's
  next beat restored GUIDED.
- `drop-sensitive`: same detection and alarm. `dropped_contested` 12: the vehicle still entered LAND (the first forged
  frame passes before a duplicate proves two senders), then forged frames and the pilot's own DO_SET_MODE beats (3 of 3,
  ack None) were dropped, so the real pilot could NOT take the vehicle out of LAND while the source was contested
  (60 s hold, refreshed by each event). The RC radio remains the override.
- So the detector only detects the counter-tracking attacker once the race yields a duplicate; it does not stop its
  first frames, and `drop-sensitive` can lock out the real GCS. A forced disarm (magic 21196) is never dropped. Only
  signing removes the problem; `ips-bridge` prints a warning when `active-ips` runs without `--signing-key-file`.
  The alarm text stays below the 50-byte STATUSTEXT limit.

**What this does not show:** single runs, a simulated autopilot, loopback with no radio latency or loss, a pymavlink
pilot rather than real GCS software, and an attacker script that reads the capture file directly (a real one needs a
radio sniffer).

## SITL finding: late-connecting GCS and the rate baseline (ArduCopter SITL, loopback)
A ground-side monitor started before the GCS asked for its telemetry streams learned a ~5 msg/s baseline, then raised 55 false
`DOS` rate-spike alarms over one flight at 140 msg/s. Two defects: the baseline never switched on for live sources (the key had
an explicit `false` default, so "set if missing" did nothing; unset now means auto: on for live, off for SIM), and a one-shot
baseline cannot follow a link whose rate steps up later (a stable 30 s plateau below the configured hard flood limit is now
adopted, at most twice per session; the hard limit is never relaxed). Same flight after the fix, ground-side IDS: 1 alert
(a heading rule one) and 0 `DOS`. One run; the bridge side was unaffected.

## SITL evidence: sidecar recovery and GPS spoofing response

ArduCopter SITL on loopback, `configs/ardupilot_copter`, flight in GUIDED at 30 m. Scripts: `scripts/ardupilot/inline_demo/sidecar_recovery.py`
(Topology A) and `gps_response.py` (bridge). SERIAL1 streams come from `MAV2_*` persistent parameters loaded with
`--defaults` (`scripts/ardupilot/sitl_defaults_monitor_port.parm`); setting them at run time over MAVLink did not produce streams. Single runs, simulated
autopilot and GPS, loopback, no real hardware.

**Test 1, Topology A** (pure sidecar `aegis serve --source serial` on SERIAL1, no bridge; pilot direct on SERIAL0, silent after takeoff;
attacker on SERIAL2 sends `DO_SET_MODE(LAND)` once):

| Run | Result |
|---|---|
| passive, attacker sysid 66 / 255 | LAND within 0.3 s, descended to 0 m in about 35 s, stayed in LAND; no injection alert |
| active-ips, attacker sysid 66 / 255 | identical: LAND, never back to GUIDED; sidecar `counter_frames_sent` 0 |

The sidecar never recovered the vehicle (no LAND to GUIDED time exists). Cause, from the code and the logs: the IDS raises
`COMMAND_INJECTION` only from command frames it sees, and SERIAL1 carries only the vehicle's own output, so the attacker's frame on SERIAL2 (and the
pilot's on SERIAL0) is invisible to the sidecar. The only trace is the HEARTBEAT mode change, which is indistinguishable from a legitimate
pilot change made on another port, so `golden.trusted_mode` simply follows it (it read `LAND`) and there is nothing to restore. This is a design
limit of a sidecar that does not see the command path, not a bug; recovery in Topology A needs the sidecar on the command path (the bridge) or a
second source of command provenance. Incidental: a start-up `dos:gnss_jamming` alert (no fix yet, on the ground) occurs in every run.

**Test 2, GPS response** (bridge `active-ips`; fault written to `SIM_GPS1_GLTCH_X`, degrees of latitude offset, 0.001 deg = about 111 m; other relevant SITL
parameters: `SIM_GPS1_GLTCH_Y/Z`, `SIM_GPS1_GLTV_*`, `SIM_GPS1_DRFTALT` (altitude only), `SIM_GPS1_JAM`, `SIM_GPS1_NOISE`; no horizontal drift parameter, so drift is a scripted ramp of GLTCH_X):

| Run | Detection (bridge) | GCS warning | Mode timeline | Ladder |
|---|---|---|---|---|
| benign, no fault | no alert in flight (3 alerts on the ground before takeoff, fix acquisition) | none | GUIDED throughout | nothing sent in flight |
| glitch ~111 m, passive | GPS_SPOOFING HIGH at +0.7 s (EKF innovation ratio 29.6), CRITICAL at +12.7 s (position residual 30 m) | none | stays GUIDED | nothing sent (0 counter-frames) |
| glitch ~111 m, active-ips (3 runs; warning seen in the one run after the fix) | same events | `AEGIS: GPS unreliable - do not trust position` at +0.9 s | GUIDED to ALT_HOLD (2) at +3.9 s (3.0 s after confirmation); descended to the ground | 1 warning + 1 ALT_HOLD; no AUTO/RTL/LOITER/GUIDED/POSHOLD |
| glitch + pilot `DO_SET_MODE LOITER` after the warning | same | at +0.8 s | LOITER at +1.1 s, stays LOITER | ladder stood down: warning only, no ALT_HOLD |
| scripted drift ~5 m/s, active-ips | EKF innovation ratio 1.3 at +0.7 s, residual 35 m at +12.7 s | at +0.9 s | ALT_HOLD at +3.9 s | warning + ALT_HOLD |
| scripted drift ~1 m/s, active-ips | no alert at all (run before the fix below) | none | GUIDED for 110 s | none: a miss |

What this shows: the ladder confirmed and acted as designed (warning, one ALT_HOLD 3 s later, no forbidden mode, pilot override honoured), with no false
actuation in the benign flight. What it does not show: the detection evidence here is the SITL EKF's own innovation ratio (the SITL estimator reacts to the glitch, also
switching lanes and printing `GPS Glitch or Compass error`), so this is not independent proof of a position-residual detector; a 1 m/s drift went unnoticed;
ALT_HOLD with no pilot throttle makes SITL descend to the ground (the ladder only stops position-dependent flight; a pilot must take over). The pilot-override test uses `DO_SET_MODE` in
`COMMAND_LONG`; a plain `SET_MODE` message (msgid 11) is not recorded as a command by the feature extractor, so it would not cancel the ladder (not changed).

Bug found and fixed: the ladder's STATUSTEXT warning was sent to the flight controller only and never reached the GCS (first glitch runs: no `AEGIS` text on the GCS side). The bridge now sends STATUSTEXT
counter-frames to the GCS transport (`hal/inline_ips.py`, regression test `test_statustext_counter_frame_goes_to_the_gcs_and_commands_go_to_the_fc`). Logs and sqlite files stay outside the repo (`C:/afsitl`).

## Signing gate and remote posture control

Signing is the only defence against a counter-tracking forger, so `active-ips` on a real link without a key is an
explicit choice:

- `aegis ips-bridge --defense-mode active-ips` without `--signing-key-file` exits 2 unless `--allow-unsigned` is given
  (a one-line notice is then printed).
- `--control-token-file PATH` enables `POST /posture` on the status API (the file holds the token; it is never printed).
  Body `{"mode": "passive"|"advisory"|"active-ips", "allow_unsigned": bool}`, auth `Authorization: Bearer <token>` or
  `X-Aegis-Token`. Errors: 403 `control_disabled`, 401 bad/missing token, 400 bad body, 409 `signing_required` (active-ips,
  no key, `allow_unsigned` not `true`), 200 `{"ok": true, "status": ...}`. Browser calls are CORS-limited to the dashboard origins.
- `--status-host HOST` (default `127.0.0.1`); a non-loopback host needs `--control-token-file` and prints a warning that the
  status API is reachable from the network.
- `GET /status` also returns `signing: {configured, unsigned_acknowledged}` and `control: {enabled}`.
