# AegisFlight — Stage-2 P2: Live Attack Proxy Design

Status: **design only** (no code in this document has been written or run). Target
environment for every claim below: **SITL** (loopback / WSL2 NAT virtual network), per
`.claude/CLAUDE.md`. Nothing here touches real RF, a real vehicle, or a third-party
network. This is a design proposal for `aegis-lead` to review and split between
`aegis-px4-mavlink` (transport) and `aegis-security` (attack logic), per the ownership
table in `.claude/CLAUDE.md`.

## 0. Why this is a new, additive component, not a Stage-1 attack

Stage-1 `attacks/base.py:Attack` hooks (`before_encode`, `perturb_state`,
`perturb_packets(t, packets, ctx)`) are frozen and depend on `AttackContext`, which
carries the simulator's `MavlinkEncoder` and the clean ground-truth `FlightState`. A
live MITM proxy sitting between PX4 SITL and the IDS has **neither**: it only ever sees
already-encoded, already-CRC'd MAVLink bytes in flight. A value attack here means
*decode → modify → re-encode*, which changes the CRC (MAVLink 2 is unsigned on this
link, so that's fine) and cannot use `encoder.encode_as(state, ...)` impersonation
tricks that read truth — it must synthesize frames from **observed traffic**
(last-seen `GLOBAL_POSITION_INT`, learned sysid/compid/seq state), not from
`FlightState`. So P2 introduces a new module tree, `src/aegisflight/proxy/`, that reuses
Stage-1 attack **parameters and mode names** where the mapping is honest (e.g.
`gps_spoofing.drift_rate_ms`, `telemetry_manipulation.altitude_bias_m`) but does not
import or subclass `attacks/base.py`.

## 1. Attacker model

- **Capability**: full read/write MITM on the single UDP GCS link between PX4 SITL and
  the IDS/GCS client — can observe, modify, delay, drop, duplicate, or inject any frame
  in either direction. This is the realistic ceiling for an unsigned MAVLink 2 link
  (`signed=0` for all captures in P1); this is a **capability assumption**, not something
  the proxy needs to "achieve" cleverly — PX4 locks to the first sender and both
  legitimate ends trust whatever arrives with the right header fields.
- **Knows**: the wire protocol (MAVLink 2, header format, CRC-X25 algorithm), the
  vehicle's sysid/compid (3/1, learned passively from traffic, not hard-coded — PX4's
  instance-derived sysid is environment-dependent per `docs/PX4_SITL_INTEGRATION.md`
  §2), current message content (by definition, it relays everything), and timing
  statistics of the benign stream (P1 rates).
- **Does not know**: PX4's internal estimator state, EKF covariances, or anything not
  observable on the wire. It cannot forge a valid firmware SHA-256 (separate PoC
  component, `aegis-security`-owned but out of scope for P2). It has no way to make the
  *vehicle* believe false GPS/baro/IMU readings — that would require sensor-level
  injection inside SITL (Gazebo plugin / `sensor_combined` manipulation), which is a
  PX4/Gazebo-side change and explicitly **out of scope** for this proxy (see §2).
- **Out of scope**: anything requiring modifying PX4 or Gazebo, anything on the
  offboard/API link (14580/14540) or payload link, anything that leaves the loopback/WSL
  NAT boundary, key material of any kind (no signing keys exist yet — P4), and real RF.

## 2. Candidate attack classes, compared

| Candidate | What PX4 SITL can actually demonstrate | Claim class supported | What detectors could plausibly see | Ground-truth defensibility |
|---|---|---|---|---|
| **Modification** (rewrite a downlink field in place, recompute CRC) | The IDS consumes a falsified value; PX4's estimator is **untouched** (PX4 never receives the modified frame — it only flows GCS-ward) | **Link-level detection only** — this is the ceiling, and it must be stated as such, not upgraded to "GPS spoofing of the vehicle" | Physics (`pos_residual_m`, `gps_baro_alt_diff_m`, cross-channel checks) if the modified field disagrees with an unmodified correlated channel; protocol (seq/CRC are consistent, so no protocol signal from the edit itself) | **Strong.** Proxy knows exactly which bytes it changed, by how much, at what frame; it can diff modified vs. original payload byte-for-byte and timestamp every edit. No ambiguity about "did the attack fire." |
| **Injection** (synthesize a new frame — e.g. rogue-sysid telemetry or an unsolicited `COMMAND_LONG`) | A frame that was never on the wire now is; if sent toward PX4 (uplink) and PX4 *accepts* it, this is a **command-path effect**, not just link-level | Link-level detection (if downlink) or command-path effect (if uplink and accepted — requires confirming via `COMMAND_ACK` or a mode-change HEARTBEAT) | Protocol (rogue source, provenance, burst-rate rules) | **Strong** — injected frames are entirely proxy-authored, trivially logged. Command-path claims need an extra verification step (did PX4 ACK/execute) that the proxy must capture, not assume. |
| **Replay** (re-send a previously captured legitimate frame later, under the real GCS identity) | Demonstrates the documented `command_injection:gcs_replay` **known gap**: an unsigned link cannot distinguish a replayed legitimate command from a fresh one | Command-path effect if it's an uplink command PX4 re-executes; otherwise link-level | None by design — this is the point: no detector signal is *expected* under current `require_signing: false`. Valuable as a **before/after** measurement once signing lands (P4/P5) | **Strong** — proxy logs the original capture time and the replay time/seq; "PX4 accepted a frame it should have rejected as stale" is directly falsifiable from COMMAND_ACK timing. |
| **Drop** (selectively suppress frames, e.g. all GPS_RAW_INT) | Demonstrates denial of a specific telemetry channel reaching the IDS; PX4 itself is unaffected (it's the sender) | Link-level detection only | Protocol (gps_dropout, heartbeat_timeout, seq gaps) | Strong but blunt — easy to prove absence, less rich signal diversity than modification. |
| **Delay/jitter** | Demonstrates link-quality-style denial without outright loss | Link-level detection only | Protocol (interarrival jitter, rate); weak/no physics signal | Strong but the *attack* and *benign WSL/host jitter* (P1 shows jitter p95 ≈ 4.9 ms, max 36 ms, and real timing noise from Gazebo RTF 0.6–1.0) are close in magnitude — risk of an ambiguous or unconvincing result as the **first** demonstration. |
| **Spoof identity** (send frames under a sysid/compid that isn't the proxy's own) | Overlaps heavily with injection; on its own it is really "injection with an attacker-chosen source field" | Link-level detection | Protocol (rogue source) | Strong, but it's a parameter of injection, not an independently novel mechanism — folding it into the injection attack (as Stage-1 `rogue_sysid` already does) avoids a redundant first deliverable. |

### Recommendation: first attack = **GPS-channel modification on downlink `GLOBAL_POSITION_INT`**, gradual-drift mode

Reasoning:
1. **Richest, cleanest ground truth.** The proxy owns both the original and modified
   bytes; no ambiguity about "did it fire," no dependence on PX4 accepting/rejecting
   anything (that would entangle the result with PX4 behavior, muddying a pure
   link-level claim).
2. **Directly reuses a Stage-1 parameterization** (`gps_spoofing.gradual_drift`,
   `drift_rate_ms`, `bearing_deg`) with an honest translation to the proxy's operating
   mode (decode → shift lat/lon → leave velocity fields alone → re-encode), which keeps
   red/blue continuity visible and lets the lead compare SIM vs. SITL link-level
   detection on the "same" conceptual attack once P3 calibration exists.
3. **Exercises exactly the physics detector's signature feature** (`pos_residual_m`,
   leaky-integrated position-vs-velocity residual) — the single feature class most
   likely to survive PX4 recalibration, since it doesn't depend on the broken absolute
   rate baseline (P1 §6 cause 1) or the sysid allowlist (cause 2). It is the most
   detector-relevant choice **despite** detectors not yet being calibrated — the
   modification's expected signature (residual grows monotonically while velocity fields
   stay internally consistent) is structurally distinguishable from the benign noise
   floor (`pos_residual_m` p95 = 0.207 m, max 2.43 m in P1; a 6 m/s drift over 30 s should
   reach ~180 m uncorrected) regardless of what the absolute threshold ends up being
   after P3.
4. **Unambiguous non-claim.** Because the proxy sits strictly on the downlink path to
   the IDS, PX4's EKF never sees the modified frame — this is mechanically impossible to
   mistake for GPS spoofing of the vehicle (that would require sensor injection inside
   SITL, out of scope here), which keeps the claim class honest without relying on
   discipline alone.

**Order after this one** (the user's suggested order — modification, injection, replay,
drop, delay — is **largely right but reordered on one point**): modification →
**injection** (COMMAND_LONG rogue-source, downlink rogue telemetry) → **drop** (selective
GPS_RAW_INT suppression, reuses the modification transport/logging almost unchanged) →
**replay** (`gcs_replay`, since it needs the richer uplink-command-ACK verification
machinery built for injection, and its *value* is maximal once signing work is scoped,
not before) → **delay/jitter** last, because P1 already shows delay/jitter attacks sit
close to the observed benign jitter noise floor on this host/WSL setup — building it
before modification/injection/drop gives the weakest, least convincing first result.
Spoof-identity is folded into injection rather than given its own slot.

## 3. First attack — exact design

**Injection point**: downlink telemetry (vehicle → GCS/IDS path), inside the proxy
relay loop, between `UdpMavlinkTransport` receive-from-PX4 and forward-to-IDS.
**Claim class**: link-level detection (SITL). Explicitly **not** estimator compromise,
not physical flight deviation — PX4's own trajectory is unaffected; only what the
*observer* (IDS) sees is falsified.

### Message / fields

- **Target**: `GLOBAL_POSITION_INT` (msg id 33), fields `lat` (int32, 1e7 deg),
  `lon` (int32, 1e7 deg). Leave `vx`, `vy`, `vz`, `alt`, `relative_alt`,
  `time_boot_ms`, `hdg` untouched — this is what makes `pos_residual_m` fire (position
  diverges from velocity-implied track) and keeps the attack an honest reuse of Stage-1
  `gradual_drift` semantics (`docs/ATTACKS.md`: "injects `drift_rate_ms · elapsed`
  metres along `bearing_deg`; velocity left truthful").
- Optionally mirror the same lat/lon shift into `LOCAL_POSITION_NED` (msg id 32, fields
  `x`, `y`) if present in the same tick, since both are at ~45 Hz and a careful detector
  (or a human inspecting a position-vs-local-position cross-check later) could otherwise
  see disagreement between two "vehicle-reported" position channels that isn't the
  intended signal. Decision deferred to implementation; documented here so it isn't a
  silent inconsistency.

### Modification function

```
on GLOBAL_POSITION_INT frame at proxy time t_recv (seconds since attack onset, clamped to [0, duration_s)):
    elapsed = t_recv - onset_t
    disp_m  = drift_rate_ms * elapsed                      # metres, monotonic
    dlat    = (disp_m * cos(bearing_rad)) / EARTH_RADIUS_M
    dlon    = (disp_m * sin(bearing_rad)) / (EARTH_RADIUS_M * cos(lat_rad))
    lat_new = lat_orig + degrees(dlat)
    lon_new = lon_orig + degrees(dlon)
    rewrite lat/lon fields in place (same buffer length, MAVLink 2 fixed-size payload)
    recompute X.25 CRC over [header(after magic) .. payload] with the *target* sysid/compid/seq UNCHANGED
    forward modified frame; original is logged, never forwarded
```

- Mode: **gradual drift** for the first attack (reuses Stage-1 default mode and is the
  mode Stage-1 docs describe as "detected throughout," unlike a sustained constant
  offset with consistent velocity, which Stage-1 docs flag as "only detectable at the
  transition"). `sudden_offset` and `replay_freeze` are natural follow-on parameter
  sweeps, not separate attacks.
- Magnitude: `drift_rate_ms` drawn per trial (see randomization below) around the
  Stage-1 default of 6.0 m/s; `bearing_deg` likewise around the Stage-1 default of 90°.
- Consistency: **sysid, compid, seq, msgid, timestamp fields are never touched** — only
  the payload bytes for `lat`/`lon` and the trailing CRC. This is what makes the frame
  pass every check except the physics one; an attack that also scrambled seq would
  conflate two Stage-1 attack classes (`gps_spoofing` + `mavlink_anomaly`) in one trial,
  which breaks clean attribution. MAVLink 2 signature field (13 bytes) is absent on this
  link (`signed=0` for 100% of P1 frames) so there is no signature to break — this
  attack produces **no evidence either way** about signing; that claim is reserved for
  the replay attack once P4 exists.

### Timing

- **Warmup**: 10 s pass-through only (let IDS detector warmup/`hysteresis_ticks`
  settle and establish a `_last_fix` baseline — the residual feature needs ≥1 prior fix
  to compute an increment).
- **Onset**: configurable per trial, default drawn from a window analogous to Stage-1's
  `start_s: 40.0` (see randomization below).
- **Duration**: default drawn around Stage-1's `duration_s: 30.0`.
- **Repeat**: within one SITL flight capture (~90–130 s per P1), one attack window per
  trial keeps ground truth unambiguous; do not fire multiple onset/offset cycles in a
  single trial — run multiple independent trials instead (see below), each its own SITL
  session + fresh proxy process, to keep PX4 clock drift (P1: SITL clock runs
  10–13% slow vs wall clock) from entangling two windows.

### Randomization plan (≥10 independent trials)

Seed a single `numpy.random.default_rng(seed)` per trial batch (seed itself logged in
the manifest, not hard-coded across trials) and draw, per trial:

| Parameter | Distribution | Range | Rationale |
|---|---|---|---|
| `onset_s` | uniform | [20, 60] | avoids the 10 s warmup; stays inside a ~90–130 s capture with room for `duration_s` |
| `duration_s` | uniform | [15, 40] | brackets the Stage-1 default (30 s) without being degenerate at either extreme |
| `drift_rate_ms` | uniform | [2, 10] m/s | brackets Stage-1 default (6 m/s); lower bound stays above P1's benign `pos_residual_m` noise growth rate so a true positive is distinguishable in principle |
| `bearing_deg` | uniform | [0, 360) | direction should not matter to a correct detector; randomizing is itself a check that detection isn't an artifact of one bearing |
| `trial_seed` | derived | `seed + trial_index` | reproducibility per trial without correlating draws across trials |

Ten trials minimum, each a fresh PX4 SITL + Gazebo session (per P1's own capture
methodology) to avoid state leakage across trials (PX4 does not cleanly "reset" without
a restart per `docs/PX4_SITL_INTEGRATION.md` §1).

### Expected detector(s) and evidence (hypothesis, not a result)

- **Physics** (`pos_residual_m > 12.0` per `configs/detector.yaml`, soft with
  `hysteresis_ticks: 2`, hard at 30.0 regardless): expected to cross within
  `onset_s + 12/drift_rate_ms` seconds of onset for the default 6 m/s rate (~2 s), well
  inside `duration_s`.
- **Protocol / ML**: not expected to react to this attack specifically — current
  false-alarm-on-benign findings (P1 §6) mean *any* detector output on PX4 SITL right
  now is dominated by miscalibration, not this attack. This is exactly why P2's job is
  the proxy + ground truth, and scoring is deferred to P3 (calibration) before this
  hypothesis is tested for real.
- **What it does NOT show**: it does not move PX4's actual position (Gazebo pose
  unaffected — not verified yet, but mechanically guaranteed by the injection point: the
  proxy only ever writes toward the IDS/GCS side); it is not GPS spoofing of the vehicle
  (that claim requires sensor/estimator-level injection, out of scope); it does not
  demonstrate anything about signed MAVLink (no signature exists on this link to break);
  it does not demonstrate detection — only that the proxy can produce the intended,
  logged wire effect for later detectors to be tested against.

## 4. Ground-truth manifest schema

Written by the **proxy itself**, at modification time, frame-by-frame — never derived
from any detector output, per the red/blue separation rule. One JSON manifest per trial
plus a frame-level log.

```jsonc
// trial manifest: artifacts/sitl/attack_proxy/<trial_id>/manifest.json
{
  "trial_id": "gps_mod_gradual_drift_20261006T143000Z_t03",
  "seed": 20261006,
  "trial_index": 3,
  "px4_version": "v1.18.0-rc1-27-gc239c63807",
  "gazebo_version": "8.15.0",
  "attack_type": "gps_spoofing",          // Stage-1 AttackType.value for continuity, not reuse of Attack class
  "attack_mode": "gradual_drift",
  "message_type": "GLOBAL_POSITION_INT",
  "target_system": 3,
  "target_component": 1,
  "injection_point": "downlink",          // downlink | uplink
  "claim_class": "link_level_detection",
  "environment": "SITL",
  "attack_action": "modify_fields",
  "parameters": {
    "drift_rate_ms": 6.4,
    "bearing_deg": 118.2,
    "onset_s": 37.1,
    "duration_s": 28.9
  },
  "attack_start_utc": "2026-10-06T14:30:37.100000Z",
  "attack_end_utc":   "2026-10-06T14:31:06.000000Z",
  "frames_seen": 1584,
  "frames_modified": 1296,
  "frames_dropped": 0,
  "frames_injected": 0,
  "expected_effect": {
    "feature": "pos_residual_m",
    "predicted_threshold_cross_s_after_onset": 1.9
  },
  "actual_effect": {                       // measured post-hoc from the frame log, NOT from the IDS
    "max_lat_lon_delta_m": 184.3,
    "position_residual_proxy_estimate_m": 181.0
  },
  // filled later, by the validation step (aegis-validation), never by this proxy:
  "detector_decision": null,
  "time_to_detection_s": null
}
```

```jsonc
// frame-level log: artifacts/sitl/attack_proxy/<trial_id>/frames.jsonl (one line per touched frame)
{
  "seq_no": 211,
  "proxy_recv_time_utc": "2026-10-06T14:30:38.041223Z",
  "msgid": 33,
  "sysid": 3,
  "compid": 1,
  "mavlink_seq": 57,
  "action": "modified",                    // modified | forwarded | dropped | injected | delayed
  "field_deltas": {"lat_1e7deg": 1823, "lon_1e7deg": -940},
  "crc_recomputed": true
}
```

All timestamps ISO-8601 UTC. `detector_decision` / `time_to_detection_s` are explicit
nullable fields the schema reserves for `aegis-validation` to fill from a *separate*
join against IDS decisions — the proxy never writes them, closing off any path to
ground truth being accidentally detector-derived.

## 5. Module layout and ownership boundary

```
src/aegisflight/proxy/
  transport.py      # aegis-px4-mavlink: bidirectional relay loop, two UdpMavlinkTransport
                     # instances (upstream connect to PX4, downstream bind for IDS client +
                     # benign flight-driver client), frame pump, PX4 single-GCS-partner
                     # lock-in handling, heartbeat passthrough/forwarding per PX4_SITL_INTEGRATION §1
  attacks_live.py    # aegis-security: pure functions (raw_bytes, envelope, trial_params) ->
                     # (raw_bytes | None, FrameLogEntry); no sockets, no threads — unit-testable
                     # with synthetic frames exactly like tests/unit/test_mavlink_live.py
  groundtruth.py     # aegis-security: ManifestWriter / FrameLogWriter — schema in §4, append-only,
                     # flushed per frame; owns trial_id/seed bookkeeping
```

**Boundary**: `transport.py` exposes a hook — `on_frame(direction, raw_bytes, envelope) ->
raw_bytes | None` (None = drop) — that `attacks_live.py` implements and `transport.py`
calls per relayed frame, plus a `send_extra(direction, raw_bytes)` callback for
injection. This is the proposed **new, additive interface** for the lead to approve; it
does not touch `attacks/base.py` or any frozen contract. Transport decides *when* the
hook runs and guarantees ordering/delivery; attack logic decides *what* to do with a
frame and is fed only bytes + decoded envelope (header-first, via the existing
`MavlinkFrameParser`), never the simulator's `AttackContext`.

## 6. Red/blue separation rules

- Detector thresholds and features are **read-only** to this work (per `.claude/CLAUDE.md`);
  this proxy is built and the trial parameter *ranges* in §3 are fixed **before** any
  detector recalibration (P3) is attempted against SITL data, so P3 cannot be tuned to
  this exact implementation's fixed constants.
- **Hold-out**: of the ≥10 trials, reserve at least 3 trials' exact parameter draws
  (`drift_rate_ms`, `bearing_deg`, `onset_s`, `duration_s`) undisclosed to whoever tunes
  P3 calibration until after calibration is frozen; only the parameter *ranges* in §3 are
  disclosed up front, not the per-trial draws.
- **Disclosure requirement**: the modification function (§3) and manifest schema (§4)
  are fully disclosed in this document (mechanism transparency) — only the specific
  per-trial random draws are held out. This mirrors standard IDS evaluation practice:
  the attack class is known, the exact instance is not.
- Any future attack reusing this proxy's `on_frame` hook must log to the same
  `groundtruth.py` schema so `aegis-validation` has one join key (`trial_id`) across all
  live attacks.

## 7. Safety / security of the proxy itself

- **Loopback-only defaults.** Reuses `UdpMavlinkTransport`'s existing
  `_loopback_only()` guard (`src/aegisflight/sources/mavlink_live.py`): `bind=(None, port)`
  defaults to `127.0.0.1`; wildcard (`0.0.0.0`/`::`) requires explicit
  `allow_wildcard=True`, which this proxy's default config must never set. The upstream
  leg (`connect=(wsl_ip, 14550)`) targets only the discovered WSL NAT address — never
  hard-coded, per `.claude/CLAUDE.md` — and only the PX4 GCS port.
- **Single-partner guarantee.** Because PX4's UDP link "locks to the first sender and
  never re-learns," the proxy becomes PX4's *only* GCS partner by being the first and
  only thing that sends it a heartbeat after SITL (re)start — this is an operational
  runbook requirement (document in `docs/STAGE2_RUNBOOK.md`, owned by
  `aegis-px4-mavlink`), not something the proxy code can enforce purely in software, but
  the proxy should refuse to start if it has not itself sent the first heartbeat (fail
  closed rather than silently attach to a wrong/stale session).
- **Resource bounds.** Bounded receive queues (reuse `queue_size=16384`,
  `rcvbuf_bytes=4 MiB` already proven in P1 at ~340 frames/s); the attack hook must be
  O(1) per frame (no unbounded per-trial buffering) — the frame log is append-only and
  flushed, not buffered in memory for a whole trial.
- **No secrets.** No keys of any kind are needed for this proxy (no signing exists yet);
  nothing here generates, stores, or logs key material. Manifests contain no credentials.
- **Only talks to SITL.** The proxy's upstream socket is `connect()`-ed (kernel-level
  peer lock, matching the pattern already used for the GCS role in
  `UdpMavlinkTransport`), so OS-level `ECONNREFUSED`/filtering applies if anything else
  tries to reach it on that socket; downstream bind is loopback, so only local processes
  (IDS, flight-driver) can reach it.
- **Fan-out is multi-client by design, not IDS-exclusive** (as-built in `transport.py`,
  confirmed by `aegis-reviewer`): every modified downlink frame goes to *all* learned
  loopback clients (up to `max_clients`), not only the IDS tap. On this local-only
  testbed that is acceptable (no other process is expected on that loopback port), but
  any future reuse of the proxy's downstream port by a second real local GCS would also
  receive spoofed frames — document this if that port is ever shared.

## 8. Test plan

1. **Unit (no sockets)**: feed synthetic MAVLink 2 `GLOBAL_POSITION_INT` byte buffers
   (same technique as `tests/unit/test_mavlink_live.py`) through `attacks_live.py`'s pure
   `on_frame` function; assert lat/lon shift matches the closed-form drift formula for
   known `(onset, t, drift_rate_ms, bearing_deg)`, CRC recomputes to a valid value
   (decodeable by `MavlinkFrameParser` with no `bad_frames` increment), sysid/compid/seq
   are byte-identical to input, and outside `[onset_s, onset_s+duration_s)` the function
   is the identity (pass-through, byte-for-byte).
2. **Loopback integration (no PX4)**: two `UdpMavlinkTransport` instances on loopback
   simulating "PX4" and "IDS" ends with the proxy relay in between; inject a synthetic
   stream of `GLOBAL_POSITION_INT` + other message types at P1-observed rates, verify
   the IDS-side stream shows exactly the expected modified frames, manifest/frame-log
   counts (`frames_seen`/`frames_modified`) match, and non-attack messages pass through
   byte-identical.
3. **SITL trial procedure** (per trial): fresh PX4 SITL + Gazebo start (per
   `docs/STAGE2_RUNBOOK.md`) → proxy starts, sends first GCS heartbeat, becomes PX4's
   locked partner → benign flight driver connects through the proxy's downstream bind
   (distinct sysid, per P1 §1 forwarding note) → draw trial parameters from the seeded
   RNG → run attack window → stop capture → verify manifest `frames_modified > 0` and
   `actual_effect.max_lat_lon_delta_m` is within tolerance of
   `drift_rate_ms * duration_s` → tee raw bytes to a tlog (reuse the P1 teeing pattern)
   for later offline replay/validation. Ten such trials, parameters logged per §3/§4,
   constitute the P2 evidence set; no detection claim is made from them until P3.
