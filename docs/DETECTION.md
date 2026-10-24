# AegisFlight — Detection Methodology

Four independent detectors each emit a `DetectorResult` (a normalised `score`
∈ [0,1], a `triggered` flag, human-readable `evidence`, and `attack_votes`).
The `FusionEngine` combines them into one `ThreatAssessment`.

Three scores, three meanings:

| Term | Range | Meaning |
|---|---|---|
| **detector score** | 0–1 | one layer's confidence that *something* is wrong |
| **threat score** | 0–1 | fused, cross-layer threat level (noisy-OR, see below) |
| **confidence** | 0–1 | threat strength × attribution dominance — a *heuristic score, not a calibrated probability* |

---

## Detector A — Protocol / rule engine (`detectors/protocol.py`)

Stateless per-frame rules over MAVLink transport behaviour. Sub-scores (the
detector score is their max); each casts a vote for the attack it implies:

| Rule | Threshold (config `protocol.*`) | Votes |
|---|---|---|
| Message flood | `msg_rate ≥ max_msg_rate_hz` (400) → 1.0; `> spike_factor×nominal` (84) → ramp | DOS |
| Sequence gaps | `max_seq_gap > max_seq_gap` (30) | DOS if rate high, else MAVLINK_ANOMALY |
| Rogue telemetry source | sysid ∉ expected & not a command source | MAVLINK_ANOMALY |
| Heartbeat stale | `heartbeat_age > heartbeat_timeout_s` (3); never received: elapsed monitoring time `> heartbeat_timeout_s` and past `startup_grace_s` (0 = off) | DOS |
| GPS dropout | `gps_age > gps_dropout_s` (2); never received: coverage line only (score 0) unless `require_global_position`, then elapsed `> gps_dropout_s` and past `startup_grace_s` | DOS |
| GNSS fix loss | `fix_type < min_gnss_fix_type` (3) or `satellites < min_gnss_satellites` (5) for `≥ gnss_loss_ticks` (5) consecutive decisions → 0.7 | DOS |
| Command provenance | command from sysid ∉ `expected_gcs_sysids`; sensitive cmd / burst | COMMAND_INJECTION |
| Signing | `require_signing` and unsigned present | MAVLINK_ANOMALY |

### Never-received vs lost-after-seen telemetry (protocol liveness rules)

`FeatureExtractor` reports `heartbeat_age_s` / `gps_age_s` as a 999 s **sentinel** until the
first HEARTBEAT / `GLOBAL_POSITION_INT` arrives. Additive `FeatureFrame` fields (`None` on
hand-built frames, not in `ML_FEATURES`) say explicitly whether a message was *ever* received
since the last reset, so a real outage longer than 999 s is no longer indistinguishable from
"never seen": `heartbeat_seen`; `gps_seen` = **position presence** (`GLOBAL_POSITION_INT`);
`gps_raw_seen` = any `GPS_RAW_INT` (reported, but not position presence).

GPS position policy (user decision 2026-10-15, "Coverage, not attack"): key
`protocol.require_global_position` (default `false`, set in `configs/detector.yaml`). A
never-received stream is judged on **elapsed monitoring time** (`t` minus the first decision),
not on the 999 s sentinel, so the first decision does not fire merely because nothing has
arrived yet.

| Case | Score / vote | Evidence |
|---|---|---|
| `GLOBAL_POSITION_INT` never received, default (`require_global_position: false`); with or without `GPS_RAW_INT` | **changed**: score 0, no vote -- a coverage condition, not a threat or alert; physics position checks are inactive | **new**, on every such decision: `coverage: GLOBAL_POSITION_INT never received (GPS_RAW_INT present\|GPS_RAW_INT never received\|GPS_RAW_INT presence unknown); position-dependent checks inactive; not attack evidence under this profile (protocol.require_global_position=false)` |
| `GLOBAL_POSITION_INT` never received, `require_global_position: true` (`GPS_RAW_INT` does not satisfy it) | DOS (`never_seen_gps_vote`), score from the sentinel ramp (1.0) capped by `never_seen_gps_max_score`; only once elapsed `> gps_dropout_s` and past `startup_grace_s` | `GPS dropout: never received (no GLOBAL_POSITION_INT since monitoring began; incomplete telemetry, not a measured dropout) > 2.0s` |
| Heartbeat never received | DOS, 1.0 (sentinel ramp); **changed timing**: only once elapsed `> heartbeat_timeout_s` (3 s) and past `startup_grace_s` -- no longer on the first decision | `heartbeat stale (never received: no HEARTBEAT since monitoring began) > 3.0s` |
| GPS / heartbeat lost after being received | unchanged | unchanged: `GPS dropout 2.4s > 2.0s`, `heartbeat stale 4.2s > 3.0s` |
| Age below threshold (stale-but-recent) | unchanged: 0, no evidence | none |
| GNSS fix bad, a valid fix (fix ≥ 3 and sats ≥ 5) seen earlier since start/`reset()` | unchanged: DOS, 0.7 | unchanged: `GNSS fix lost: fix_type=0, satellites=0 for 5 decisions` (parsed by `scripts/sitl/make_p2n_summary.py`) |
| GNSS fix bad, no valid fix ever seen (e.g. cold receiver, no sky view; also no receiver at all, see "fix_type 0" below) | unchanged: DOS, 0.7 | **changed text**: `GNSS fix never acquired: fix_type=0, satellites=0 for 5 decisions (no valid fix since monitoring began)` |

The never-received fault texts keep the `GPS dropout` / `heartbeat stale` prefixes that
downstream scripts match; the coverage line deliberately contains neither `GPS dropout` nor
`lost`, so a dropout/loss-matching script does not count it.

**Security consequence of the default (disclosed, not mitigated).** Under `require_global_position: false` an in-path
adversary that suppresses `GLOBAL_POSITION_INT` *before the IDS first observes it* (from link-up, or across an IDS restart /
`pipeline.reset()` while the stream is already suppressed) is reported only as the score-0 coverage line, and it also blinds
the position-dependent physics checks that drive `GPS_SPOOFING` detection. Before this change the same situation was a
CRITICAL `DOS` alert. The IDS cannot tell why the stream is absent: "not attack evidence under this profile" in the
evidence text is a policy label (*not scored* as attack evidence), not an observation. Suppression *after* the stream was
seen is still a `DOS` loss alert, but not at once: the protocol rule fires at `gps_age > gps_dropout_s` (2 s) with score
0.5, which fuses to 0.5 x 0.30/0.34 = 0.441 < `threat_threshold` 0.45 (no threat). A protocol-only fused threat needs a
score of 0.45 / 0.882 = 0.51, i.e. the ramp `(gps_age - 2) / (6 - 2)` >= 0.51, so `gps_age` >= ~4.04 s (pinned by
`test_genuine_gps_dropout_detector_fires_at_threshold_but_fused_alert_waits`). An IDS restart / `pipeline.reset()` inside
that window, with the stream still suppressed, leaves only the coverage line. Deployments where position is expected must set `require_global_position: true`, and a
live source must not call `pipeline.reset()` on reconnect (today none does). The runner persists the condition in
`summary.json` / `health.jsonl` (`telemetry_coverage`), not as an alert.
The never-acquired GNSS text deliberately does NOT contain "lost" (a loss-matching script will not
count it); whether a never-acquired fix should also *score* differently is an open question,
detector policy P3 (`docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.5), not changed here.
`startup_grace_s` (default 0 = off) suppresses only the never-received case, for that many
seconds after the first decision; it combines with the elapsed-time gate as a maximum (the later of
the two applies; it does not add to it). A loss after valid data is never covered by either.

Optional keys, effective **only with `require_global_position: true`** (`configs/detector.yaml`
does not set them): `protocol.never_seen_gps_vote` (default `DOS`; e.g. `MAVLINK_ANOMALY`) and
`protocol.never_seen_gps_max_score` (default 1.0; floored at 0.5). The floor guarantees
**detector-level** reporting only -- the protocol detector triggers with score >= 0.5 and the
evidence is in that decision's assessment. It does **not** guarantee a fused threat or an operator
alert: 0.5 x the max-normalised protocol fusion weight (0.30/0.34) = 0.441 is below
`fusion.threat_threshold` (0.45), so at the floor the assessment is `threat=False` and is not
alerted **when protocol is the only contributing detector**. Under the noisy-OR a small second
score lifts it past 0.45: ML >= ~0.034 (weight 0.16/0.34) or physics >= ~0.016. On a link whose
position stream was *never* received, the physics speed gate (below) removes the usual physics
contribution. So with `require_global_position: true` and `never_seen_gps_max_score: 0.5`, a moving
position-less vehicle now fuses to 0.441 (no threat); before the gate it was a threat. No shipped
profile sets that combination, and no test pins it. The keys never affect a measured dropout.

Known limits of the presence / GNSS rules (documented, not changed):

- **No shipped profile requires position.** `configs/detector.yaml` sets
  `require_global_position: false`; `configs/px4_sitl/detector.yaml` does not set it (built-in
  default `false`). The PX4 profile's `startup_grace_s: 1.4` no longer does anything: both elapsed
  gates (heartbeat 3 s, position 2 s) end later than 1.4 s, so the grace never decides.
- **Presence counts any source.** `heartbeat_seen` / `gps_seen` / `gps_raw_seen` and the ages are
  updated by a HEARTBEAT / `GLOBAL_POSITION_INT` / `GPS_RAW_INT` from *any* sysid/compid, so for
  example a GCS heartbeat could keep heartbeat liveness fresh while the vehicle's own is absent.
  Latent: in bench captures 005-007 every such message is from sys1/comp1.
- **`GPS_RAW_INT` has no staleness / age check** (known gap, pre-existing). The extractor keeps the
  last `fix_type` / `satellites`, and tracks only "ever received" (`gps_raw_seen`). If
  `GPS_RAW_INT` stops, the GNSS rule keeps judging the frozen value (a frozen good fix stays quiet,
  a frozen bad fix keeps firing). If it never arrives, the GNSS rule is silent. "GPS_RAW_INT
  present" in the coverage line means received at least once since reset, not currently arriving.
  The rule counts decisions, not reports: at 1 Hz one bad report spans 5 decisions and fires it.
- **fix_type 0 vs 1.** The GNSS rule does not distinguish `GPS_FIX_TYPE_NO_GPS` (0, no receiver
  connected) from `NO_FIX` (1); both give the same evidence and score. Bench capture 007 (`BENCH`,
  stream description, not detection): the 120 `GPS_RAW_INT` counted in
  `artifacts/hardware/telemetry_radio_probe_007.json` were read back from its git-ignored input
  `data/hardware/raw/telemetry_radio_007.tlog` (sha256 `0a701331…d0e17a`; the field values are not
  in the committed JSON): all fix_type 0, 0 satellites, eph 65535, with the `SYS_STATUS` GPS
  present/enabled/healthy bits all false and `GLOBAL_POSITION_INT` at (0, 0). That is a board
  reporting **no GPS receiver**, not a receiver without a fix.
- **Where the coverage line is visible.** It is in every assessment's evidence (always the last
  protocol item, so it never heads an alert raised by another rule), but only alerts are persisted
  (event store / hash chain), and the dashboard evidence panel shows evidence only for threats.
  `scripts/hardware/run_serial_ids.py` persists the condition as `telemetry_coverage` in
  `summary.json` / `health.jsonl`.

Stage-1 effect: the simulated streams carry HEARTBEAT and `GLOBAL_POSITION_INT` from the first
decision (now pinned by `tests/integration/test_sim_presence_paths.py`, 7 scenarios), so these
paths (and the physics speed gate below) are not expected to move the Stage-1 benchmark.
aegis-validation ran the regression on an **earlier code state** of this change (2026-10-16,
scratch output, not committed): TP/FP/TN/FN 6535 / 4 / 16826 / 65, `results.csv` identical to
`artifacts/benchmarks/` on all non-timing columns (see `docs/VALIDATION_EVIDENCE.md`). `src/`
changed after that run (physics speed gate, coverage line moved last). **Re-run on the current code
(2026-10-20, `src`+`configs` diff sha256 `708192a0…0ad6`, scratch output, not committed):**
`aegis benchmark --out <scratch> --no-figures` → TP/FP/TN/FN 6535 / 4 / 16826 / 65 over 23,430
decisions; all 42 rows x 9 non-timing columns of `results.csv` identical to `artifacts/benchmarks/`.
The speed gate changes 0 of 194,628 ALFA replay decisions (`gps_seen` False and speed diff > 5 never
co-occur), so `artifacts/external/` is unaffected (see `docs/VALIDATION_EVIDENCE.md`).

Physics blind spot (reported; one rule gated): with no `GLOBAL_POSITION_INT` ever received,
`pos_residual_m`, `accel_ms2` (and jerk), `gps_baro_alt_diff_m` and `yaw_course_diff_deg` stay 0,
while `gps_vfr_speed_diff_ms` equals the `VFR_HUD` groundspeed (0 without `VFR_HUD`), because the
missing GPS velocity is read as 0. A moving vehicle would therefore turn the missing stream into
`TELEMETRY_MANIPULATION` evidence, so the GPS/VFR speed **rule** is gated on position presence
(`gps_seen is not False`; P1 follow-up, 2026-10-20). `gps_seen` `None` (hand-built frames) and
`True` (Stage-1 SIM) behave as before. The feature itself is unchanged (`ML_FEATURES` is frozen)
and the ML detector still sees it. The altitude-rate (`VFR_HUD` baro) and battery (`SYS_STATUS`)
checks do not need position and still run. The position cross-checks are thus silent, not alarmed
-- the coverage line above is then the only signal that they cannot run. After a **loss**
(position seen, then stopped) the extractor keeps the last GPS velocity and altitude, so the speed
and GPS/baro checks compare stale GPS values against fresh `VFR_HUD` values (pre-existing Stage-1
behaviour, documented, not changed); heading-vs-course is skipped once `gps_age` > 2 s.

## Detector B — Cyber-physical consistency (`detectors/physics.py`)

Cross-checks physically-coupled channels an attacker can't falsify all at once:

| Check | Threshold (config `physics.*`) | Votes |
|---|---|---|
| Position residual (reported track vs velocity-implied) | `> gps_pos_residual_m` (12); hard `≥ 30` | GPS_SPOOFING |
| GPS altitude vs baro altitude | `> alt_consistency_m` (8) | TELEMETRY_MANIPULATION |
| GPS-velocity speed vs VFR groundspeed | `> gps_speed_consistency_ms` (5); not evaluated if `GLOBAL_POSITION_INT` was never received | TELEMETRY_MANIPULATION |
| Altitude rate plausibility | `> alt_jump_ms` (25) | TELEMETRY_MANIPULATION |
| Acceleration plausibility | `> max_accel_ms2` (20) | GPS_SPOOFING |
| Battery voltage rise / collapse | `> battery_rise_v` (0.4) / `battery_drop_rate_v_s` (2) | TELEMETRY_MANIPULATION |
| Heading (attitude) vs course-over-ground | `> yaw_course_deg` (25; configurable) | TELEMETRY_MANIPULATION |

A **hysteresis** (`hysteresis_ticks`) damps soft triggers until they persist,
suppressing single-tick GPS-noise spikes; a hard position residual fires
immediately.

## Detector C — ML anomaly (`detectors/anomaly.py`)

Benign-trained **ensemble** over the 11-feature `ML_FEATURES` vector, combined
as `max(isolation-forest z, mahalanobis z)`:

- **Isolation Forest** — subtle *in-distribution* multivariate anomalies.
- **Diagonal Mahalanobis / scaled-norm** — the L2 norm of the standardised (z-score) vector,
  i.e. Mahalanobis distance with a *diagonal* covariance (feature correlations ignored) and
  ordinary mean/std (not a robust estimator).
  Isolation Forest cannot extrapolate past its training range, so it is blind to
  out-of-range spikes (msg-rate floods, sequence gaps); the scaled-norm covers
  that blind spot.

The normalised score is a logistic of the combined signal (calibrated so benign
validation stays low). Attribution uses the most-deviating standardised feature
(`FEATURE_ATTACK_MAP`). Trigger at `anomaly.score_threshold` (0.62). If no model
is present the detector is a no-op (score 0) so the rest of the system still
runs. See `docs/ML_PIPELINE.md`.

## Detector D — Firmware integrity (`detectors/integrity.py`)

Re-hashes firmware components against a SHA-256 manifest (**unsigned** in the PoC; signing is future work)
(`FirmwareVerifier`, throttled to every `recheck_every` decisions). An INVALID
verdict → score 1.0, vote FIRMWARE_INTEGRITY, with the exact mismatched
component(s) as evidence. This is genuine crypto, not a mock.

---

## Fusion (`fusion/engine.py`) {#fusion}

A plain weighted sum would cap a lone detector below the 0.45 threshold (a
firmware failure at weight 0.20 would never alert). Instead:

```
w'_i   = w_i / max_j(w_j)            # max-normalised config weights
threat = 1 - Π_i (1 - score_i · w'_i)   # noisy-OR
```

This keeps the config's *relative* trust (physics highest, ML lowest), lets a
single strong high-trust detector raise a threat, boosts the score when
detectors corroborate, and keeps a lone weak ML signal below threshold. Note: a lone ML
score ≥ 0.956 (0.45 / 0.47) *does* cross the threat threshold on its own, and on the
baseline benchmark every false positive is of this kind (compare the ML-off ablation,
`artifacts/benchmarks_ablation_no_ml/summary.md`).

- **Attribution:** `attack_type = argmax` of the weight-scaled vote sum across
  detectors; strong runners-up become `secondary_indicators`.
- **Severity:** bands (`WATCH` 0.30 / `SUSPICIOUS` 0.45 / `HIGH` 0.62 /
  `CRITICAL` 0.80).
- **Alerting:** an assessment becomes an *alert* (`is_alert`) when severity ≥
  `alert_threshold_severity` and it is outside the per-attack `cooldown_s`
  window; `clear_ticks` consecutive normal decisions clear the active state.

Every alert carries the concatenated evidence from all firing detectors — there
are no unexplained black-box alerts.

## Per-vehicle calibration (PX4 SITL)
Thresholds above are the **Stage-1 simulator** values and are the reference condition. A
separate, generated PX4-SITL profile (`configs/px4_sitl/detector.yaml`) and a separate
PX4-benign anomaly model (`models/isoforest_px4.joblib`) exist for false-alarm reduction on
that stack only; methodology, held-out evaluation and the cost side (what the loosened
rules may no longer catch) are in `docs/CALIBRATION_PX4.md`. It is not attack detection.
