# GPS workstream: readiness plan (Stage 2, Objective 2)

**Status (2026-10-26, GPS iteration 2):** the estimator-aware position residual (gate v2, `physics.estimator_gate: true`)
is implemented in the working tree on `90b9aa2` and is **not committed**. It is outside increments G1–G7, and those are
still not implemented. Live status, review findings and every number: `docs/GPS_WORKSTREAM_PROGRESS.md`.
* **Landed (uncommitted):**
  * the extractor reads `EKF_STATUS_REPORT.flags` (a frozen-contract extension the user confirmed on 2026-10-26,
    `docs/HANDOFF.md`);
  * a debounced "no horizontal solution" state;
  * the Stage-1 rule on links that never send the report;
  * 79 tests in `tests/unit/test_gps_scenarios_fused.py`.
  * Design and limitations: `docs/DETECTION.md`, "Estimator-aware position residual".
* **Evidence:** `artifacts/validation/estimator_gate_v2/README.md`, `docs/VALIDATION_EVIDENCE.md` (2026-10-26 rows).
  * Stage-1 benchmark identical (`SIM`).
  * ALFA changes only in the unlabelled category (`REPLAY`).
  * 44 of 44 earlier replays byte-identical; none of them contains `EKF_STATUS_REPORT`.
  * Bench 008 `GPS_SPOOFING` 1 → 0 (`REPLAY` of `BENCH`, in-sample).
* **Still open:**
  * the 2026-10-25 dashboard alerts (no bytes saved, effect unknown);
  * links without `EKF_STATUS_REPORT` (PX4), where the Stage-1 rule applies unchanged;
  * the ML detector, which is not gated;
  * the attacker capability under forged or injected status. It is disclosed and SIM-only, and only MAVLink-2 signing
    closes it;
  * the commit itself, which waits for the user;
  * P3 and G1–G7, unchanged.

**Update (2026-10-25, GPS connectivity sprint):** none of the increments G1–G7 is implemented. P3 (a user decision) is still open;
nothing in this sprint requires deciding it. What changed:
* A GNSS receiver is now attached to the bench Pixhawk 6X. Its receive-only telemetry was verified end to end, through the IDS
  and the dashboard (`docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.10).
* New finding: **position-residual false `GPS_SPOOFING` alerts on a board that was stationary (operator statement), with a
  reported-valid but weak fix.** The cause is
  GNSS wander while ArduCopter's EKF reports zero velocity. It is not fixed; it is a policy decision, recorded in
  `docs/VALIDATION_EVIDENCE.md` §3. *(2026-10-26: partly addressed by iteration 2, see the status above.)*
* Synthetic GPS-content scenarios (discontinuity, velocity mismatch, the drift-rate floor, recovery, wander) are now pinned by
  `tests/unit/test_gps_scenarios_fused.py` (SIM).

**Status (2026-10-20): plan only. Nothing in this document is implemented.** It records what the code does today,
the facts established offline this sprint, one open user decision (P3), and the smallest testable increments for
the GPS spoofing / jamming workstream. Environment of every fact below: code inspection, `SIM`, or offline `REPLAY`
of existing captures/tlogs. No port was opened, no SITL was run, nothing was transmitted.

**Telemetry core is FROZEN** at `HEAD` `83f07c1` + the uncommitted tree (`git diff HEAD -- src configs | sha256sum` =
`708192a0…0ad6`). Its state is *READY FOR SUPERVISED PHYSICAL VALIDATION*: the bench run in
`docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.9 has **not** been performed, so physical validation is **PENDING**. Telemetry may
reopen only for:
1. a reproducible defect;
2. a failed acceptance test;
3. physical evidence that contradicts the implementation;
4. a GPS requirement below that cannot be met without a telemetry change.

Increments G1/G2 below are such a requirement. They are scheduled GPS work, not a reopening now.

## 0. Requirement basis
* No official Stage-2 brief is in the repository. Requirements are taken from:
  * the challenge's six attack classes, of which GPS spoofing is the *navigation* class (`docs/technical_proposal.md`
    §2, `docs/REPORT_ALIGNMENT.md`);
  * the evaluation axes stated there: high recall, very low false-positive rate, low latency, low compute,
    reproducibility, and a deployment path;
  * the report language rule: never say "detects GPS spoofing" without the constant-offset caveat
    (`docs/REPORT_ALIGNMENT.md`);
  * the claim classes and environment tags in `.claude/CLAUDE.md` and `.claude/rules/evidence-claims.md`.
* If the official Stage-2 brief adds GPS requirements (e.g. real RF or field tests), this plan must be re-checked
  against it.

## 1. Message flow and extractor state today (`src/aegisflight/features/extractor.py`)
| Message | Extractor state | Feeds |
|---|---|---|
| `GLOBAL_POSITION_INT` | `_last_gps_t`; snapshot lat, lon, alt_msl, vx/vy/vz (199-210) | `gps_age_s`, `gps_seen`; position residual (241-261, re-anchors after `_LINK_GAP_S` = 2.0 s); accel/jerk; GPS/VFR speed; GPS/baro altitude; yaw-vs-course (only if GPS speed > 2 and `gps_age` ≤ 2 s) |
| `GPS_RAW_INT` | `_gps_raw_seen`; snapshot fix_type, satellites, hdop (= eph/100) (228-232). **No timestamp** | protocol GNSS rule only |
| `VFR_HUD` | groundspeed, baro_alt | GPS/VFR speed, GPS/baro altitude, altitude rate |
| `SYS_STATUS` | battery only; GPS sensor bits **not parsed** | — |

Not used today:
* `GPS_RAW_INT` lat/lon/alt, epv, vel, cog, `time_usec`, h_acc, v_acc, vel_acc, hdg_acc;
* `GLOBAL_POSITION_INT` hdg and `time_boot_ms`;
* `EKF_STATUS_REPORT` (not streamed on the bench).

After a loss, the snapshot keeps its last values with no expiry.

## 2. Five GPS states (keep them separate)
| State | Meaning | Tracked today |
|---|---|---|
| (i) Receiver status | `GPS_RAW_INT` fix_type / satellites / eph | yes, as a frozen-forever snapshot |
| (ii) Position-stream presence | `GLOBAL_POSITION_INT` received since reset | `gps_seen` |
| (iii) Valid fix | fix_type ≥ `min_gnss_fix_type` (3) and satellites ≥ `min_gnss_satellites` (5) | per decision, on the snapshot |
| (iv) Position freshness | age of the last `GLOBAL_POSITION_INT` | `gps_age_s` |
| (v) Receiver-report freshness | age of the last `GPS_RAW_INT` | **no** (only `gps_raw_seen`) |

Presence is not validity. In bench capture 007 all 120 `GLOBAL_POSITION_INT` frames have lat = lon = 0 while
`gps_seen` is True (ArduPilot sends stale/zero position; `docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.1 S6, §6.9).

## 3. Rules and fusion interactions (file:line in the current tree)
* **Protocol** (`detectors/protocol.py`):
  * GPS dropout / never-received / coverage line (157-183);
  * GNSS rule (185-202): fix < 3 or sats < 5 for ≥ `gnss_loss_ticks` (5) **decisions** → DOS 0.7. `_gnss_ever_valid`
    changes only the wording ("lost" vs "never acquired").
* **Physics** (`detectors/physics.py`):
  * position residual: GPS_SPOOFING at 12 m, hard at 30 m;
  * GPS/baro altitude: TELEMETRY_MANIPULATION at 8 m;
  * GPS/VFR speed: TELEMETRY_MANIPULATION at 5 m/s, gated on `gps_seen is not False`;
  * acceleration: GPS_SPOOFING at 20 m/s²;
  * yaw-vs-course: 25°;
  * soft scores are damped ×0.35 until 2 consecutive ticks.
* **ML:** GPS-derived `ML_FEATURES` are `pos_residual_m`, `gps_vfr_speed_diff_ms`, `gps_baro_alt_diff_m`,
  `accel_ms2` and `yaw_course_diff_deg`. These are a **frozen contract**, and ML is off for ArduPilot.
* **Fusion** (`fusion/engine.py`):
  * noisy-OR with max-normalised weights: physics 1.0, protocol 0.882, integrity 0.588, ML 0.471;
  * threat at ≥ 0.45; severity bands 0.30 / 0.45 / 0.62 / 0.80; 4 s cooldown per attack type.
  * Consequences: the GNSS rule alone fuses to 0.6176, a SUSPICIOUS alert; a GPS dropout becomes a fused threat
    only at `gps_age` ≳ 4.04 s.

## 4. Facts established offline this sprint
Tags: CAPTURE = read from a recorded file, CODE = read from source, KNOWLEDGE = MAVLink/ArduPilot knowledge, not
repo evidence. Measurements are uncommitted scratch analyses (aegis-px4-mavlink, aegis-security, 2026-10-20) over
the named files.
* **`fix_type` 0 is `GPS_FIX_TYPE_NO_GPS`, but it does not prove a disconnected receiver.**
  * Clean ArduPilot SITL tlogs (`data/ardupilot/raw/*.clean.tlog`) were read on the autopilot's own `time_boot_ms`
    clock, *with a simulated receiver configured*. [CAPTURE]
    * They report fix 0 from the first `GPS_RAW_INT` (~2.5 s) until ~9.9 s, about 7.4 s of fix-0 reports.
    * The first fix ≥ 3 (fix 6) arrives at 10.13 s in the 5 Hz logs and 9.93–10.01 s in the 2 Hz logs.
    * NO_FIX appears for at most one report.
  * In ArduPilot, 0 also covers "no GPS configured" and "receiver stopped responding". A detected but jammed
    receiver should report 1 or a degraded fix, not 0. [KNOWLEDGE, uncertain]
  * The SYS_STATUS GPS bit reflects the same driver state, so it does not corroborate fix 0 independently.
    [KNOWLEDGE]
* **Bench capture 007** (`data/hardware/raw/telemetry_radio_007.tlog`, `time_boot_ms` 90 359–149 859) [CAPTURE]:
  * fix 0, 0 satellites, `time_usec` 0, eph 65535 and SYS_STATUS GPS bits clear in 120/120 frames.
  * It establishes that the firmware *reported* no GPS sensor about 90–150 s after boot. It does not establish
    whether a module was attached, the `GPS_TYPE` value, the wiring or the baud rate.
* **The SITL GNSS attack chose fix 0 itself** [CODE + CAPTURE]:
  * `GnssDegradationAttack` draws `fix_type = round(uniform(0, 1))` (`src/aegisflight/proxy/attacks_live.py`
    ~284-315) and overwrites PX4's own value.
  * Across the 14 `artifacts/sitl/p2n_*` manifests, every original frame was fix 3 with 10 satellites.
  * The trials contain **10 distinct draws**, 5 at fix 0 and 5 at fix 1. All 14 manifests use seed 7001;
    `final_001–003` and the pilot repeat n10 trial indices 0–2 and 0, so they are re-runs, not new samples.
  * SIM `gnss_jamming` uses fix 1 (`attacks/scenarios.py` ~214). In every SIM and SITL GNSS attack a valid fix
    precedes onset.
* **`GPS_RAW_INT` interval** [CAPTURE]:

  | Stream | Median | Max |
  |---|---|---|
  | bench 007 | 504 ms | 505 ms |
  | ArduPilot SITL 5 Hz (six tlogs) | 198–216 ms | 210–244 ms |
  | ArduPilot SITL 2 Hz | 547 ms | 556 ms |
  | PX4 SITL benign (9 tlogs) | 222 ms | 224–295 ms |
  | PX4 SITL `benign_002` | 222 ms | **1 433 ms** |
* **Clocks** [CODE]:
  * Live sources stamp with `time.monotonic_ns`, and `t` = tick index / rate.
  * `frame_ticks` replay never decreases `t`; a backwards tlog stamp becomes a late frame.
  * `tlog_adapter` clamps backsteps under 1 s and splits on a backstep over 1 s or a gap over 30 s, with a fresh
    pipeline per segment.
  * A negative `elapsed` in the protocol detector is therefore unreachable on every path inspected. The ULog path
    was not checked.

## 5. P3 decision brief: a GNSS fix never valid since monitoring began or `reset()` (USER DECISION)
Today (option A), it is DOS 0.7, fused 0.6176 SUSPICIOUS, alerting every ~4 s. Capture 007 gave 15 alerts in 60 s
(`artifacts/hardware/replay_p1p2_007/`).

| | A alert (today) | B coverage only | C profile key | D fix 0 → health | **D′: D only before the first valid fix** |
|---|---|---|---|---|---|
| Security coverage | full | jamming from power-on silent | depends on deployed profile | NO_FIX still alerts | as D; fix 0 *after* a valid fix still alerts |
| Bench like 007 (fix 0) | alert every ~4 s | quiet | per profile | quiet | quiet |
| False positives | benches; cold starts (ArduPilot SITL: ~7.4 s of fix 0, then ≤ 1 NO_FIX report) | none | misconfiguration | cold-start NO_FIX on real receivers (KNOWLEDGE; SITL shows ≤ 1 report, below `gnss_loss_ticks`) | same as D |
| Monitoring starts mid-interference | alerts | silent | per profile | alerts if NO_FIX | alerts if NO_FIX |
| After IDS restart / `reset()` (clears `_gnss_ever_valid`) | alerts | silent | per profile | NO_FIX alerts, fix 0 quiet | same as D |
| Effect on existing evidence | none | none in SIM/SITL (all start after a fix) | — | the 5 p2n draws at fix 0 would need re-scoring | **none expected** (all p2n trials are after a valid fix; must be verified by re-scoring) |
| Tests needed | none | unit + integration | profile-load tests | fix {0,1} × {never valid, after valid}; SIM regression; p2n re-score | same as D |

* **Armed-state gating (option E) is not recommended.** The armed bit is read from any source's HEARTBEAT
  (`extractor.py` 195-197); on an unsigned link an injector controls it.
* Safeguards for B, C, D and D′ (all **proposed, not implemented**):
  * a startup banner naming the GNSS policy;
  * the policy recorded in the runner's `summary.json`;
  * a test that the shipped profiles load the intended value.
* **Recommendation: D′.** It keeps every existing SIM/SITL detection, which all start after a valid fix. It quiets
  the only observed bench condition. Jamming from power-on still alerts if the receiver reports NO_FIX (that
  jamming presents as NO_FIX is KNOWLEDGE, not repo evidence). An in-path attacker gains nothing new, because it can
  already rewrite fix_type or drop `GPS_RAW_INT`. The remaining cost is cold-start NO_FIX alerts.
* **Questions for the user:**
  1. Adopt D′, or A/B/C/D?
  2. Are cold-start NO_FIX alerts acceptable, or should there be a GNSS start-up grace? A grace would also hide
     power-on jamming for its duration.
  3. Does any decision differ between the default profile and `configs/px4_sitl`?
* Until decided, A stays in force and is documented.

## 6. Offline telemetry gaps: classification
A = must fix before telemetry sign-off · B = fix before GPS implementation · C = documented limitation for this
stage · D = user / competition decision.

| Gap | Class | Reason |
|---|---|---|
| No `GPS_RAW_INT` freshness check: a frozen bad fix alerts forever, a frozen good fix masks a later loss, and a missing stream is silent | **B** | GNSS-quality claims need it. It is not a defect against the documented telemetry scope (the gap is already disclosed in `docs/DETECTION.md` / `docs/THREAT_MODEL.md`). → G1 + G2 |
| `GLOBAL_POSITION_INT` presence ≠ position validity (007: lat/lon 0) | **B** | Matters once position-based GPS claims are made on real stacks. → G3 |
| Presence counted from any source/sysid | **C** | Needs injection on an unsigned link; never observed in any capture; the real fix is MAVLink 2 signing. Opt-in design → G6 |
| Clock going backwards | **C** | Unreachable on all inspected paths (§4); no code needed. The ULog path was not checked |
| Dashboard not connected to physical runner output | **D** | An operator-visibility feature, not a telemetry defect. Whether a live physical dashboard is required for Stage-2 is a user/competition decision |

Nothing is class A.

## 7. GPS threat scenarios
**Existing**, all link-level:

| Scenario | Environment | Evidence |
|---|---|---|
| `gps_spoofing` (`gradual_drift`, `sudden_offset`, `replay_freeze`; lat/lon only, velocity truthful) | SIM | `artifacts/benchmarks*/`; constant-offset caveat |
| `dos:gnss_jamming` (fix 1) | SIM | same |
| `PositionDriftAttack` on downlink lat/lon | PX4 SITL and ArduPilot SITL | `artifacts/sitl/p2_*`, `artifacts/ardupilot/ap_attack_drift_00{1,2,3}` |
| `GnssDegradationAttack` (fix 0/1, 0–4 satellites) | PX4 SITL | `artifacts/sitl/p2n_*` |
| `DropAttack` (position + raw GPS together, onset 35–45 s) | PX4 SITL | `artifacts/sitl/p2d_*` |

None of these shows estimator compromise or physical deviation.

**Missing** (attack design belongs to aegis-security; claim class in brackets):
1. velocity-consistent drift, where lat/lon, velocity, groundspeed and heading all agree [link-level];
2. a drift-rate sweep down to slow ramps [link-level];
3. `GPS_RAW_INT` vs `GLOBAL_POSITION_INT` inconsistency [link-level];
4. replay of old GPS frames [link-level];
5. jamming or position suppression from link-up, with no warm-up [link-level via the proxy; estimator compromise if
   done by SITL GPS-disable/failure injection];
6. receiver-side spoofing via SITL sensor injection [estimator compromise; simulated physical deviation]. This needs
   the user's go-ahead for WSL runtime commands; the PX4 tree stays unmodified.
7. position forgery as sysid 1 [link-level; closed only by signing];
8. uplink RTCM/inject corruption [command-path; SITL RTK support unverified].

## 8. Increments (smallest first; each is additive, and defaults reproduce today's behaviour unless stated)
Every increment goes through the same validation:
1. unit and fused tests;
2. Stage-1 `aegis benchmark --out <scratch> --no-figures`, which must give TP/FP/TN/FN 6535 / 4 / 16826 / 65 with
   identical non-timing columns;
3. replay of `artifacts/hardware/replay_p1p2_00{5,7}` inputs, ArduPilot `ap_benign_*` and the PX4 calibration
   tlogs, diffing decisions;
4. live PX4 and ArduPilot SITL benign flights, split by flight;
5. supervised bench.

No new threshold is introduced without the benign data that sets it.

**G1 + G2 must ship together.** G1 alone would let an attacker jam, trigger the alert, then drop `GPS_RAW_INT` so
the alert ends silently.

* **G1. `GPS_RAW_INT` freshness (correctness).**
  * Change: extractor `_last_gps_raw_t` → `FeatureFrame.gps_raw_age_s` (outside `ML_FEATURES`; 999 if never received;
    `None` on hand-built frames). The GNSS rule judges the snapshot only while the report is fresh
    (`gnss_report_max_age_s`, default = `gps_dropout_s` 2.0 s). The default must be checked against §4: the 1.433 s
    maximum plus about 0.3 s of tick/decision quantisation leaves little margin.
  * Accept when:
    * a fresh bad fix still fires;
    * a frozen bad fix stops after the timeout;
    * a frozen good fix is no longer counted as valid;
    * a never-received report stays silent;
    * `None` frames behave as today;
    * `reset()` clears the timestamp;
    * the Stage-1 regression is identical (SIM sends `GPS_RAW_INT` once per decision);
    * replays 005/007 are identical;
    * 0 decisions change on PX4/ArduPilot benign tlogs, or every change is explained.
* **G2. Staleness reporting (policy; needs user approval of the key and default).**
  * Change: a stale or never-received `GPS_RAW_INT` gives a score-0 coverage line by default, so optional streams
    never alert. `protocol.require_gps_raw: true` makes it a DOS fault after the timeout.
  * Accept when:
    * the default never alerts;
    * `require` faults only after the timeout;
    * the coverage text is distinguishable from the `GLOBAL_POSITION_INT` line;
    * the runner's `telemetry_coverage` gains `gps_raw_age_s`.
* **G3. Receiver-status wording and P3.**
  * Change: evidence names NO_GPS vs NO_FIX. After the user decides P3, implement D′ (or the chosen option).
  * Parsing the SYS_STATUS GPS bits is a new field mapping, a **frozen contract**: it needs user approval, a
    migration note and regression.
  * Accept when: the fix {0, 1, ≥3} × {never valid, after valid} matrix holds; the 10 distinct p2n draws re-score
    to the same verdicts; and SIM `gnss_jamming` recall is unchanged.
* **G4. Count `GPS_RAW_INT` reports, not decisions, for `gnss_loss_ticks`.**
  * Stage-1-neutral by construction (one report per decision); verify that by regression.
  * The real-stack meaning must be set from benign report rates and fix-outage durations, split by flight.
* **G5. Gate the speed and GPS/baro checks on `gps_age` ≤ 2 s after a loss.**
  * This mirrors the existing yaw gate.
  * **May move blackout sessions.** They are in `artifacts/benchmarks_extended/`, not in the `aegis benchmark`
    baseline, so G5 additionally needs the extended-benchmark regression (into scratch, never the committed path).
    It also needs approval and re-documentation. High risk; last.
* **G6. Source-scoped liveness** (opt-in `protocol.liveness_sources: any | expected`, default `any`).
  * Accept when:
    * a heartbeat from sys255 only, with the vehicle silent, faults under `expected` and stays quiet under `any`;
    * sys42 `GLOBAL_POSITION_INT` after the vehicle's stream is lost is reported under `expected`;
    * all existing tests are unchanged under the default;
    * the regression is identical.
  * Disclose that the identity is claimed, not authenticated.
* **G7. Attack coverage.**
  * aegis-security implements the missing scenarios in §7 as pre-registered SITL experiments: hypothesis, injection
    point, ground truth from the injector log, n flights, and a paired clean control.
  * aegis-detection evaluates on held-out flights and discloses that the attack implementation was known.

## 9. What each environment can and cannot prove
* **SIM**: rule logic, regression, recall on simulated attacks. Not real-stack behaviour.
* **SITL (PX4, ArduPilot)**: real autopilot message timing and fix semantics; link-level detection via the proxy;
  estimator compromise via sensor/failure injection (with approval). Not RF, not a real receiver.
* **Indoor bench (current Pixhawk 6X)**: telemetry ingestion only. It reports **no GPS receiver**, so it cannot show
  fix acquisition, loss, jamming, spoofing or any GPS detection.
  *(2026-10-25: a receiver is now attached. The bench shows real fix acquisition and degradation, plus receiver-side false
  alarms (§6.10). It still cannot show jamming, spoofing or any GPS detection, because nothing is injected into a physical
  vehicle.)*
* **Hardware prerequisites for GPS bench work:**
  * a GNSS receiver confirmed attached and configured, read-only parameter check by a person;
  * sky view, outdoors or with a window antenna;
  * the `EXTRA3` stream if `EKF_STATUS_REPORT` is wanted;
  * no RF transmission of any kind (spoofing/jamming hardware is out of scope and not authorised).
* **Not claimable without new evidence:** real RF spoofing or jamming detection, flight deviation, field false-alarm
  rates.

## 10. Metrics and evidence for the Stage-2 report
Every result is tagged with environment and claim class; rows from different tags are never merged.

| Metric | How |
|---|---|
| Detection per pre-registered scenario | DETECTED / n with n stated (never a rate for small n); time from onset to first alert (min/median/max); detector that fired |
| False alarms | paired clean-control alerts in the attack window; benign alerts per flight on held-out SITL flights (n flights, flight-hour exposure) |
| Stage-1 regression | TP/FP/TN/FN identical, or an intended change re-documented |
| Cost | decision latency p99, CPU % (machine stated) |
| Provenance | git commit + diff hash, PX4 `git describe` / ArduPilot version, Python/package versions, config/model hash, regeneration command |
| Known gaps reported | constant-offset GPS, velocity-consistent drift (until tested), presence not authenticated, no RF evidence |

## 11. Telemetry backlog (non-blocking; deliberately not implemented)
* Offline bench-gate checker for the §6.9 outputs. The criteria are listed in the closure handoff.
* Parametrise or strip the absolute scratch path in `artifacts/hardware/loopback_dryrun_20261020/tools/run_one.sh`
  before committing.
* `configs/px4_sitl/detector.yaml` has a stale generated `startup_grace_s` comment (the value is now inert).
* Index this document and the §6.9 procedure in `docs/README.md` when the next doc sync happens.
* Runner: save input bytes (tlog via `TapTransport`), a bounded `decisions.jsonl`, and an environment tag in
  `summary.json` (`docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.4(b)).
* Dashboard: read-only `--follow <run-dir>` backend mode with a SIM/SITL/BENCH source label (§6.4 steps 4–5),
  a class D decision.
