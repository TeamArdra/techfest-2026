# AegisFlight — Feature Catalogue

The `FeatureExtractor` (`features/extractor.py`) consumes decoded
`MessageEnvelope`s (`update(msg)`), reconstructs an observed `TelemetrySnapshot`,
and emits a `FeatureFrame` at each decision tick (`extract(t)`). It is
**policy-free**: it computes physical quantities and raw aggregates; detectors
apply thresholds and the "expected source" policy.

## Feature groups

### Network / transport
| Feature | Unit | Meaning / calculation | Used by |
|---|---|---|---|
| `msg_rate_hz` | msg/s | messages in the last `rate_window_s` (1 s) | protocol, ML |
| `interarrival_mean_ms` / `interarrival_jitter_ms` | ms | mean / std of inter-arrival in the window | protocol, ML |
| `max_seq_gap` | count | largest per-source sequence jump this decision window | protocol, ML |
| `n_sources` | count | distinct (sysid,compid) seen this window | protocol |
| `sources` | map | (sysid,compid) → count (rogue-source detection) | protocol |
| `heartbeat_age_s` / `gps_age_s` | s | time since last HEARTBEAT / GLOBAL_POSITION_INT | protocol |
| `loss_ratio` | 0–1 | `min(1, max_seq_gap/50)` loss estimate | protocol, ML |
| `signed_ratio` | 0–1 | fraction of signed messages | protocol |

### Navigation / cyber-physical
| Feature | Unit | Meaning / calculation | Used by |
|---|---|---|---|
| `pos_residual_m` | m | **bounded sliding-window sum** of (measured displacement − velocity·dt); the signature GPS-spoofing signal | physics, ML |
| `gps_vfr_speed_diff_ms` | m/s | `|hypot(vx,vy) − VFR groundspeed|` | physics, ML |
| `gps_baro_alt_diff_m` | m | `|GPS altitude − baro altitude|` (independent channels) | physics, ML |
| `alt_rate_ms` | m/s | baro-altitude derivative (decision cadence) | physics, ML |
| `accel_ms2` / `jerk_ms3` | m/s²,³ | horizontal accel/jerk from velocity history | physics, ML |
| `battery_v_rate` / `battery_v_rise` | V/s | battery-voltage derivative / upward part | physics (**not** ML*) |
| `yaw_course_diff_deg` | ° | `|attitude yaw − course-over-ground|` (frozen-attitude signal) | physics, ML |
| `ekf_flags` / `ekf_age_s` | — / s | last `EKF_STATUS_REPORT.flags` and its age at `t`; `None` = never received | physics (**not** ML) |
| `nav_solution` | bool / None | estimator state at the **latest position fix** (not at `t`; before the first fix, at `t`): True = horizontal solution, False = none (`CONST_POS_MODE`, or no `POS_HORIZ_ABS/REL`), None = unknown (no report, or older than 2 s at that fix) | diagnostic only (**not** ML) |
| `nav_gated` | bool | the latest fix was *gated*: fresh no-solution report **and** no-solution reported continuously for ≥ 2 s (a solution report or a > 2 s report gap restarts the run); `False` by default; the latest-fix state, so it goes stale if `GLOBAL_POSITION_INT` stops | physics (**not** ML) |
| `pos_residual_nav_m` | m | `pos_residual_m` over the same 15-fix window without the increments of gated fixes and of the gated → ungated transition fix; **exactly** `pos_residual_m` when the window holds neither; `None` if `EKF_STATUS_REPORT` was never received | physics (**not** ML) |
| `pos_step_max_m` | m | largest unclamped residual increment \|Δp − v·dt\| of a gated or transition fix in the window (the step the reported velocity does not account for, not the raw displacement); 0 when there is none | physics (**not** ML) |
| `ekf_vel_var` / `ekf_pos_var` / `ekf_compass_var` | ratio | `EKF_STATUS_REPORT` velocity_variance / pos_horiz_variance / compass_variance (ArduPilot normalised innovation ratios; ≥ 1.0 = inputs rejected, ≥ 0.5 warning); `None` if never received or older than 2 s | physics (**not** ML) |
| `gps_sat_jump` | count | \|Δ `GPS_RAW_INT.satellites_visible`\| between consecutive reports, held 1 s; 0 unless EKF_STATUS_REPORT / GPS_STATUS was received | physics (**not** ML) |
| `gps_snr_spread_db` / `gps_snr_sats` | dB / count | std and count of the non-zero `GPS_STATUS.satellite_snr`; `None`/0 without GPS_STATUS, older than 2 s, or < 8 satellites | physics (**not** ML) |
| `gps_vel_disagree_ms` | m/s | \|`GPS_RAW_INT.vel` − hypot(`GLOBAL_POSITION_INT` vx, vy)\|; `None` unless EKF_STATUS_REPORT / GPS_STATUS was received and both are fresh | physics (**not** ML) |
| `pos_vel_shortfall_gated_m` | m | over the gated fixes in the window, the velocity-implied movement the position does not show: \|V\| − (P projected on V, clamped to [0, \|V\|]), with V = Σ v·dt and P = Σ raw measured displacement of those fixes; 0 ≤ value ≤ \|V\|; movement perpendicular to V is not measured; 0 when no gated fix is in the window | physics (**not** ML) |

**Contract extension (2026-10-25; authorisation recorded in `docs/HANDOFF.md`, "Do NOT change casually").** `EKF_STATUS_REPORT` (ardupilotmega id 193)
is a new message read by the extractor. This is an additive extension of the "MAVLink field
mappings" frozen contract:
* Only `flags` is read, with bit values taken from the installed pymavlink dialect.
* The Stage-1 codec does not encode the message, so SIM streams are unchanged.
* `ML_FEATURES` and the computation of every existing feature are unchanged, so no retraining was
  needed.
* Hand-built frames get `None` / `False` / `0.0` defaults. Migration note: `docs/HANDOFF.md`.
* Rules that read these fields: `docs/DETECTION.md`, "Estimator-aware position residual".

\* `battery_v_rate` is intentionally excluded from `ML_FEATURES`: it is ~0 in
steady flight (near-zero variance), so throttle transitions read as extreme
outliers and caused benign false positives. The physics detector's
transition-robust 0.4 V threshold covers battery attacks instead.

### Command
| Feature | Unit | Meaning | Used by |
|---|---|---|---|
| `cmd_rate_hz` | cmd/s | COMMAND_LONG rate in `cmd_window_s` (2 s) | protocol, ML |
| `commands_recent` | list | recent `CommandEvent`s (source, id, params) | protocol |

## The ML feature vector (`ML_FEATURES`, 11 dims)

`msg_rate_hz, interarrival_jitter_ms, max_seq_gap, pos_residual_m,
gps_vfr_speed_diff_ms, gps_baro_alt_diff_m, alt_rate_ms, accel_ms2,
yaw_course_diff_deg, cmd_rate_hz, loss_ratio`

`FeatureFrame.to_vector()` returns them in this exact order. **The saved model
depends on this order and content** — changing `ML_FEATURES` requires retraining
(`aegis train`).

## Windows, warmup, state

- **Position residual:** `_RESID_WINDOW` = 15 position fixes (~3 s), per-fix
  increment magnitude-clamped to 30 m so a single position snap-back cannot
  dominate. Bounded window ⇒ recovers ~3 s after an attack stops (no long
  detector tail) while still accumulating sub-noise gradual drift.
- **Rate window:** 1 s sliding (`_recv_times` deque). **Command window:** 2 s.
- **Per-decision reset:** `clear_window_counts()` resets per-window source
  counts and sequence-gap maxima (the pipeline calls it after each `extract`).
  Persistent state (`_seq_state`, residual increments, histories) is *not*
  reset.
- **Warmup:** benchmark/training exclude the first `warmup_s` (5 s); the ML
  detector also has a `warmup_ticks` (20) grace before it scores.
- **Missing values:** `TelemetrySnapshot` fields start `None`; features guard
  against `None` (treated as 0 / skipped) until the first message of each type.

## False-positive conditions (known)
- Sharp turns momentarily raise `yaw_course_diff` and `accel` (damped by physics
  hysteresis; small ML z-scores because turns are common in benign training).
- Throttle transitions perturb `battery_v_rate` (excluded from ML for exactly
  this reason).
- A GPS spoof leaves a ~3 s elevated `pos_residual` after it stops (the position
  snap-back is genuinely anomalous); handled by the benchmark's grace window and
  documented in `docs/BENCHMARKING.md`.
