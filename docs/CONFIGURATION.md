# AegisFlight — Configuration

All tunables live in `configs/*.yaml` and are deep-merged over built-in defaults
by `config.py` (`load_config()`), so the package works even with no YAML present.
Flow: `configs/*.yaml` → `AegisConfig` (`simulation`, `message_rates`,
`detector`, `attacks`) → consumed by simulator / encoder / detectors / fusion.

## `configs/simulation.yaml`
| Key | Default | Unit | Effect | Safe range |
|---|---|---|---|---|
| `seed` | 42 | — | determinism | any int |
| `sample_rate_hz` | 10 | Hz | simulator tick rate | 5–50 |
| `duration_s` | 120 | s | session length | 30–600 |
| `home.{lat,lon,alt_msl}` | IIT-B | deg/m | takeoff point | any valid |
| `cruise_alt_m` | 60 | m | target altitude | 20–120 |
| `cruise_speed_ms` | 12 | m/s | nominal speed | 5–20 |
| `route` | survey_box | — | survey_box\|out_and_back\|perimeter | — |
| `noise.*` | see file | m,m/s,rad | sensor noise σ | keep small |
| `message_rates.*` | see file | ticks | per-message decimation | ≥1 |

**Danger:** changing `noise.*`, `cruise_*`, or `sample_rate_hz` shifts the
feature distribution → **retrain the ML model** (`aegis train`) and re-benchmark.

## `configs/detector.yaml`
- `decision_rate_hz` (5) — fusion cadence. Compute budget per decision =
  1000/rate ms (200 ms at 5 Hz); we run ≪ that.
- `protocol.*` — expected sysids/compids, `max_msg_rate_hz` (400),
  `nominal_msg_rate_hz` (28), `msg_rate_spike_factor` (3), `max_seq_gap` (30),
  `heartbeat_timeout_s` (3), `gps_dropout_s` (2), sensitive commands, burst
  limits, `require_signing`, `startup_grace_s` (0; optional - ignore the
  "no heartbeat/GPS seen yet" sentinel for the first N seconds).
- `physics.*` — `gps_pos_residual_m` (12) + hard (30), `gps_speed_consistency_ms`
  (5), `alt_consistency_m` (8), `alt_jump_ms` (25), `max_accel_ms2` (20),
  `battery_rise_v` (0.4), `battery_drop_rate_v_s` (2), `hysteresis_ticks` (2),
  `yaw_course_deg` (25; optional key - previously a hard-coded constant).
- `anomaly.*` — `model_path`, `score_threshold` (0.62), `contamination` (0.02),
  `n_estimators` (200), `warmup_ticks` (20).
- `fusion.*` — `weights` (protocol 0.30 / physics 0.34 / ml 0.16 / firmware
  0.20), `threat_threshold` (0.45), `severity_bands`, `alert_threshold_severity`
  (SUSPICIOUS), `cooldown_s` (4), `clear_ticks` (4).

**Danger — detector thresholds are the accuracy/FPR trade-off.** Lowering
`gps_pos_residual_m`, `alt_consistency_m`, etc. raises recall but risks false
positives; raising `msg_rate_spike_factor` or `max_seq_gap` reduces DoS
sensitivity. Fusion `weights` are max-normalised (relative trust); `n_estimators`
must match the trained model's metadata.

## `configs/px4_sitl/detector.yaml` (per-vehicle profile, overrides only)
A **separate, generated** profile for PX4 SITL (`load_config("configs/px4_sitl")`); Stage-1
`configs/detector.yaml` is the reference condition and is never edited for it. Every override
is derived from the benign calibration flights and commented with its evidence; see
`docs/CALIBRATION_PX4.md`. It reduces benign false alarms on that stack only - it is not
attack detection and not valid for the simulator or other vehicles.

## `configs/attacks.yaml`
Per-scenario `mode`, `start_s`, `duration_s`, and mode-specific magnitudes (e.g.
GPS `drift_rate_ms`, telemetry `altitude_bias_m`, DoS `flood_multiplier`,
firmware `tamper_component`). These drive the benchmark's ground-truth windows
and the simulated attack strength; they do **not** affect the live dashboard's
runtime-injected attacks (those activate from "now").

## Notes
- Config is **not** hot-reloaded: restart the process / re-run after edits.
- Built-in defaults in `config.py` mirror the YAML exactly, so deleting a YAML
  file falls back to the documented default rather than breaking.
