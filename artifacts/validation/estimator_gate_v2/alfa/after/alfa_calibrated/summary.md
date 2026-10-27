# E2 — ALFA real MAVLink telemetry through the full IDS (generated)

_E2b ALFA held-out dates: protocol rate thresholds calibrated per vehicle, ML off._

_Manifest: `data/external/manifests/alfa.json` · 21 ground-station `.tlog` files · 83577 decisions (4.64 h) after dropping 51057 decisions from overlapping recordings of the same flight · 47 author-labelled sequences {"no_failure": 10, "fault": 36, "no_ground_truth": 1}._

Ground truth comes from the dataset authors' processed sequences: `benign_gt` = no-failure sequences + pre-onset part of fault sequences; `fault` = after the `failure_status` onset (physical faults, **not** cyber attacks); `unlabelled` = rest of the log (manual flight, taxi, ground).

## Decision-level alarm rates (fused IDS; configuration as in the title — nothing retrained)

| Category | Decisions | Fused threat rate | Protocol ≥0.5 | Physics ≥0.5 | ML ≥0.62 |
|---|---|---|---|---|---|
| benign_gt (all) | 11545 | 0.16 % | 0.01 % | 0.15 % | 0.00 % |
| fault (all) | 2755 | 0.76 % | 0.04 % | 0.73 % | 0.00 % |
| unlabelled (all) | 69277 | 6.28 % | 5.95 % | 0.33 % | 0.00 % |
| benign_gt (airborne) | 8482 | 0.21 % | 0.01 % | 0.20 % | 0.00 % |
| fault (airborne) | 1899 | 1.05 % | 0.00 % | 1.05 % | 0.00 % |
| unlabelled (airborne) | 13092 | 1.34 % | 0.11 % | 1.23 % | 0.00 % |

## What fired on author-labelled benign periods

```
{
 "predicted_classes": {
  "GPS_SPOOFING": 17,
  "MAVLINK_ANOMALY": 1
 },
 "top_evidence": {
  "implausible acceleration 25.6 m/s\u00b2": 3,
  "implausible acceleration 26.7 m/s\u00b2": 2,
  "implausible acceleration 24.3 m/s\u00b2": 2,
  "implausible acceleration 29.1 m/s\u00b2": 2,
  "implausible acceleration 20.9 m/s\u00b2": 1,
  "heading/course mismatch 27\u00b0": 1,
  "implausible acceleration 27.3 m/s\u00b2": 1,
  "implausible acceleration 24.6 m/s\u00b2": 1
 }
}
```

## Real link statistics (airborne, author-labelled benign) vs simulator assumptions

Simulator reference: nominal 28 msg/s configured (`protocol.nominal_msg_rate_hz`); see the ML scaler means in `models/isoforest.joblib` for the simulated benign rate/jitter.

```
{
 "msg_rate_hz": {
  "n": 8482,
  "p50": 201.0,
  "p95": 213.0,
  "p99": 220.0,
  "max": 234.0,
  "mean": 200.19287903796274
 },
 "interarrival_jitter_ms": {
  "n": 8482,
  "p50": 7.939089698466942,
  "p95": 9.200837775438048,
  "p99": 9.92579150202714,
  "max": 11.656696721754404,
  "mean": 7.978443567554558
 },
 "max_seq_gap": {
  "n": 8482,
  "p50": 0.0,
  "p95": 0.0,
  "p99": 1.0,
  "max": 14.0,
  "mean": 0.0361942937986324
 },
 "loss_ratio": {
  "n": 8482,
  "p50": 0.0,
  "p95": 0.0,
  "p99": 0.02,
  "max": 0.28,
  "mean": 0.000723885875972648
 },
 "n_sources": {
  "n": 8482,
  "p50": 1.0,
  "p95": 2.0,
  "p99": 3.0,
  "max": 3.0,
  "mean": 1.4118132515916058
 }
}
```
Source ids seen (sysid/compid: decisions present): `{"1/1": 83552, "255/190": 17669, "255/0": 16712, "0/0": 5}`

## Fault events (physical faults — not attacks)

| Sequence | Pre-onset threat rate | Post-onset threat rate | First threat after onset (s) | First physics after onset (s) |
|---|---|---|---|---|
| carbonZ_2018-09-11-11-56-30_engine_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-14-22-07_1_engine_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-14-22-07_2_engine_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-14-41-51_elevator_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-14-52-54_left_aileron__right_aileron__failure | 0.00 % | 0.16 % | 94.63 | — |
| carbonZ_2018-09-11-15-05-11_1_elevator_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-15-06-34_1_rudder_right_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-15-06-34_2_rudder_right_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-15-06-34_3_rudder_left_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-17-27-13_1_rudder_zero__left_aileron_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-17-27-13_2_both_ailerons_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-17-55-30_1_right_aileron_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-09-11-17-55-30_2_left_aileron_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-10-05-14-34-20_2_right_aileron_failure_with_emr_traj | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-10-05-14-37-22_2_right_aileron_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-10-05-14-37-22_3_left_aileron_failure | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-10-05-15-52-12_3_engine_failure_with_emr_traj | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-10-05-15-55-10_engine_failure_with_emr_traj | 0.00 % | 3.08 % | 11.74 | 11.74 |
| carbonZ_2018-10-05-16-04-46_engine_failure_with_emr_traj | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-10-18-11-03-57_engine_failure_with_emr_traj | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-10-18-11-04-00_engine_failure_with_emr_traj | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-10-18-11-04-08_1_engine_failure_with_emr_traj | 0.00 % | 25.71 % | 7.58 | 7.58 |
| carbonZ_2018-10-18-11-04-08_2_engine_failure_with_emr_traj | 0.00 % | 0.00 % | — | — |
| carbonZ_2018-10-18-11-04-35_engine_failure_with_emr_traj | 2.17 % | 0.00 % | — | — |
| carbonZ_2018-10-18-11-06-06_engine_failure_with_emr_traj | 0.00 % | 0.00 % | — | — |

Summary: `{"n_with_telemetry": 25, "detected_any_threat": 3, "detected_by_physics": 2, "mean_pre_onset_threat_rate": 0.0008695652173913043, "mean_post_onset_threat_rate": 0.01157888601258336}`

## Calibration (E2b)

```
{
 "dates": [
  "2018-07-18",
  "2018-07-30"
 ],
 "n_calibration_decisions": 22678,
 "rule": "nominal_msg_rate_hz := median airborne non-fault msg rate on calibration dates; max_msg_rate_hz scaled by the same ratio as the default config",
 "protocol_overrides": {
  "nominal_msg_rate_hz": 186.0,
  "max_msg_rate_hz": 2657.1428571428573
 }
}
```
Test dates: ['2018-09-11', '2018-10-05', '2018-10-18']
