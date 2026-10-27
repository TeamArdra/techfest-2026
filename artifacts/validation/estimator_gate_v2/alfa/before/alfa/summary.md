# E2 — ALFA real MAVLink telemetry through the full IDS (generated)

_E2 ALFA real MAVLink telemetry -> full AegisFlight pipeline (production config, ML on)._

_Manifest: `data/external/manifests/alfa.json` · 35 ground-station `.tlog` files · 137926 decisions (7.66 h) after dropping 56702 decisions from overlapping recordings of the same flight · 47 author-labelled sequences {"no_failure": 10, "fault": 36, "no_ground_truth": 1}._

Ground truth comes from the dataset authors' processed sequences: `benign_gt` = no-failure sequences + pre-onset part of fault sequences; `fault` = after the `failure_status` onset (physical faults, **not** cyber attacks); `unlabelled` = rest of the log (manual flight, taxi, ground).

## Decision-level alarm rates (fused IDS; configuration as in the title — nothing retrained)

| Category | Decisions | Fused threat rate | Protocol ≥0.5 | Physics ≥0.5 | ML ≥0.62 |
|---|---|---|---|---|---|
| benign_gt (all) | 17989 | 100.00 % | 100.00 % | 0.09 % | 100.00 % |
| fault (all) | 3711 | 100.00 % | 100.00 % | 0.57 % | 100.00 % |
| unlabelled (all) | 116226 | 99.93 % | 99.92 % | 0.77 % | 99.54 % |
| benign_gt (airborne) | 14926 | 100.00 % | 100.00 % | 0.11 % | 100.00 % |
| fault (airborne) | 2836 | 100.00 % | 100.00 % | 0.74 % | 100.00 % |
| unlabelled (airborne) | 27191 | 100.00 % | 100.00 % | 1.13 % | 100.00 % |

## What fired on author-labelled benign periods

```
{
 "predicted_classes": {
  "DOS": 17989
 },
 "top_evidence": {
  "message-rate spike": 17989,
  "ML anomaly score 1.00": 17989,
  "implausible acceleration 25.6 m/s\u00b2": 3,
  "heading/course mismatch 27\u00b0": 2,
  "implausible acceleration 26.7 m/s\u00b2": 2,
  "implausible acceleration 24.3 m/s\u00b2": 2,
  "implausible acceleration 29.1 m/s\u00b2": 2,
  "implausible acceleration 21.5 m/s\u00b2": 1
 }
}
```

## Real link statistics (airborne, author-labelled benign) vs simulator assumptions

Simulator reference: nominal 28 msg/s configured (`protocol.nominal_msg_rate_hz`); see the ML scaler means in `models/isoforest.joblib` for the simulated benign rate/jitter.

```
{
 "msg_rate_hz": {
  "n": 14926,
  "p50": 200.0,
  "p95": 213.0,
  "p99": 219.0,
  "max": 234.0,
  "mean": 199.73006833712984
 },
 "interarrival_jitter_ms": {
  "n": 14926,
  "p50": 7.914465028740505,
  "p95": 9.109203561847655,
  "p99": 9.802917001006787,
  "max": 11.656696721754404,
  "mean": 7.959603187094187
 },
 "max_seq_gap": {
  "n": 14926,
  "p50": 0.0,
  "p95": 0.0,
  "p99": 1.0,
  "max": 26.0,
  "mean": 0.06324534369556478
 },
 "loss_ratio": {
  "n": 14926,
  "p50": 0.0,
  "p95": 0.0,
  "p99": 0.02,
  "max": 0.52,
  "mean": 0.0012649068739112959
 },
 "n_sources": {
  "n": 14926,
  "p50": 1.0,
  "p95": 2.0,
  "p99": 3.0,
  "max": 3.0,
  "mean": 1.4104917593461075
 }
}
```
Source ids seen (sysid/compid: decisions present): `{"1/1": 137877, "255/190": 27993, "255/0": 27523, "0/0": 6}`

## Fault events (physical faults — not attacks)

| Sequence | Pre-onset threat rate | Post-onset threat rate | First threat after onset (s) | First physics after onset (s) |
|---|---|---|---|---|
| carbonZ_2018-07-18-15-53-31_1_engine_failure | 100.00 % | 100.00 % | 0.10 | — |
| carbonZ_2018-07-18-15-53-31_2_engine_failure | 100.00 % | 100.00 % | 0.10 | 10.70 |
| carbonZ_2018-07-18-16-22-01_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.00 | — |
| carbonZ_2018-07-18-16-37-39_2_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.19 | — |
| carbonZ_2018-07-30-16-29-45_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.14 | — |
| carbonZ_2018-07-30-16-39-00_1_engine_failure | 100.00 % | 100.00 % | 0.17 | — |
| carbonZ_2018-07-30-16-39-00_2_engine_failure | 100.00 % | 100.00 % | 0.18 | — |
| carbonZ_2018-07-30-17-10-45_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.17 | — |
| carbonZ_2018-07-30-17-20-01_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.13 | — |
| carbonZ_2018-07-30-17-36-35_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.12 | — |
| carbonZ_2018-07-30-17-46-31_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.00 | — |
| carbonZ_2018-09-11-11-56-30_engine_failure | 100.00 % | 100.00 % | 0.06 | — |
| carbonZ_2018-09-11-14-22-07_1_engine_failure | 100.00 % | 100.00 % | 0.09 | — |
| carbonZ_2018-09-11-14-22-07_2_engine_failure | 100.00 % | 100.00 % | 0.09 | — |
| carbonZ_2018-09-11-14-41-51_elevator_failure | 100.00 % | 100.00 % | 0.02 | — |
| carbonZ_2018-09-11-14-52-54_left_aileron__right_aileron__failure | 100.00 % | 100.00 % | 0.03 | — |
| carbonZ_2018-09-11-15-05-11_1_elevator_failure | 100.00 % | 100.00 % | 0.16 | — |
| carbonZ_2018-09-11-15-06-34_1_rudder_right_failure | 100.00 % | 100.00 % | 0.17 | — |
| carbonZ_2018-09-11-15-06-34_2_rudder_right_failure | 100.00 % | 100.00 % | 0.08 | — |
| carbonZ_2018-09-11-15-06-34_3_rudder_left_failure | 100.00 % | 100.00 % | 0.08 | — |
| carbonZ_2018-09-11-17-27-13_1_rudder_zero__left_aileron_failure | 100.00 % | 100.00 % | 0.18 | — |
| carbonZ_2018-09-11-17-27-13_2_both_ailerons_failure | 100.00 % | 100.00 % | 0.08 | — |
| carbonZ_2018-09-11-17-55-30_1_right_aileron_failure | 100.00 % | 100.00 % | 0.15 | — |
| carbonZ_2018-09-11-17-55-30_2_left_aileron_failure | 100.00 % | 100.00 % | 0.15 | — |
| carbonZ_2018-10-05-14-34-20_2_right_aileron_failure_with_emr_traj | 100.00 % | 100.00 % | 0.12 | — |
| carbonZ_2018-10-05-14-37-22_2_right_aileron_failure | 100.00 % | 100.00 % | 0.07 | — |
| carbonZ_2018-10-05-14-37-22_3_left_aileron_failure | 100.00 % | 100.00 % | 0.07 | — |
| carbonZ_2018-10-05-15-52-12_3_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.07 | — |
| carbonZ_2018-10-05-15-55-10_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.14 | 11.74 |
| carbonZ_2018-10-05-16-04-46_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.14 | — |
| carbonZ_2018-10-18-11-03-57_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.03 | — |
| carbonZ_2018-10-18-11-04-00_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.02 | — |
| carbonZ_2018-10-18-11-04-08_1_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.18 | 7.58 |
| carbonZ_2018-10-18-11-04-08_2_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.18 | — |
| carbonZ_2018-10-18-11-04-35_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.17 | — |
| carbonZ_2018-10-18-11-06-06_engine_failure_with_emr_traj | 100.00 % | 100.00 % | 0.12 | — |

Summary: `{"n_with_telemetry": 36, "detected_any_threat": 36, "detected_by_physics": 3, "mean_pre_onset_threat_rate": 1.0, "mean_post_onset_threat_rate": 1.0}`
