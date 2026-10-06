# P1 summary - benign PX4 SITL (generated; do not edit)

Environment: **SITL**. Attack: **NONE**. Claim class: none (reference / false-alarm measurement).
Regenerate: `.venv/Scripts/python.exe scripts/sitl/make_p1_summary.py`.

PX4: `v1.18.0-rc1-27-gc239c63807` (release candidate, not a stable tag) | Gazebo `8.15.0` | model `gz_x500 (headless)` | vehicle sysid/compid `3/1`

## Captures (artifacts/sitl/benign_00N_stream_stats.json, data/sitl/raw/benign_00N.json)

| flight | frames | dur s | frames/s | SITL clock vs wall (ppm) | mean RTF (=1+ppm/1e6) | fwd seq gaps | reordered | net missing | duplicates | signed |
|---|---|---|---|---|---|---|---|---|---|---|
| benign_001 | 35067 | 103.68 | 338.2 | -99989.5 | 0.900 | 6 | 2 | 0 | 0 | 0 |
| benign_002 | 34957 | 107.27 | 325.9 | -132950.4 | 0.867 | 0 | 0 | 0 | 0 | 0 |
| benign_003 | 44669 | 132.14 | 338.0 | -100505.7 | 0.899 | 0 | 0 | 0 | 0 | 0 |
| benign_004 | 30240 | 89.61 | 337.5 | -101896.1 | 0.898 | 0 | 0 | 0 | 0 | 0 |
| benign_005 | 40001 | 118.5 | 337.6 | -101544.2 | 0.898 | 0 | 0 | 0 | 0 | 0 |

## Stage-1 default detectors on benign SITL (artifacts/sitl/benign_replay_stage1_default*.json)

| adapter | flight | decisions | false-alarm decisions | classes | protocol trig | physics trig | ML trig |
|---|---|---|---|---|---|---|---|
| tlog (Stage-1 adapter) | benign_001.tlog | 519 | 519 | {'DOS': 504, 'MAVLINK_ANOMALY': 15} | 1.000 | 0.050 | 0.963 |
| tlog (Stage-1 adapter) | benign_002.tlog | 537 | 537 | {'DOS': 514, 'MAVLINK_ANOMALY': 23} | 1.000 | 0.050 | 0.965 |
| tlog (Stage-1 adapter) | benign_003.tlog | 662 | 662 | {'DOS': 644, 'MAVLINK_ANOMALY': 18} | 1.000 | 0.042 | 0.971 |
| tlog (Stage-1 adapter) | benign_004.tlog | 449 | 449 | {'DOS': 435, 'MAVLINK_ANOMALY': 14} | 1.000 | 0.060 | 0.958 |
| tlog (Stage-1 adapter) | benign_005.tlog | 593 | 593 | {'DOS': 579, 'MAVLINK_ANOMALY': 14} | 1.000 | 0.046 | 0.968 |
| tlog (Stage-1 adapter) | POOLED | 2760 | 2760 | {'DOS': 2676, 'MAVLINK_ANOMALY': 84} | 1.000 | 0.049 | 0.966 |
| live parser (header-first) | benign_001.tlog | 519 | 519 | {'DOS': 504, 'MAVLINK_ANOMALY': 15} | 1.000 | 0.050 | 0.963 |
| live parser (header-first) | benign_002.tlog | 537 | 537 | {'DOS': 514, 'MAVLINK_ANOMALY': 23} | 1.000 | 0.050 | 0.965 |
| live parser (header-first) | benign_003.tlog | 662 | 662 | {'DOS': 644, 'MAVLINK_ANOMALY': 18} | 1.000 | 0.042 | 0.971 |
| live parser (header-first) | benign_004.tlog | 449 | 449 | {'DOS': 435, 'MAVLINK_ANOMALY': 14} | 1.000 | 0.060 | 0.958 |
| live parser (header-first) | benign_005.tlog | 593 | 593 | {'DOS': 579, 'MAVLINK_ANOMALY': 14} | 1.000 | 0.046 | 0.968 |
| live parser (header-first) | POOLED | 2760 | 2760 | {'DOS': 2676, 'MAVLINK_ANOMALY': 84} | 1.000 | 0.049 | 0.966 |

## Feature shift (pooled, live parser; Stage-1 simulator values must be taken from `aegis benchmark` artifacts)

| feature | p50 | p95 | max |
|---|---|---|---|
| msg_rate_hz | 338.000 | 344.000 | 369.000 |
| interarrival_jitter_ms | 3.710 | 4.909 | 36.017 |
| max_seq_gap | 0.000 | 0.000 | 253.000 |
| pos_residual_m | 0.015 | 0.207 | 2.430 |
| gps_vfr_speed_diff_ms | 0.008 | 0.290 | 0.709 |
| gps_baro_alt_diff_m | 0.003 | 0.274 | 0.700 |
| yaw_course_diff_deg | 0.000 | 23.086 | 85.233 |
| loss_ratio | 0.000 | 0.000 | 1.000 |

## Live UDP run vs offline replay of the same bytes (artifacts/sitl/live_run_002.*, *_equivalence.json)

- live: decisions=700 threat_decisions=700 classes={'DOS': 680, 'MAVLINK_ANOMALY': 15, 'GPS_SPOOFING': 5}
- source stats: {'datagrams_received': 47308, 'frames_received': 47308, 'bad_frames': 0, 'ticks_emitted': 1400, 'late_ticks': 77, 'late_frames': 0, 'dropped_overflow': 0}
- per-decision comparison: compared=700 flag_mismatches=0 score_mismatches(>0.001)=0 max_abs_score_diff=0.0005; offline-only t=[140.0] live-only t=[]
- caveat: shared assembler+parser: not an independent decode check; all-alarm regime makes flag agreement weak
- the IDS is an ACTIVE link partner (sends the GCS heartbeat PX4 needs); the benign flight driver used a distinct sysid (254/191)
- decision latency (live, Windows, ML on): {'mean': 70.81977014284348, 'p95': 174.50140000437386}
- provenance: commit `5c009484abc5a9bd2b667a4e826955b7539175c9` dirty=True model_sha256=`3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4` tlog_sha256=`feebea904d871b100edf441f7cde248d007de28818d7904d8cf21ea83601edff`
