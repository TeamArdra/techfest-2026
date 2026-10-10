# ArduPilot SITL benign baseline (generated; do not edit)

Environment: **SITL** (ArduCopter 4.7.1, isolated netns, pipe transport, wall-clock 1x) for the live runs; the ML-off columns are a **REPLAY** of the same recorded bytes. Claim class: **none** -- benign false-alarm / coverage / cost reference. Not detection evidence; says nothing about real vehicles.
Regenerate: `.venv/Scripts/python.exe scripts/ardupilot/make_ap_baseline_summary.py` (inputs: `artifacts/ardupilot/ap_benign_*`, `data/ardupilot/raw/*.clean.tlog`).

In-flight = takeoff, square, rtl, landed. Ground = boot, await_gps, arm (start-up before GPS lock / arming).

| run | stream | decisions | Stage-1+ML alerts (ground / in-flight) | ML-off alerts (ground / in-flight) |
|---|---|---|---|---|
| ap_benign_groups_001 | groups | 702 | 15/231 / 23/471 | 5/231 / 0/469 |
| ap_benign_six_001 | six | 697 | 15/232 / 26/465 | 5/232 / 0/463 |
| ap_benign_six_002 | six | 702 | 15/236 / 26/466 | 5/236 / 0/464 |
| ap_benign_six_003 | six | 702 | 15/234 / 26/468 | 5/234 / 0/466 |
| ap_benign_six_004 | six | 702 | 15/233 / 25/469 | 5/233 / 0/467 |

Totals over 5 flights: Stage-1+ML in-flight alerts 126/2339; ML-off in-flight alerts 0/2329; ML-off ground alerts 25/1166.

| run | agg Hz | B/s | lat p50/p95/p99/max ms | emit p50/p99 ms | CPU mean/max % of 1 core | RSS MB |
|---|---|---|---|---|---|---|
| ap_benign_groups_001 | 61.26 | 2533.8 | 10.457/12.74/18.168/24.633 | 5.6032/6.4401 | 5.54/9.3 | 165.6 |
| ap_benign_six_001 | 26.37 | 1045.0 | 10.287/12.23/17.94/29.584 | 5.524/6.1206 | 7.21/10.8 | 165.2 |
| ap_benign_six_002 | 26.19 | 1037.7 | 10.383/14.431/22.098/54.412 | 5.538/6.5931 | 7.49/12.3 | 164.8 |
| ap_benign_six_003 | 26.19 | 1037.8 | 10.361/14.392/22.167/62.733 | 5.538/8.3519 | 7.46/13.8 | 165.6 |
| ap_benign_six_004 | 26.19 | 1037.8 | 10.348/12.135/16.744/20.744 | 5.5395/6.0229 | 5.47/9.3 | 165.6 |

Resource figures are the Windows IDS process only, with the Stage-1 ML model loaded (the WSL simulator is excluded); latency is the pipeline's own per-decision compute time; `emit` is tick-close to tick-emit.
