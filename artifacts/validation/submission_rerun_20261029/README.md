# submission_rerun_20261029: regenerated evidence behind figures that previously existed only in prose

**Environment: `SIM`** (generated sessions; attacks and detectors written by the same team). Claim class: none beyond "design evidence". Nothing
here involves a vehicle, a serial port, SITL or a network. Generated 2026-10-29 on Windows 11, CPython 3.13.15, numpy 2.5.3, pandas 3.0.6,
scikit-learn 1.9.1, `models/isoforest.joblib` sha256 `3fe74cddf3689e169610ffd7…` (first 24 hex characters; the full hash is in
`gps_drift_sweep_ml_on/sweep_meta.json`), `configs/detector.yaml` sha256 `be787674…1f8be`. Tree: commit `d0d134b` plus the working-tree changes of the
branch `sprint/hardware-free-20261029`; `src/aegisflight/` detector, feature and fusion code is unchanged from `d0d134b`.

Historical artifacts (`artifacts/benchmarks/`, `artifacts/benchmarks_extended/`) are **not overwritten**. Differences from them are reported as differences.

## 1. Baseline benchmark re-run (Stage-1 grid)
```
aegis benchmark --out <scratch> --no-figures          # ML on, default seeds; ~10 min on this machine
python scripts/compare_benchmark_runs.py artifacts/benchmarks/results.csv <scratch>/results.csv --json baseline_vs_committed.json
```
Result (`baseline_vs_committed.json`, `baseline_rerun_summary.md`): TP / FP / TN / FN **6535 / 4 / 16826 / 65** (accuracy 0.9971, recall 0.9902, FPR 0.0002),
identical to `artifacts/benchmarks/summary.md`; **378 of 378** non-timing cells of `results.csv` equal. Timing columns (`throughput_msgs_per_s`,
`mean_compute_latency_ms`) are machine-dependent and excluded; `baseline_rerun_results.csv` is the re-run table.

## 2. Extended benchmark v2 re-run (`extended_rerun/`)
```
python scripts/benchmark_extended.py --out <scratch> --workers 4          # ML on; 353 s wall
```
- The 5 s-grace rows are identical to the committed artifact (51,073 decisions, 9088 / 39 / 40813 / 1133, accuracy 0.9771, recall 0.8891, FPR 0.0010).
- **No-grace rows differ**: re-run 9088 / **463** / 42216 / 1133 (FPR 0.0108), committed (2026-09-24, pre-Stage-2 code) 9088 / **470** / 42209 / 1133 (FPR 0.0110).
  The committed artifact is kept; both numbers are cited and labelled in the report. The only per-mode change is `dos:blackout`'s post-attack tail.
- `sessions.csv`: the first twelve columns (everything up to `detected`) are identical between the re-run and the committed file (`diff` of `cut -d, -f1-12`: no output).
- `summary.md`, `results.json`, `sessions.csv` copied unmodified; `decisions.csv.gz` (208 KB) was not copied (regenerate with the command above).

## 3. Session-level uncertainty and time to first alert (`extended_rerun/stats/`, `extended_committed_stats/`)
```
python scripts/make_submission_stats.py --sessions extended_rerun/sessions.csv --out extended_rerun/stats
```
Wilson 95 % intervals on **sessions** (not decisions: decisions within a session are correlated). With n = 4 sessions per mode and 12–16 per class the intervals are wide
(e.g. 16/16 sessions detected → [0.81, 1.00]; `gcs_replay` 0/4 → [0.00, 0.49]). Time to first alert is reported as min / median / max; a 95th percentile is
**not** printed because no class has 20 detected sessions. Benign sessions with at least one false-positive decision (5 s-grace scoring): 4 of 12 (Wilson [0.14, 0.61]);
both link-stress conditions 6 of 6.

## 4. Detection versus GPS drift magnitude (`gps_drift_sweep_ml_off/`, `gps_drift_sweep_ml_on/`)
```
python scripts/sweep_gps_drift.py --out gps_drift_sweep_ml_off --seeds 10
python scripts/sweep_gps_drift.py --out gps_drift_sweep_ml_on  --seeds 10 --model models/isoforest.joblib
```
`SIM`, `gradual_drift`, 30 s window, 9 rates × 10 seeds (seeds 50,000–50,009, different routes/speeds), Stage-1 `configs/`, 10 benign sessions on the same seeds.
- **ML off (rules + physics, what the live non-SIM sources run):** 0/10 detected at 0.5, 1, 2 and 3 m/s; 10/10 at 4, 5, 6, 8 and 12 m/s; 0/10 benign sessions with a false positive.
- **ML on:** 0/10 at 0.5 and 1 m/s; 10/10 from 2 m/s up; **1/10 benign sessions had a false-positive decision** (seed 50005).
These are characterisations after the floor was already pinned by unit tests: **not** independent validation. The simulator reports the true velocity, so the drift is
velocity-inconsistent (the easy case); slow velocity-consistent drift is not swept (the unit tests pin it as undetected).
The ML detector's contribution does not carry over to the live serial/UDP/replay sources, where the ML detector is off by default.

## 5. Not regenerated here
SITL batches (PX4, ArduPilot: need WSL, PX4 and ArduPilot), ALFA and PX4 Flight Review replays (need the fetched raw logs), the hardware capture, the `P4` signing run, and the
historical 8-suite timing. Their numbers remain as committed and are cited only with their original artifact paths.

## 6. Test-suite run
See `test_suite_run.json` in this directory (command, counts, durations; produced from the pytest JUnit output of this sprint).
