# estimator_gate_v2: regression evidence for the GPS estimator gate v2 (2026-10-26)

This bundle is the regression evidence for GPS iteration 2: the estimator-aware position residual, with
`physics.estimator_gate: true` (`docs/DETECTION.md`, "Estimator-aware position residual"). The code is uncommitted,
on top of `HEAD` `90b9aa2`. Each part below states where it ran:

| Part | Environment | Claim class | Result |
|---|---|---|---|
| Stage-1 benchmark | `SIM` | regression identity | **identical**: TP/FP/TN/FN 6535 / 4 / 16826 / 65; 378 / 378 non-timing CSV cells equal |
| ALFA before / after | `REPLAY` (real ArduPilot fixed-wing flights, public dataset) | none (false-alarm behaviour; the dataset has physical faults, no attacks) | changes **only** in the `unlabelled` category; `benign_gt` and `fault` identical in both configurations |
| Replay identity, 44 recordings | `REPLAY` (ArduPilot SITL ×32, PX4 SITL ×10, `BENCH` 005/007) | regression identity | **44 / 44 byte-identical**, but **none of the 44 contains `EKF_STATUS_REPORT`** (see §3) |

Nothing here is attack-detection evidence, a real-world rate, or a `SITL` result with estimator status. The gate's
adversarial behaviour (forged or injected `EKF_STATUS_REPORT`) is SIM-only evidence:
`tests/unit/test_gps_scenarios_fused.py` (79 tests).

## Provenance
- **Tree:** `HEAD` `90b9aa247fdcda2f95d0096c1e0f486b9d030aed` plus the uncommitted iteration-2 tree.
  - sha256 of `git diff HEAD -- src configs` (Git Bash) = `b4d434e3dffed2ab646bb4d9aed963e0a4fb44e636353901b963a59d15967eaf`.
  - aegis-validation re-verified it on 2026-10-26 at 13:17Z, before any run below. `replay_identity.py` recorded the same
    value at its start and its end (`replay_identity/identity.json`).
  - The last `src/`/`configs/` edit (file time 12:23:04Z) is before every run in this bundle.
- **Before tree:** a clean, detached worktree of `90b9aa2` (`<wt_head>`, 0 modified files), selected with
  `PYTHONPATH=<wt_head>/src`. `aegisflight.config.CONFIG_DIR` resolves next to the imported package, so "before" runs
  use `<wt_head>/configs` (HEAD's configs). This was checked by import probe in `replay_identity/identity.json`.
  `scripts/` is unchanged from `HEAD` in the working tree.
- **Config:** `configs/detector.yaml` sha256 `be7876745a26e1a9de23acb1e079cab18165887df3ad8cd9800f67dae4e1f8be` after,
  `88ec9ffbced4c898f226c91b421ae05b39d72049575ec5cc808fc9ceec0aaac3` before (`HEAD`). The only difference is
  `physics.estimator_gate: true` and its comment block.
- **Model** (ML-on runs only): `models/isoforest.joblib` sha256 `3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4`,
  the same file in both trees. `ML_FEATURES` is unchanged, and nothing was retrained.
- **Environment:** Python 3.13.15, scikit-learn 1.9.1, numpy 2.5.3, scipy 1.18.1, pandas 3.0.6, pymavlink 2.4.50,
  pyserial 3.5; Windows 11 (10.0.26300).
- **Who ran what:**
  - The lead ran the Stage-1 benchmark, both ALFA runs and the ALFA GPS probe. Their outputs were copied here by
    `tools/import_scratch.py` (sha256 of every source and copy in `manifest.json`).
  - aegis-validation ran the replay identity check, the EKF-presence scan, the ALFA init-window listing, the
    comparator re-runs and the 008/009 regeneration.
  - Heavy runs were sequential (the machine was short on memory).

## 1. Stage-1 regression (`SIM`)
- Command: `.venv/Scripts/aegis.exe benchmark --out <scratch>/bench_final --no-figures`. Lead, 2026-10-26 12:28:13Z–12:32:49Z,
  exit 0. `--no-figures` means the committed `artifacts/figures/` were not touched.
- Result: TP/FP/TN/FN **6535 / 4 / 16826 / 65** over 23,430 decisions, identical to `artifacts/benchmarks/summary.md`.
- `stage1_regression/compare_vs_committed_baseline.txt`:
  - **378 of 378** non-timing `results.csv` cells are identical.
  - Of 145 non-timing `results.json` leaves, only `/config/python` differs (3.13.11 in the baseline, 3.13.15 now:
    interpreter metadata). The comparator exits 1 on any difference, including this one.
- `summary.md` differs from the committed one only in the compute-latency, throughput, CPU and RSS rows. These are
  machine-dependent and not a regression. The per-attack table is identical.
- The committed `artifacts/benchmarks/` was not modified.

## 2. ALFA before / after (`REPLAY` of real flights; claim class none)
- Commands (lead, 2026-10-26, each run alone, 8 workers, exit 0; the interpreter is the repository `.venv`, and
  `results.json` records `python` 3.13.15):
  - before: `PYTHONPATH=<wt_head>/src .venv/Scripts/python.exe scripts/external_validation.py --alfa --workers 8 --out <scratch>/alfa_head`.
    Its output files are dated 07:09Z; the start time was not recorded. The HEAD code is fixed, so its timing relative
    to the working-tree edits does not matter.
  - after: the same without `PYTHONPATH`, with `--out <scratch>/alfa_final` (12:33:06Z–12:42:48Z).
- Each run writes two configurations:
  - `alfa`: the production config, ML on;
  - `alfa_calibrated`: a 1-parameter rate calibration on held-out dates, ML off.
- Copies are in `alfa/before/` and `alfa/after/`. Comparator outputs: `alfa/compare_before_after_alfa.txt` and
  `alfa/compare_before_after_alfa_calibrated.txt`.
- In both configurations `benign_gt` (author-labelled no-failure and pre-onset periods) and `fault` (after a physical
  failure onset) are **identical**. Outputs change only in the `unlabelled` category (ground, taxi, manual flight); the gate may act elsewhere without changing outputs.

| `unlabelled` category | `alfa` before | `alfa` after | `alfa_calibrated` before | `alfa_calibrated` after |
|---|---|---|---|---|
| decisions | 116,226 | 116,226 | 69,277 | 69,277 |
| fused threat rate | 99.93 % | 99.93 % (unchanged) | 6.28 % | 6.28 % (unchanged) |
| physics ≥ 0.5 | 0.766 % | 0.338 % | 0.784 % | 0.333 % |
| predicted `GPS_SPOOFING` | 6 | **17** | 261 | 164 |
| predicted `DOS` | 116,133 | 116,122 | 4,012 | 4,109 |

Also differing:
- the top-evidence membership. New: "position discontinuity 8117062.4 m in one fix" and `navigation:`, plus lines
  that rose into the top list ("implausible acceleration 20.7 m/s²" in `alfa`; "GNSS fix lost", "heading/course
  mismatch 29°/37°" and "implausible acceleration 21.9 m/s²" in `alfa_calibrated`). Gone: "position residual
  12.x–13.x m" and, in `alfa_calibrated`, "28.9 m". Full lists: `alfa/compare_before_after_*.txt`;
- `alfa`'s `wall_time_s` (machine-dependent).

**Why ML-on `GPS_SPOOFING` goes from 6 to 17** (`alfa/gps_spoofing_decisions/`):
- `alfa_gps_head.json` and `alfa_gps_final.json` list every decision predicted `GPS_SPOOFING` (`alfa` config, ML on),
  **before** the script drops overlapping recordings: 8 before and 32 after. That is 24 extra; the deduplicated counts
  6 → 17 add 11.
- Every one of the 40 rows is `unlabelled`, on the ground (`airborne: false`) and a threat.
- All 40 are in two flights: 2018-07-18 `flight4` and 2018-10-05 `flight1`. HEAD's 8 are a subset of v2's 32.
- `init_window_head.txt` and `init_window_final.txt` list all 43 decisions around those windows in both trees
  (`tools/alfa_init_probe.py`):
  - the **threat flag is the same on all 43** (43 threats in both trees);
  - the **only** change is the label of **24 decisions, `DOS` → `GPS_SPOOFING`**.
- Evidence of those decisions:
  - HEAD: the clamped residual "position residual 27.0–31.5 m", physics 0.83–1.00. The fused label falls back to `DOS`
    (message-rate spike) once the residual is below the 30 m hard threshold.
  - v2: "position discontinuity 8116935.8 / 8117062.4 m in one fix ≥ hard 30 m (at or leaving an estimator state without
    a horizontal solution)", that is rule 3 on the raw step. It stays hard for the window, so `GPS_SPOOFING` wins the vote.
- First-to-last v2 `GPS_SPOOFING` span: 3.0 s (2018-07-18) and 3.6 s (2018-10-05). Each is interrupted by
  `TELEMETRY_MANIPULATION` decisions that are the same in both trees.
- The lead attributes the step to the receiver's GPS initialisation as the estimator acquires its first solution. That
  is consistent with its magnitude and with the ground phase. It was not verified further here.
- Conclusion (`REPLAY`, claim class none):
  - **in these windows no threat decision is added or lost**, and the label changes on a benign ground event. That event
    is not an attack, and this is not detection evidence;
  - overall, the `unlabelled` threat rate is unchanged to full precision, and `benign_gt` and `fault` are identical.
    Equal rates could in principle hide offsetting per-decision changes elsewhere; outside these two windows no
    per-decision listing was made.
- In `alfa_calibrated` (ML off), `GPS_SPOOFING` 261 → 164 is matched by `DOS` +97 with an unchanged threat rate. So 97
  decisions lose the `GPS_SPOOFING` label but stay threats. The lead reads them as gated ground decisions. No
  per-decision listing was made for this configuration.

**The committed `artifacts/external/alfa*` is stale relative to `HEAD`.** It was NOT overwritten.
- It dates from commit `5cb7dd9` (2026-09-24).
- Against the HEAD re-run (`alfa/compare_committed_vs_before_*.txt`), 36 of 682 leaves differ in `alfa` (including
  `/python` and `/wall_time_s`) and 23 of 515 in `alfa_calibrated` (including `/python`).
- The differing evidence keys ("GPS dropout 999.0s" / "GNSS fix lost" → "GNSS fix never acquired") fit the P1–P3
  coverage-policy commits that followed. This was not bisected.
- So numbers quoted from `artifacts/external/alfa*` (for example `artifacts/validation/validation_table.md`) describe that
  earlier code state, not `HEAD`. Regenerating them is a separate decision.

## 3. Replay identity, before vs after (`REPLAY`, ML off)
- Command (aegis-validation, 2026-10-26 13:17:45Z–13:18:56Z; 88 replay processes, strictly one at a time):
  `.venv/Scripts/python.exe artifacts/validation/estimator_gate_v2/tools/replay_identity.py --before-src <wt_head>/src --raw-dir <scratch>/val_v2/identity_raw --out artifacts/validation/estimator_gate_v2/replay_identity`.
  Each side runs `scripts/ardupilot/replay_ap_tlog.py <tlog> --no-ml --json …`.
- Inputs:
  - every `data/ardupilot/raw/*.tlog` (32: ArduPilot SITL clean/observed captures, including the attacked drift runs);
  - every `data/sitl/raw/benign_*.tlog` (10: PX4 SITL);
  - `data/hardware/raw/telemetry_radio_00{5,7}.tlog` (2: `BENCH`).
- **Result: 44 / 44 outputs byte-identical** (`replay_identity/identity.md`, `identity.json`: per-file input sha256,
  output sha256 and counts).
- The 005/007 "after" outputs are also byte-identical to the committed
  `artifacts/hardware/replay_p1p2_00{5,7}/replay_noml.json`. This holds for the working-copy bytes and for the committed
  blob modulo line endings.
- **Scope of this identity:**
  - `replay_identity/ekf_presence.json` (`tools/ekf_presence.py`): **none of the 44 inputs contains a single
    `EKF_STATUS_REPORT`**. So this check exercises only the "no estimator status → Stage-1 rule unchanged" path.
  - The only local inputs with estimator status are the bench captures 008/009 (all reports say no solution; 62.0 s and
    59.49 s spans). See `artifacts/hardware/replay_gnss_00{8,9}_estimator_gate/` (in-sample) and the ALFA flights (§2).
  - The per-file raw JSON outputs (about 1–2 KB each) were left in scratch (`<scratch>/val_v2/identity_raw/`), not
    committed. Their sha256 values are in `identity.json`.

## 4. Bench captures 008/009 (`REPLAY` of `BENCH`; claim class none; in-sample)
- `artifacts/hardware/replay_gnss_008_estimator_gate/`: `GPS_SPOOFING` **1 → 0**; 7 `DOS` + 1
  `TELEMETRY_MANIPULATION` remain; threats 146 → 138.
- `artifacts/hardware/replay_gnss_009_estimator_gate/`: 0 → 0. The output is byte-identical to HEAD's.
- Each has its own README with provenance. n = 1 alert removed, on the captures the gate was designed from.

## What this bundle does not show
- Attack detection of any kind, or any false-alarm *rate* on real vehicles.
- What happens to the 11 `GPS_SPOOFING` alerts of the 2026-10-25 dashboard session. That session saved no input bytes
  and no EKF flags, so the effect is **unknown**.
- Behaviour with ML on beyond ALFA. The gate covers the physics rule only; the ML detector still sees the ungated
  residual (SIM, `docs/DETECTION.md`).
- Anything under forged or injected `EKF_STATUS_REPORT`. That is SIM-only, and it includes disclosed capabilities the gate
  adds for an attacker (`docs/DETECTION.md` limitations; `docs/VALIDATION_EVIDENCE.md`). Only MAVLink-2 signing closes
  them.
- `SITL` or `HITL` with estimator status: not run.

## Files and regeneration
- `tools/import_scratch.py --scratch <scratch>` copies the lead's scratch outputs, re-runs the comparator and writes
  `manifest.json`.
  - Copies are byte-for-byte, except the `code` field of the two `alfa_gps_*.json`. That field was an absolute local
    path naming the user profile, and it is replaced by a placeholder. The script asserts that every other value is
    unchanged and records both hashes.
  - `manifest.json` also records a scan for coordinate keys: 0 hits. The ALFA files hold flight file names, unix times,
    rates and evidence text, and no coordinates.
- `tools/compare_results.py` is a verbatim copy of the lead's scratch script.
  - `tools/alfa_gps_probe.py` and `tools/alfa_init_probe.py` are copies with one change (lead, 2026-10-26): the
    hard-coded local repository path became `Path(__file__).resolve().parents[4]`, so no local path is committed.
    Their logic is unchanged; `manifest.json` lists them under `redacted_copies`.
  - Regenerate a GPS list with `[PYTHONPATH=<wt_head>/src] .venv/Scripts/python.exe tools/alfa_gps_probe.py <out.json> [workers]`
    (the lead ran it with 4 workers; the result does not depend on the count).
  - Regenerate an init window with `[PYTHONPATH=<wt_head>/src] .venv/Scripts/python.exe -W ignore tools/alfa_init_probe.py alfa/gps_spoofing_decisions/alfa_gps_final.json > alfa/gps_spoofing_decisions/init_window_{head,final}.txt`
    (run from the repository root with the bundle-relative paths prefixed).
- `tools/replay_identity.py` and `tools/ekf_presence.py`: see §3.
- Re-running `tools/import_scratch.py` rewrites `manifest.json`, including the README's hash.
