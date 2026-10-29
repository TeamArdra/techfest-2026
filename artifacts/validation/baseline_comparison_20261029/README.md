# Simple-threshold baseline vs AegisFlight (`SIM`)

**Environment `SIM`, claim class link-level detection; design evidence only** (simulator, attacks, AegisFlight and baseline are all team-written).

- Script: `scripts/baseline_comparison.py`; baseline definition: `configs/baseline_threshold.yaml`, committed (`9944a57`) **before** the first run; its sha256 is in `baseline_meta.json`.
- Regenerate: `python scripts/baseline_comparison.py --out artifacts/validation/baseline_comparison_20261029` (roughly 25 min; needs the trained model, `aegis train`).
- Inputs: the Stage-1 grid (7 scenarios × seeds 1..6 × 3 routes), identical ticks and the pipeline's own `FeatureFrame` for both systems. Scoring replicates the benchmark (5 s warm-up, 5 s grace).
  The script aborts unless AegisFlight's TP/FP/TN/FN equal `artifacts/benchmarks/results.json` (they do: 6535 / 4 / 16826 / 65).
- Outputs: `comparison.md` / `comparison.json` (metrics), `per_session.csv`, `baseline_meta.json` (provenance: git HEAD, dirty paths, python, model sha).

## Result (decision level, 23,430 decisions)

| System | TP | FP | TN | FN | Recall | FPR |
|---|---|---|---|---|---|---|
| AegisFlight | 6535 | 4 | 16826 | 65 | 0.9902 | 0.0002 |
| Threshold baseline | 996 | 1510 | 15320 | 5604 | 0.1509 | 0.0897 |

## How to read it (and what it does not show)

- All 1510 baseline false-positive decisions come from one rule, the fixed `abs_vertical_rate > 10 m/s` limit: 279 in the benign sessions and 1231 in the non-attack (pre/post-attack) ticks of attack sessions (`baseline_rule_firings_by_scenario_rule_kind` in `comparison.json`). The baseline raises at least one false alarm in 6/6 benign sessions (AegisFlight 1/6). The limit was defined in git before the run (`9944a57`; the run time itself is not independently timestamped, so this is "defined beforehand", not an externally witnessed pre-registration) from the airframe envelope, by the same authors who wrote the simulator, and **was not changed after seeing the result**. The outcome depends on that rule choice: without this one rule the baseline would have almost no false positives and roughly 600/6600 recall (DoS only), so the comparison does not favour AegisFlight through the rule choice alone, but a better-chosen baseline could do either better or worse than this one. Which flight phase triggers the rule was not examined.
- The same rule also supplies most of the baseline's attack-window hits outside DoS (a climb-rate exceedance inside the window, not shown to be caused by the attack). The only rule whose firings match an attack mechanism is `loss_ratio` on DoS (600/600 attack decisions). The baseline's session-level "6/6" for the non-DoS classes therefore does **not** show that it detects those attacks.
- It is not a model of ArduPilot or PX4 failsafes. Those were not run, and no failsafe/EKF-check outputs exist for the attacked sessions, so **no comparison with the autopilot's own checks is made** (missing: autopilot check results for the same attacked sessions).
- Six sessions per scenario: session-level Wilson intervals are wide (`comparison.md`). No real-world rate follows.
