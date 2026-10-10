# ArduPilot SITL — integration, benign baseline, and one reproducible link-level attack

**Environment tag: `SITL`** (ArduCopter **4.7.1**, `dbe792162d06`, tag `Copter-4.7.1`; SITL binary sha256
`fdc6f68f84e1473597dff39b91b412d081d09ba03716892ebcc78d76aadeb247`; `--model + --speedup 1 --sysid 1`,
home −35.363261, 149.165230; Linux 6.18.40.1-microsoft-standard-WSL2 / Ubuntu-24.04), analysed live and as **`REPLAY`** of
the recorded bytes. AegisFlight `9a6cd0274cd0a15ed52278cce0bd7df5713bfb68` + this sprint's uncommitted files.
Date 2026-10-10. The PX4 path and its evidence (`docs/STAGE2_RUNBOOK.md`, `artifacts/sitl/`, `models/isoforest_px4.joblib`)
were not modified.

**Claim classes in this document** (never merged):

| Section | Claim class | What it shows | What it does NOT show |
|---|---|---|---|
| §3–§5 benign baseline | none | false-alarm, coverage and cost reference | detection of anything; any real vehicle |
| §6 position-drift scenario | **link-level detection (SITL)** | the IDS alerts on a downlink whose GLOBAL_POSITION_INT lat/lon was rewritten in-path | estimator compromise, physical flight deviation, real GPS spoofing, anything about the physical Pixhawk |

## 1. What it took to ingest ArduPilot (the smallest change that works)

Nothing in the detection path changed. Measured on all 8 flights: **0 `bad_frames`, 0 `unverified_frames`,
0 `late_ticks`, 0 pipe overflow**; every ArduPilot message id is in pymavlink's `all` dialect (it includes `ardupilotmega`) so the
existing CRC-verified parser needs no `extra_crc` (the PX4-only table is not applied). ArduPilot's sysid 1 matches the
Stage-1 `expected_sysids: [1]`, and `HEARTBEAT.custom_mode` already maps through the ArduCopter table (PX4 needed a profile).

What was needed was **telemetry configuration**, not parsing: with default parameters ArduPilot streams only HEARTBEAT/TIMESYNC until the streams are
requested (measured on SITL and on the physical board, `docs/HARDWARE_BENCH_PIXHAWK6X.md`) or configured by parameters (§8a). Note for 4.7.x: the per-port stream parameters are `MAVn_*`, **not** `SRn_*`.

| Telemetry config | How | The six pipeline messages (Hz, measured wall-clock) | Aggregate | Other message types |
|---|---|---|---|---|
| **`six`** | `MAV_CMD_SET_MESSAGE_INTERVAL` for exactly the six at the Stage-1 simulator rates (SYS_STATUS 2, GPS_RAW_INT 5, GLOBAL_POSITION_INT 5, ATTITUDE 10, VFR_HUD 5; HEARTBEAT 1 unsolicited) | HEARTBEAT 0.95, SYS_STATUS 1.83, GPS_RAW_INT 4.56, GLOBAL_POSITION_INT 4.57, ATTITUDE 9.13, VFR_HUD 4.56 | 26.2–26.4 Hz, ~1.04 kB/s (Stage-1 nominal is 28 Hz) | 6 (COMMAND_ACK, PARAM_VALUE, STATUSTEXT, TIMESYNC, GPS_GLOBAL_ORIGIN, HOME_POSITION: startup/GCS-connect traffic) |
| **`groups`** | `REQUEST_DATA_STREAM` per group (EXTENDED_STATUS 2, POSITION 5, EXTRA1 10, EXTRA2 5) — what persistent per-port stream parameters on a real FC give (`MAVn_*` in 4.7.1, `SRn_*` in older firmware) | HEARTBEAT 0.95, SYS_STATUS 1.82, **GPS_RAW_INT 1.82** (it lives in the 2 Hz group), GLOBAL_POSITION_INT 4.54, ATTITUDE 9.07, VFR_HUD 4.53 | 61.3 Hz, ~2.5 kB/s | 15 (AHRS2, LOCAL_POSITION_NED, NAV_CONTROLLER_OUTPUT, POWER_STATUS, MEMINFO, MISSION_CURRENT, ESC_TELEMETRY_1_TO_4, SIMSTATE (SITL-only), …) |

Rates are ≈ 0.91–0.95× the requested ones because **the simulator ran at a real-time factor of 0.917–0.926** (least-squares slope of ATTITUDE
`time_boot_ms` against capture time, `scripts/ardupilot/measure_sitl_rtf.py` -> `artifacts/ardupilot/sitl_rtf.json`: **0.9167-0.9258** over 9 captures; boot-time frames carry a bogus
`time_boot_ms` and are excluded; the HEARTBEAT count rate of 0.95 includes boot time and is not a clock effect). Timing-derived features therefore
see a slightly slower, jitterier stream than a real FC would send.

### New code (all additive; nothing frozen touched)
| File | Role | Owner area |
|---|---|---|
| `src/aegisflight/sources/frame_pipe.py` | `LengthPrefixedPipeTransport`: a third `FrameTransport` (beside UDP and serial) reading length-prefixed frames from a child process's stdout; receive-only | transport |
| `src/aegisflight/sources/frame_tap.py` | `TapTransport`: tees clean + observed frames to tlogs and applies an optional `FrameHook` (same hook type as the UDP proxy); fails open and counts `hook_errors` | transport |
| `scripts/ardupilot/ap_netns_run.sh` | runs SITL in a private network namespace; proves isolation at run time; only stdout leaves | harness |
| `scripts/ardupilot/ap_gcs_pipe.py` | in-namespace GCS role (SITL only): stream config, scripted benign flight, frames → stdout | harness |
| `scripts/ardupilot/run_ap_sitl_ids.py` | Windows side: pipe → `TapTransport` → unchanged `LiveMavlinkSource` → unchanged `IDSPipeline` + `EventStore` hash chain; metrics, manifest | harness |
| `scripts/ardupilot/replay_ap_tlog.py`, `make_ap_baseline_summary.py`, `measure_replay_cost.py` | offline replay / baseline summary / portable cost metric | validation |
| `scripts/ardupilot/ap_attack.py`, `evaluate_ap_attack.py`, `check_ap_attack_reproducible.py` | §6 attack (red), scoring (blue), reproducibility | attack / validation |
| `scripts/ardupilot/ap_netns_run_passive.sh`, `ap_passive_monitor_pipe.py`, `ap_param_probe.py`, `sitl_defaults_monitor_port.parm` | §9: passive-monitor experiment (second SERIAL port, persistent stream parameters, a monitor that never transmits) | harness |
| `scripts/hardware/pixhawk_passive_probe.py`, `run_serial_ids.py`, `virtual_serial_replay.py` | receive-only probe for a physical FC / headless receive-only serial monitor / loopback "virtual serial device" | hardware |
| `tests/unit/test_frame_pipe.py` (16), `test_frame_tap.py` (9), `test_ap_attack.py` (9), `test_run_serial_ids.py` (5) | 39 new tests | — |
| `.gitignore` | ignores raw tlogs (`data/hardware/raw`, `data/ardupilot/raw`, `artifacts/ardupilot/*/downlink.tlog`) | — |

Only existing code touched: `src/aegisflight/sources/__init__.py` (one added export).

### Network namespace, stated explicitly
The simulator's TCP 5760 exists **only inside** `unshare --user --map-root-user --net`. Per run, the harness proves before
launching it: separate netns, `lo` the only interface, no address but loopback, no default route, no pre-existing listeners (fails
closed otherwise). The only channel out is stdout. Post-check, **all 8 runs**: no listener on 5760/5501/20722 in the default namespace, no new
listener of any port versus before, no `arducopter` left, harness exit 0 (`artifacts/ardupilot/*/manifest.json` → `postcheck`).
No port was opened in the default network and no WSL IP was used. (The simulator's own listener binds `0.0.0.0:5760` -- SITL's `--serial0 tcp:0` is INADDR_ANY -- but inside the loopback-only private namespace; reachability from the default namespace is excluded by the namespace, and `ss_default_*.txt` shows the default namespace unchanged. The in-namespace bind is visible in each run's `harness.stderr.log`.)
Pipe integrity, all runs: the frames the Windows side received equal the frames the WSL side wrote, **frame for frame**
(`pipe_integrity.identical = true`; 3,660 frames per `six`/attack flight, 8,559 for `groups`).

## 2. Flight used for the benign runs
Scripted by `ap_gcs_pipe.py` against the simulator: wait for GPS 3D fix → GUIDED → arm (retried while the EKF initialises) → takeoff 15 m →
50 m square at 15 m → RTL → land → disarm. ≈ 140 s of link per flight. Phase boundaries come from the collector's own events.
This flight is simple, short, and identical every time; it is **not** representative of real missions, wind or manoeuvres.

## 3. Benign baseline — Stage-1 configuration, no ArduPilot profile
Generated by `scripts/ardupilot/make_ap_baseline_summary.py` → **`artifacts/ardupilot/BASELINE_SUMMARY.{md,json}`**
(inputs: `artifacts/ardupilot/ap_benign_*` — 4 × `six`, 1 × `groups` — and their clean tlogs). "In-flight" = takeoff, square, rtl, landed;
"ground" = boot, await_gps, arm (start-up before GPS lock / arming).

| Variant | In-flight alert decisions | Ground alert decisions |
|---|---|---|
| Stage-1 config + **Stage-1 ML model** (live) | **126 / 2,339** (5.4 %) | 75 / 1,166 |
| Stage-1 config, **ML detector off** (replay of the same bytes) | **0 / 2,329** (0 in each of the 5 flights) | 25 / 1,166 (exactly 5 per flight) |

* **The Stage-1 ML model does not transfer to this ArduPilot-SITL path, and it is the only in-flight false-alarm source here.** Its score is ≈ 1.0 on most decisions, with
  `interarrival_jitter_ms` named as the driver in 165 alert-evidence strings (positive z up to +19.2, median +13.0; and many strongly **negative** z, down to -44, after start-up). That the model
  was trained on the Stage-1 simulator's perfectly regular timing is an *inference*, not tested; the measured stream also includes WSL/TCP/pipe
  relaying, Windows receive stamps and an RTF of 0.92, so part of the jitter is path-induced. It is therefore **disabled
  (`--no-ml`) for every ArduPilot result below**; nothing in this document is evidence about the ML detector on ArduPilot in general (no ML-on attack run exists).
  Retraining it per vehicle is Stage-2 step 4 and was not done.
* The 5 ML-off ground alerts per flight are start-up artefacts, outside any scored window, and the same in every flight. The evidence strings are:
  "heartbeat stale 999 s" and "GPS dropout 999 s" (never-seen sentinels), "GNSS fix lost: fix_type=0, satellites=0" (for 12 and for 32 consecutive decisions,
  i.e. ≈ 2.4 s and ≈ 6.4 s), "battery voltage rose ≈ 23 V", "position residual 30 m ≥ hard 30 m" and "implausible altitude rate 2920 m/s". The values look like
  first-sample transients after boot; they were not investigated further. The existing additive `protocol.startup_grace_s` key would cover only the first two;
  **no profile was created and no threshold was tuned**.
* **Selection caveat:** ML was switched off *because* it was the only in-flight alert source on these same 5 flights, so 0 / 2,329 is selected-on-data, not held out. The only out-of-sample ML-off benign check is the pre-onset in-flight 0 / 223 of the three attack flights (the choice was made on benign flights before any attack run, so it does not tune against the attack score). The ML-on and ML-off denominators differ (live 2,339 vs replay 2,329).
* The 5 start-up alerts per flight include one **`GPS_SPOOFING`** alert (score 1.0 at t ~ 10 s, "position residual 30 m >= hard 30 m / altitude rate 2920 m/s", the first position samples after boot): the alert *type* GPS_SPOOFING occurs on the ground in benign flights, which matters for criterion D2 (D2 is scored only inside the attack window) and for operators.
* 0 / 2,329 in-flight decisions bounds nothing precisely: decisions are autocorrelated and there are only 5 flights of one simple trajectory.
  Do not quote a false-alarm *rate* from it.
* Replay vs live: replaying the clean tlogs reproduces the live alert verdict on every decision (Stage-1 + ML: 695/695, 700/700 x4; per run in `artifacts/ardupilot/replay_vs_live/`), so the
  offline numbers above are the live behaviour, not an approximation.

### Latency, throughput and resources (Windows host = ASUS TUF F15; the simulator runs in WSL and is excluded)
| | Decision latency (pipeline compute) | Tick close → emit | CPU (one core) | RSS |
|---|---|---|---|---|
| ML on (`ap_benign_*`) | mean 10.4–10.8 ms, p50 10.3–10.5, p95 12.1–14.4, p99 16.7–22.2, max 20.7–62.7 | p50 5.5 ms, p99 6.0–8.4 | mean 5.5–7.5 %, max 9.3–13.8 % | ≈ 165 MB |
| ML off (`ap_attack_drift_*`) | mean 0.18 ms, p50 0.18, p99 0.31, max 0.55–1.01 | p50 5.5–5.6 ms, p99 6.1 | mean 1.0–1.4 %, max 4.5–6.2 % | ≈ 59 MB |

`late_ticks = 0` in all 8 flights. The tick-close→emit figure is dominated by the 5 ms `settle_s` of `LiveMavlinkSource`. These are
**one laptop, one OS, 140 s runs**; they do not transfer to a companion computer (see `docs/ONBOARD_DEPLOYMENT.md`, which uses a re-measurable metric instead).

## 4. Hash-chained logging
Every alert goes through the unchanged `EventStore`; `verify_chain` reports "chain intact" for all 8 runs (e.g. 41 events in
`ap_benign_six_001`, 12 in each attack run). The chain proves the log was not edited after the fact; it does not prove the alerts are correct.

## 5. Known limitations of the baseline
Simulated GPS/IMU/battery (no vibration, multipath, EMI, GPS glitches); RTF 0.92 and a single airframe model; one scripted trajectory;
no wind; no GCS traffic mix; ML off; Stage-1 thresholds untouched and not calibrated for ArduPilot; the `groups` configuration was run
once; start-up alerts are not suppressed; resource figures are laptop figures with the simulator excluded.

## 6. P2 — one pre-registered link-level attack: downlink position drift
**Environment `SITL`. Claim class: link-level detection only.** The in-path hook rewrites `GLOBAL_POSITION_INT` frames on their way
from the simulator to the IDS; **the simulator never receives a modified frame**, so its estimator and its flight are untouched
(it flies the commanded square regardless). This is not GPS spoofing of the vehicle, not an estimator compromise, and not a physical deviation.

**Defined before running** (`artifacts/ardupilot/p2_position_drift_preregistration.json`, recorded and hashed 2026-10-10T06:09:00Z -- a self-written timestamp on an untracked file, **not a cryptographic signature** -- 14 code files hashed, no attack artifact existed):

* *Attack:* reviewed, unchanged `PositionDriftAttack`, wrapped by `ap_attack.py` which adds one thing — an attacker-observable gate (stay
  pass-through until the downlink itself shows `relative_alt ≥ 12 m`). Then, 5 s later, drift lat/lon **east at 5 m/s for 25 s (125 m)**;
  vx/vy/vz/alt/relative_alt/hdg left truthful; CRC recomputed; every other frame byte-identical. No simulator ground truth, no detector state.
* *Expected observable effect:* the reported track diverges from the (truthful) velocity and from GPS_RAW_INT; the physics-consistency
  position-residual check (soft 12 m, hard 30 m) should trip within ~15 s of onset.
* *Clean baseline:* §3 (ML off: 0 in-flight alerts in 5 flights) **and** a paired control — each attack run's own clean frames (tee'd before the hook) replayed through the same pipeline/config.
* *Criteria* (all must hold): **D1** ≥ 1 alert decision in [onset, end + 10 s]; **D2** the first such alert is `GPS_SPOOFING`; **D3** it lists
  `physics_consistency` among its contributing detectors; **C1** the control arm has 0 alert decisions in that window; **B1** 0 in-flight alerts before onset.
  Validity gates (any failure ⇒ `INVALID`, not a result): harness exit 0, pipe byte-identical, no overflow, hash chain intact, no orphan simulator,
  no default-namespace leak, `hook_errors = 0`, gate opened, ≥ 80 frames modified, run matches the registered spec/config/ML setting.
* *Plan:* 3 fresh flights, all reported, no parameter changes.

**Result (scored by `evaluate_ap_attack.py`, `artifacts/ardupilot/ap_attack_drift_00N/evaluation.json`): 3 of 3 `DETECTED`, all validity gates passed.**

| Run | Window (s from first frame) | Frames modified / max drift on the wire | Alerts in window (all `GPS_SPOOFING`) | First alert (after onset) | Evidence of the first alert (hash-chain event) | Control arm in window | Pre-onset in-flight alerts |
|---|---|---|---|---|---|---|---|
| `ap_attack_drift_001` | 61.19 – 86.19 | 115 / 124.6 m | 6 (+1 at t=88.0, in the 10 s grace) | t = 64.0 s (+2.81 s) | "position residual 13.5 m > 12 m (reported track diverges from velocity)", `physics_consistency` only; event 6, `ec697e14…` | 0 / 175 | 0 / 78 |
| `ap_attack_drift_002` | 61.13 – 86.13 | 114 / 123.9 m | 6 (+1 at t=88.0) | t = 64.0 s (+2.87 s) | "… 14.0 m > 12 m …"; event 6, `5ae3422a…` | 0 / 175 | 0 / 79 |
| `ap_attack_drift_003` | 61.08 – 86.08 | 116 / 124.5 m | 6 (+1 at t=88.0) | t = 63.8 s (+2.72 s) | "… 13.3 m > 12 m …"; event 6, `d7a96289…` | 0 / 175 | 0 / 66 |

Each run logged 12 alerts in total: the 5 start-up ones of §3 plus 7 `GPS_SPOOFING` alerts after onset (6 inside the attack window, 1 in the 10 s scoring grace). The "drift on the wire" figure comes
from the attack's own frame log (`attack_frames.jsonl`, ground truth written at modification time, read only by the evaluator).

**Reproducibility** (`artifacts/ardupilot/ap_attack_drift_00N/reproducibility.json`, offline, no simulator; needs the git-ignored raw tlogs, so it cannot be regenerated from a bare clone):
* Re-applying the registered spec to the run's **clean** tlog reproduces the live **observed** tlog **byte for byte — 3,660 / 3,660 frames in all three runs**, with identical modified-frame counts (115, 114, 116).
* Replaying the **observed** tlog through the unchanged pipeline reproduces the live alert verdict on **696/696, 696/696 and 695/695** decisions, with the same first alert and time.
* Command to regenerate everything: see §8.

### Honest reading
* This supports exactly: **"on ArduCopter 4.7.1 SITL, with the ML detector off and Stage-1 thresholds, the physics-consistency detector raised a
  `GPS_SPOOFING` alert about 2.7–2.9 s after an in-path eastward position drift of 5 m/s began, in 3 of 3 flights, with no alert in the paired clean control, and
  the evidence reproduces from the recorded bytes."**
* It does **not** support: a detection rate (n = 3, one scenario, one simulated airframe/trajectory, one host); detection by the ML detector; any
  statement about other attacks on ArduPilot (the other five classes were not run); anything about a real vehicle or the physical Pixhawk; signing/replay resistance.
* **The attack is the easy case for this detector.** Only lat/lon are rewritten while vx/vy/vz stay truthful, so the physics residual check (soft 12 m) trips by construction, and 125 m is ~10x the threshold. A velocity-consistent offset or drift -- the realistic spoofing case, and the known Stage-1 `sudden_offset` gap -- was not tested. The Stage-1 physics thresholds were designed for this attack family and it had already passed 10/10 on PX4, so a detection was the expected outcome; the value of the run is the reproducible ArduPilot link-level evidence chain, not a surprise.
* Detection time is bounded below by the detector design: a 12 m residual at 5 m/s needs ≥ 2.4 s. A slower drift (< ~1 m/s) was not tried and may be missed or detected late.
* The attack is the same one that was validated on PX4 (`artifacts/sitl/P2_summary.md`: 10/10); the two are not merged into one figure.

### Process disclosures (post-registration changes, none to criteria)
`artifacts/ardupilot/p2_position_drift_preregistration_addendum.json` records four sets of edits made **after** the registration, with hashes and diffs. The first two concern `evaluate_ap_attack.py` (entry timestamps are when the entry was *written*, not when the edit was made, so the stated order is approximate, and no pre-edit evaluation output exists to compare for edit 2, which changed a label only): (1) a `KeyError` at first use — it read `pre["attack_spec"]` but the file stores `pre["attack"]["spec"]` — fixed before any evaluation output existed; (2) a
misleading output label renamed (`alerts_whole_flight_inflight_phases` → `…_all_phases`; it counts start-up alerts too). No criterion, threshold, window,
parameter or verdict logic changed, and the evaluation was re-run afterwards with identical verdicts. Entry 3 added the optional `--harness` argument to the orchestrator (default unchanged). Entry 4 (after independent code/security review) hardened the orchestrator, the evaluator (extra validity gates; verdicts re-run unchanged) and `frame_pipe.py`/`frame_tap.py`; those two transport files were edited **after** the three attack runs, so the runs used the earlier versions (changes: stricter record validation, fail-open ordering). The manifests record only the collector hash, not per-run hashes of every script. The orchestrator's console summary of alert counts had been printed
before the evaluator was fixed, so the evaluator was not "blind" in the strict sense; the criteria and parameters were nonetheless fixed in advance and are unchanged. One collector
bug (a keyword clash in `event(...)`) crashed the very first flight attempt before any data were produced; the rerun is the evidence. The passive-monitor run `ap_passive_monitor_params_001` is the **second execution**: a first complete execution (8,581 frames, `tx_frames 0`) was discarded after a lint-only edit of the monitor script so that the recorded script hash matches the final file; its result did not differ materially. That run's `summary.json` says `stream_config: six` although the monitor port was configured by `MAV2_*` parameters (the label refers to the unused driver option on SERIAL0).

## 7. Regression gate (project process §4)
* `pytest` (with `addopts` overridden to see the summary line): **541 passed, 3 skipped** (the same 3 PTY tests that cannot run on Windows) = 502 prior + 39 new.
* `ruff check src tests scripts backend`: clean.
* Stage-1 benchmark regression, scratch dir, `--no-figures`: **TP/FP/TN/FN = 6535 / 4 / 16826 / 65**, identical to the committed baseline over the same 23,430
  decisions; per-attack table identical; only timing rows differ (machine-dependent). Committed `artifacts/` untouched.
* PX4 tree: `git status --porcelain --untracked-files=no` empty, `v1.18.0-rc1-27-gc239c63807`. ArduPilot tree: 0 tracked changes.

## 8a. Passive-monitor path (deployment preparation; env SITL; not part of the registered P2)
Question: can the FC stream to a monitor that **never transmits**, if the streams are configured by *persistent parameters* on a dedicated port?
**Yes, in this SITL** — and the way it was found matters:
* ArduCopter **4.7.1 has no `SRn_*` parameters** (read back from the simulator: absent; the source says `// SR0 through SR6 was here`); stream rates are `MAVn_*`. A first parameter file
  with `SR1_*` names was therefore a silent **no-op** (the simulator's defaults loader reported "Loaded defaults" regardless): runs `ap_passive_monitor_001` (strictly receive-only) and
  `ap_passive_monitor_hb_001` (sending only a 1 Hz GCS heartbeat, 130 frames) both received just HEARTBEAT/TIMESYNC (+ STATUSTEXT/PARAM_VALUE/origin/home) — i.e. "default parameters give no streams, with or without a
  heartbeat". I had hypothesised that ArduPilot withholds streams until it hears a GCS heartbeat; that was **wrong**.
* With the corrected file (`MAV2_EXT_STAT=2, MAV2_POSITION=5, MAV2_EXTRA1=10, MAV2_EXTRA2=5`; read back from the simulator) the strictly receive-only monitor on SERIAL1 received **8,589 frames, all six messages, `tx_frames 0`** in
  `ap_passive_monitor_params_001`; the unchanged pipeline (ML off) logged 5 start-up alerts and **0 in-flight alerts (0/476)**; replay reproduced the live verdicts on 706/706 decisions; 13 other message types, 60.9 Hz, 2.5 kB/s;
  CPU 2.3 % of a core, RSS 58.6 MB. Evidence: `artifacts/ardupilot/ap_passive_monitor_params_001/`, `artifacts/ardupilot/passive_monitor_param_readback/README.md`.
* Not shown: the physical board, any other firmware version, which `MAVn` maps to which `SERIALx` outside this SITL. See `docs/ONBOARD_DEPLOYMENT.md`.
* Addendum: this path needed an optional `--harness` argument in `run_ap_sitl_ids.py` (default unchanged), recorded in `p2_position_drift_preregistration_addendum.json` (entry 3).

## 8. Reproduce
```
# benign flight (≈2.5 min), live, ML on (Stage-1 default) or --no-ml
.venv/Scripts/python.exe scripts/ardupilot/run_ap_sitl_ids.py --name ap_benign_six_001 --stream six --profile flight
# attack flight (registered spec)
.venv/Scripts/python.exe scripts/ardupilot/run_ap_sitl_ids.py --name ap_attack_drift_001 --stream six --profile flight --no-ml \
    --attack "position_drift:onset=5,duration=25,rate=5,bearing=90,airborne_m=12"
.venv/Scripts/python.exe scripts/ardupilot/evaluate_ap_attack.py artifacts/ardupilot/ap_attack_drift_001 \
    --prereg artifacts/ardupilot/p2_position_drift_preregistration.json --json artifacts/ardupilot/ap_attack_drift_001/evaluation.json
.venv/Scripts/python.exe scripts/ardupilot/check_ap_attack_reproducible.py artifacts/ardupilot/ap_attack_drift_001
.venv/Scripts/python.exe scripts/ardupilot/make_ap_baseline_summary.py
```
Raw tlogs are local (`data/ardupilot/raw/`, sha256 in each `manifest.json`); everything else is committed-able under `artifacts/ardupilot/`.
