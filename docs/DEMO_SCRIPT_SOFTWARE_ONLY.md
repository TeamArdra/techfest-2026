# Software-only demonstration script (to be recorded; no video exists yet)

**Status: this is a plan and a narration, not a recording.** No demonstration video has been produced; the template requires one
("screen recording of a real run"). Everything below runs on a laptop with no vehicle attached. The only real-vehicle material is
a *replay* of a receive-only bench capture, and it is labelled as such on screen. Nothing in this script transmits to any vehicle.

Environment tags on screen for every segment: the dashboard's header badge shows **SIM** or **REPLAY**; say the tag aloud before
each segment. Never describe a SIM or REPLAY result as a flight, a real attack or a real-vehicle detection.

## 0. Before recording (once)
```bash
pip install -e ".[dev]"
aegis train                                              # models/isoforest.joblib (without it the ML detector is a silent no-op)
npm --prefix frontend ci && npm --prefix frontend run build
python scripts/verify_stage2.py                          # 8 suites, SIM hand-built inputs, not validation evidence
pytest -q                                                # state the pass/skip counts you actually get
```
Use a scratch database for every server (`--db <scratch>.sqlite`); the default `artifacts/aegisflight_live.sqlite` is local evidence.
Close anything on ports 8000/8001. The replay segment needs `data/hardware/raw/gps_hw_verify_20261029.tlog` (local, git-ignored; it
holds the bench GPS position; the dashboard shows no coordinates, but do not open the file or print its contents on screen).

## 1. Architecture (≈45 s, slide or the report's §3 diagram)
Say: passive tap → MAVLink decode → feature extraction → four detectors (protocol rules, physics consistency, learned model,
firmware integrity) → noisy-OR fusion → SQLite hash-chained log → dashboard. Detectors read only the extracted features.
`tests/unit/test_label_independence.py` checks that decisions do not change when the ground-truth fields are removed (SIM, five
attack classes).

## 2. SIM: one successful attack (≈2 min)
```bash
aegis serve --port 8000 --db <scratch>/demo_sim.sqlite       # default posture: PASSIVE
```
Open http://127.0.0.1:8000. Header badge **SIM**; footer "not a real UAV". Click **GPS Spoofing → Gradual Drift → 6.0 m/s (Standard) →
Inject**. Expected (observed 2026-10-29 in this repository; timings vary): threat state HIGH / GPS SPOOFING within about a second of
simulated time; the "Why this alert?" panel shows a physics line like "position residual … m > 12 m (reported track diverges from
velocity)" and an ML line; the persisted-alert list grows; the posture reads "PASSIVE … 0 bytes sent".
Say: this is a **simulation with the ML detector on**, an attack the team wrote, and a detector the team wrote. It is design evidence.
Screenshot of this state: `demo/screenshots/dashboard_SIM_gps_spoofing_gradual_drift.png`.

## 3. SIM: one limitation (≈1 min)
The same console, **Clear Attack**, then inject `command_injection` with mode `gcs_replay` (the replayed commands carry the legitimate
ground-station identity):
```bash
curl -X POST http://127.0.0.1:8000/api/simulation/attack -H "content-type: application/json" \
     -d '{"attack":"command_injection","mode":"gcs_replay"}'
```
Expected: **no alert for the injected commands**. Observed in the live console on 2026-10-29: 0 persisted alerts after about 50 s. Reproduced headless: 0 of 100 attack-window decisions flagged, with and without ML
(seed 7), and 0/4 sessions in the extended benchmark (`artifacts/validation/submission_rerun_20261029/`). Say: without
message authentication this class cannot be told apart from the real operator; the planned answer is MAVLink-2 signing (tested once
in PX4 SITL, `artifacts/sitl/P4_signing_summary.md`), not a better threshold. Also state the GPS drift floor: slow drift below about
4 m/s is not flagged by the rules and physics layers (ML off), see `artifacts/validation/submission_rerun_20261029/gps_drift_sweep_ml_off/`.

## 4. Reading the output and the defense (≈1 min)
Walk the alert: class, score, evidence strings, contributing detectors, timestamp, hash. Click **Verify SHA-256 Chain** and run
`aegis verify-log <scratch>/demo_sim.sqlite` in a terminal. The chain detects edits and deletions; it is **not signed**.
Defense: in this software-only demo "ACTIVE IPS" is shown as a **SIM model**. On live sources the default `passive` posture sends nothing; the
`active-ips` posture and the inline bridge (`docs/INLINE_IPS.md`) exist but were verified only on ArduCopter SITL / loopback, never on a real
vehicle. Do not show it as a working prevention capability, and do not quote its "detour" figure: no prevention metric was measured.

## 5. REPLAY: the real bench capture (≈1.5 min)
Stop the server. Then:
```bash
aegis serve --source replay --tlog data/hardware/raw/gps_hw_verify_20261029.tlog --replay-speed 1.0 --port 8001 --db <scratch>/demo_replay.sqlite
```
Header badge **REPLAY**, footer "not live and not a flight", link "Replaying". Point at the GPS line: the receiver says "3D_FIX · 7 sats ·
usable fix yes" while the autopilot's own status says "no horizontal position solution" and "GPS sensor unhealthy". Say exactly this:
a powered-on, disarmed, stationary board indoors; the IDS stayed quiet (0 alerts in 451 decisions in the live run) **and** states what the
vehicle says about itself. This is receive-only bench data, 90 s, one vehicle, no attack; the status messages are unauthenticated;
it says nothing about detecting an attack on a vehicle. Screenshot: `demo/screenshots/dashboard_REPLAY_bench_capture_gps_health_note.png`.
Note on that screenshot: the threat card reads "NORMAL / nominal flight" next to the unconfirmed-position note. "Normal" there means
"no detector fired", not "the position is verified".

## 6. Closing statement (read as written)
"AegisFlight is a passive IDS. We have shown its detectors on a simulator and on software-in-the-loop link attacks, and its receive-only
ingestion on a physical autopilot on the bench. We have not flown it, have not attacked a real vehicle, have not measured it on a
companion computer, and cannot yet state a false-alarm rate per hour. Known gaps: replay of legitimate commands, slow GPS drift, and
forged status messages. The next step is receive-only flight trials."

## Capture checklist
- [ ] Resolution ≥ 1920×1080, browser zoom 100 %, terminal font ≥ 16 pt.
- [ ] Header badge (SIM / REPLAY) and footer visible in every dashboard shot; segment title card names the environment.
- [ ] No file explorer, no coordinates, no private paths, no `.claude/`, no tokens on screen.
- [ ] Record the exact commit (`git rev-parse HEAD`) and `pytest` counts at the end card.
- [ ] Do not narrate "defense prevented" or "drone stayed airborne": those are SIM-model outputs.
- [ ] Save the video outside Git; list its filename and SHA-256 in the submission archive manifest.
