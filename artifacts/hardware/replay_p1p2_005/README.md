# replay_p1p2_005 — HEARTBEAT-only capture 005 replayed through the P1/P2 working tree

**Environment:** `REPLAY` of `BENCH` data (capture 005: physical Pixhawk 6X, telemetry radio on COM7,
60 s, HEARTBEAT only, recorded before the `SR1_*` change; see `docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.7).
**Claim class:** none. This describes a benign stream and shows the P1 coverage path. It is **not**
detection evidence.

## Provenance
- Code: `HEAD` `83f07c1782c7a19dcc2ec3e5f2261ee848cf5402` **plus the uncommitted P1/P2 working tree**.
  - sha256 of `git diff HEAD -- src configs`: `e03ab6c879680b09c3c982ac46245796eed278e81cd0f3b30c98610f2723aa9e`.
  - Whole-tree `git diff HEAD | sha256sum`: see the end of this file.
- Config: Stage-1 default `configs/`. `configs/detector.yaml` sha256
  `88ec9ffbced4c898f226c91b421ae05b39d72049575ec5cc808fc9ceec0aaac3`. ML: **off**.
- Python 3.13.15, pymavlink 2.4.50, numpy 2.5.3, scikit-learn 1.9.1; Windows 11.
- Input: `data/hardware/raw/telemetry_radio_005.tlog` (local, git-ignored), sha256
  `0f4e2887e4da853b0ffb9aadc56488a0080930d453e245c720a8b063256784b5`.
  - No tlog hash was recorded for 005 before this replay.
  - The companion `.rawbin` sha256 `fb342f47f93c46d5931c8ea43c547d74b9faab9d5c48e0366674abd40527d315` matches
    `artifacts/hardware/telemetry_radio_probe_005.json`.
  - The tlog's 60 frames match the probe's `frames` count.
- Path: in-process only. No serial device, virtual port or socket is used.

## Regenerate
```
.venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/telemetry_radio_005.tlog --no-ml --json artifacts/hardware/replay_p1p2_005/replay_noml.json
```

## Not in `replay_noml.json` (scratch analysis, same replay loop, not committed)
- 60 frames, 296 decisions, 0 threat decisions, 0 alerts.
- Every decision (296 of 296) carries the coverage line:
  "coverage: GLOBAL_POSITION_INT never received (GPS_RAW_INT never received); position-dependent checks
  inactive; not attack evidence under this profile (protocol.require_global_position=false)".
- telemetry_coverage at the end: heartbeat_seen true, global_position_seen false, gps_raw_seen false,
  decisions_without_global_position 296.

## Limitations
- n = 1.
- No attack.
- The replay clock starts at the first frame.
- This shows the default profile only. `require_global_position: true`, which would restore the old DOS
  outcome, was not replayed.

## Whole-tree diff hash at time of writing
`git diff HEAD | sha256sum` = `afcd5bb7a85d30732fbfbbbaa1113c92f1d1323a03ac46cb2897387c03604633` (computed 2026-10-16 ~00:05 +0530, after the benchmark; `src/`+`configs/` diff hash unchanged across the run)

## Provenance re-check, 2026-10-20 (appended; the numbers above are unchanged)
- The `src`+`configs` diff hash recorded above (`e03ab6c8…a9e`) is **stale**: it describes the tree at the time of
  this replay. `src/aegisflight/detectors/protocol.py` was modified afterwards (file time 2026-10-16 00:16 +0530; content of
  that edit not recorded) and again on 2026-10-20 (aegis-detection: the coverage line is appended last in the protocol
  evidence; `detectors/physics.py` gates the GPS/VFR speed rule on `gps_seen`).
- Re-run on the 2026-10-20 tree: `HEAD` `83f07c1` + working tree, `git diff HEAD -- src configs | sha256sum` (Git Bash) =
  `708192a04883a7ad83a5918c81bf752c34e96744f2ff35ab498af81795aa0ad6`, taken immediately before the replay and unchanged
  after it. The regenerate command above, with `--json` pointed at a scratch directory, gives a `replay_noml.json` that is
  **byte-identical** to the one in this directory (sha256 `a3212016e8ec89b399e35b8fe694c7f29d3a0f10092da3a841f0bdceab86a54c`).
- The scratch-only figures listed above (296 coverage lines of 296 decisions, exact text; `telemetry_coverage` end values)
  were re-measured on the same tree with the same replay loop and reproduce exactly. Input tlog sha256 re-verified:
  `0f4e2887…84b5`.
