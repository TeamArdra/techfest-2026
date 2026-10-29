# Submission archive manifest (draft for the team to decide)

The Stage 2 template says source code, tests, flight logs and datasets, attack-injection scripts, ground-truth files, result
files and the demonstration video "must be included in the submitted archive; a link alone is not sufficient", and that large
data may be "included or supplied with a checksum". This file states what a clean checkout of this branch contains, what it does
not, and which decisions only the team can make. Nothing here was staged, published or copied: it is an inventory.

Sizes were measured on 2026-10-29 with `du`; the git-tracked tree is about 5.5 MB (1,224 files).

## 1. In Git: ships with the repository

| Path | Purpose | Note |
|---|---|---|
| `src/`, `backend/`, `scripts/`, `frontend/` (source only), `configs/`, `rust/`, `pyproject.toml` | code and thresholds | `frontend/dist/` and `node_modules/` are not tracked: `npm --prefix frontend ci && npm --prefix frontend run build` |
| `tests/`, `backend/tests/`, `frontend/tests/` | test suites | `docs/TESTING.md` |
| `docs/`, `README.md`, `LICENSE`, `THIRD_PARTY_NOTICES.md` | guides, risk register, report draft, audit | the report itself is `docs/stage2_report_draft.md` (Markdown; the committee's format is the team's decision) |
| `artifacts/benchmarks*/`, `artifacts/external/`, `artifacts/validation/`, `artifacts/sitl/`, `artifacts/ardupilot/` (summaries, traces) | result files behind the numbers | `artifacts/**/events.sqlite`, `*.log` and `artifacts/ardupilot/*/downlink.tlog` are git-ignored (see §2) |
| `artifacts/hardware/gps_hw_verify_20261029/` and earlier `artifacts/hardware/*` | receive-only bench evidence | summaries only; no `lat`/`lon` keys and no decimal-degree-like numbers found by a scan on 2026-10-29 (the only matches were timestamps) |
| `data/external/manifests/*.json` | URL, licence, SHA-256 of every external log | the logs themselves are not in Git |
| `data/sitl/raw/*.json` | SITL driver traces | simulated position, not private |

## 2. Not in Git, needed to reproduce or to be seen (decide per item)

| Item | Size | Why it matters | Reproducible? | Options for the archive |
|---|---|---|---|---|
| `models/isoforest.joblib` (sha256 `3fe74cdd…`, recorded in `.claude/CLAUDE.md` on 2026-10-06 and re-read from the file on 2026-10-29) and `models/isoforest_px4.joblib` | 3.8 MB total | Without the model the ML detector is a **silent no-op** (`AnomalyDetector`): the Stage-1 headline numbers need it | yes: `aegis train` (~15 s, seeded). Verify that the retrained file reproduces the benchmark counts before relying on it | include the file with its checksum, **and** keep `aegis train` in the instructions |
| `data/hardware/raw/*.tlog`, `*.rawbin` (physical bench captures; the 2026-10-28 capture sha256 `c2e3459b…`) | 960 KB | the only real-vehicle data; replays in `artifacts/hardware/**/replay/` depend on it | no (needs the vehicle) | **HUMAN DECISION.** They contain the bench GPS position. Options: supply only the SHA-256 now and the files on committee request; or include a copy whose position fields are removed or offset (no tool for that exists yet, and the replay results would then change). Do not publish as-is |
| `data/external/raw/alfa/` | part of 3.1 GB | real fixed-wing logs for the false-alarm replays | yes: `scripts/fetch_external_data.py` (SHA-256 manifest) | include or supply checksums (the manifest records "CC BY 4.0"; confirm at the source) |
| `data/external/raw/px4_review/` | part of 3.1 GB | PX4 Flight Review replays | yes (fetch script) | **do not include**: no dataset licence is stated |
| `artifacts/ardupilot/*/downlink.tlog`, `artifacts/**/events.sqlite`, `*.log` | tens of MB | raw SITL captures behind the summaries | no (needs WSL, PX4, ArduPilot) | include if size allows (SITL position is simulated); otherwise checksum |
| Demonstration video | n/a | mandatory | not produced | **HUMAN ACTION.** Plan: `docs/DEMO_RUNBOOK.md` |
| Rendered figures of the two Mermaid diagrams, an operator-view screenshot | n/a | template asks for them | yes (second pass): `docs/figures/` (Figure 3, 4: `.mmd`, `.png`, `.svg`); two screenshots in `demo/screenshots/` | render from the report source; label every screenshot SIM / REPLAY / SITL |

## 3. Never include

`.claude/`, `.venv/`, `node_modules/`, `.ruff_cache/`, `.pytest_cache/`, `AEGISFLIGHT_STAGE2_ENGINEERING_BRIEF.md` and
`LOCAL_AEGISFLIGHT_END_TO_END.md` (local, git-ignored working notes), any MAVLink signing key, and any file with a
coordinate from the bench capture.

## 4. Open items for the team (cannot be filled from the repository)

1. Team ID, submission date, team-leader signature, the integrity declaration (§11.3 of the report).
2. The "final team target" column of the §3 requirements table.
3. The AI-tool verification statement for §11.1: what the team itself reviewed, ran and checked.
4. Whether `Copyright (c) 2026 Team Ardra` in `LICENSE` is the right holder line.
5. Raw hardware capture handling (§2) and the video.
