# CLAUDE.md — AegisFlight

Guidance for Claude Code (and humans) working in this repo.

## What this is
A Stage-1 proof-of-concept **UAV Intrusion Detection System** (PUSHPAK
challenge). Detects six attack classes on a **simulated** MAVLink link +
firmware, fuses four detectors into explainable alerts, logs to a tamper-evident
hash chain, streams to a React dashboard. **Everything is a local simulation.**

## Environment
- Python ≥ 3.11 in `.venv` (use `.venv/Scripts/python.exe` on Windows).
- Install: `pip install -e ".[dev]"`. Node ≥ 18 only for the dashboard.
- Windows: the shell is PowerShell; a Bash tool is also available.

## Key commands
```bash
aegis simulate --attack gps_spoofing   # one session + alerts
aegis train                            # train models/isoforest.joblib
aegis benchmark                        # metrics + figures -> artifacts/
aegis serve                            # dashboard http://127.0.0.1:8000
aegis verify-log <db.sqlite>           # check hash chain
pytest                                 # 545 passed, 3 skipped (Windows PTY)
ruff check src tests scripts backend   # lint (keep clean)
python scripts/run_demo.py             # narrated headless demo
```

## Architecture (one line)
`simulator → mavlink(+noise) → [attack] → decode → features → 4 detectors →
fusion → ThreatAssessment → {SQLite hash chain, FastAPI/WS → dashboard}`.
The pipeline is wired only in `pipeline.py`; backend + benchmark reuse it. Full
docs in `docs/` (start at `docs/README.md`, then `docs/HANDOFF.md`).

## Conventions
- `ruff` clean; `from __future__ import annotations`; modern generics.
- Small logical commits; end messages with
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Detectors read only a `FeatureFrame`; `core/` imports nothing internal; ground
  truth (`FlightState`, attack `label`) is benchmark-only.

## Do NOT change casually
`ML_FEATURES` order (model depends on it — retrain), `FlightState`/
`MessageEnvelope` fields, enum `.value` strings, MAVLink field mappings, the
event schema / hash-chain canonicalisation, the benchmark scoring policy, attack
hook signatures. See `docs/HANDOFF.md`.

## After changing detectors/features/simulator
Retrain (`aegis train`) and re-benchmark (`aegis benchmark`), then update the
numbers in `README.md`, `docs/BENCHMARKING.md`, `docs/technical_proposal.md`, and
keep the relevant `docs/*.md` in sync (see `docs/DEVELOPMENT.md`).

## Generated vs committed
Commit `artifacts/benchmarks/*` and `artifacts/figures/*` (evidence). Do NOT
commit `models/*.joblib`, `*.sqlite`, `frontend/dist/`, `node_modules/` (all
gitignored; regenerable).

## History
Recovered after a mid-build crash — see `docs/RECOVERY_AUDIT.md`. Foundation
(config/core) is unchanged; everything else was built during continuation.
