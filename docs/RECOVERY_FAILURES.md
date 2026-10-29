# AegisFlight — Recovery Failures Log

Failures observed by **actually executing** the recovered code (Phase 4), not
by reading it. Because the crash left the project at foundation-only stage,
every failure has the same root cause: the module that raised was never
written. They are recorded here for traceability and are resolved by the
continuation build (see status column).

| # | Command | Error | Root cause | Severity | Fix | Status |
|---|---|---|---|---|---|---|
| 1 | `python -c "from aegisflight.simulator import FlightSimulator"` | `ModuleNotFoundError: aegisflight.simulator.flight` | `simulator/__init__.py` re-exports from `.flight`, which the crash interrupted before creation | P0 (crash point) | Implement `simulator/flight.py` | ✅ FIXED |
| 2 | `python -m pytest -q` | collected 0 items (no tests, no failures) | `tests/**` were empty skeleton dirs | P1 | Add unit/integration/e2e suites | ✅ FIXED |
| 3 | `python -c "from aegisflight.cli.main import main"` | `ModuleNotFoundError: aegisflight.cli.main` | `pyproject` declares `aegis = aegisflight.cli.main:main` but `cli/` was empty | P0 | Implement `cli/main.py` | ✅ FIXED |
| 4 | `pip install -e .` (editable) | package not importable | Package had never been installed into the venv | P0 | `pip install -e .` (done during recovery) | ✅ FIXED |

## Verification method

After each subsystem was implemented it was exercised directly (import, unit
test, then the end-to-end pipeline via `python -m aegisflight.cli ...`) before
moving on. The "Status" column reflects execution-verified resolution, not a
code read. Final clean-slate validation is recorded in
`docs/installation.md` and reproduced by `scripts/validate.py`.
