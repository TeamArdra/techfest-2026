# Clean-environment install and test run, 2026-10-29

**Environment: host Windows 11, disposable clone + disposable venv; claim: the documented install works from a clean checkout of the committed branch.** Not a Linux / macOS / container run (no Dockerfile exists in the repository; Docker Desktop was present but not used).

Procedure (`clean_install.sh`, arguments: scratch dir, repo path, Python 3.13 interpreter):
1. `git clone --branch sprint/hardware-free-20261029 <repo> <scratch>/clean/repo`, which gives only committed content, HEAD `9944a57b02bfef8bd6e64f1b696b024af3cbc071`, 0 modified files. (A per-command `-c safe.directory=*` was needed because the repo is owned by another Windows account; global git config was not changed.)
2. `python -m venv <scratch>/clean/venv` with CPython 3.13.15. The host `.venv` and global packages were not touched.
3. `pip install -e ".[dev]"` (QUICKSTART step 1): exit 0. Floor-pinned dependencies resolved **newer** than the host `.venv`: numpy 2.5.4 (host 2.5.3), pandas 3.1.0 (3.0.6), fastapi 0.162.0, pydantic 2.14.1, pytest 9.2.0, ruff 0.17.3 (host 0.16.10); scikit-learn 1.9.1, scipy 1.18.1, pymavlink 2.4.50, joblib 1.6.0 unchanged.
4. `pytest -p no:cacheprovider -o addopts= -q -rs` in the clone: **899 passed, 11 skipped, 0 failed** (140 s). The host run (same commit plus uncommitted docs): 907 passed, 3 skipped, 0 failed (counted from the progress output; the summary line is suppressed by the doubled `-q`). The 8 extra skips are tests that need git-ignored inputs absent from a fresh clone (`models/isoforest.joblib`, bench captures 007/008/009, `data/sitl/raw/benign_001.tlog`), reported as skips with those reasons, not hidden; the 3 PTY skips also occur on the host.
5. `ruff check src tests scripts backend`: All checks passed (ruff 0.17.3).

Not done in this run: `aegis train` (the committed repo has no model; ML-dependent benchmark reproduction needs it), `aegis benchmark`, the frontend build in the clone. The host Stage-1 regression is covered by `artifacts/validation/baseline_comparison_20261029/` (AegisFlight counts 6535 / 4 / 16826 / 65 reproduced by the script on the host tree). Re-run: `bash artifacts/validation/clean_install_20261029/clean_install.sh <scratch> <repo> <python>`.
