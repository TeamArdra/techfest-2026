#!/bin/bash
# Disposable clean-install check: fresh clone of the committed branch + fresh venv. Host environments untouched.
set -x
SP="$1"; REPO="$2"; PY="$3"
rm -rf "$SP/clean/repo" "$SP/clean/venv"
mkdir -p "$SP/clean"
date -u +%FT%TZ
git -c safe.directory="*" clone --quiet --branch sprint/hardware-free-20261029 "$REPO" "$SP/clean/repo"
cd "$SP/clean/repo" || exit 9; git rev-parse HEAD && git status --short | wc -l
"$PY" --version
"$PY" -m venv "$SP/clean/venv"
VP="$SP/clean/venv/Scripts/python.exe"
"$VP" -m pip install --quiet --disable-pip-version-check -e ".[dev]" ; echo "pip exit $?"
"$VP" -m pip freeze | grep -i -E "^(numpy|pandas|scipy|scikit-learn|pymavlink|pytest|ruff|fastapi|pydantic|joblib)=="
ls models 2>&1 | head -3
date -u +%FT%TZ
"$VP" -m pytest -q -p no:cacheprovider 2>&1 | tail -15; echo "pytest done"
date -u +%FT%TZ
"$VP" -m ruff check src tests scripts backend; echo "ruff exit $?"
