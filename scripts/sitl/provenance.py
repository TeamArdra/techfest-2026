"""Provenance block for SITL evidence (evidence-claims rule 5) + backfill for older manifests.

    from provenance import collect                      # used by record_flight.py / live_ids.py
    .venv/Scripts/python.exe scripts/sitl/provenance.py --backfill data/sitl/raw/benign_001.json ...

``collect`` records: aegisflight git commit + dirty flag (uncommitted changes under
src/, scripts/, configs/), python and key package versions, SHA-256 of the model and of
the concatenated configs, command line, UTC time. Backfilled blocks carry
``"backfilled": true`` -- they describe the repo at backfill time, NOT at capture time, and
must be read that way.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:  # noqa: BLE001 - provenance must never break a run
        return "unknown"


def collect(model: str = "models/isoforest.joblib", configs: str = "configs", **extra) -> dict:
    cfg_hash = hashlib.sha256()
    for p in sorted(Path(configs).glob("*.yaml")):
        cfg_hash.update(p.name.encode() + p.read_bytes())
    pk = {}
    for name in ("pymavlink", "numpy", "scikit-learn", "joblib", "scipy"):
        try:
            pk[name] = md.version(name)
        except md.PackageNotFoundError:
            pk[name] = None
    dirty = [ln for ln in _git("status", "--porcelain", "--", "src", "scripts", "configs").splitlines() if ln]
    return {
        "collected_utc": datetime.now(UTC).isoformat(),
        "aegisflight_commit": _git("rev-parse", "HEAD"),
        "working_tree_dirty": bool(dirty),
        "dirty_paths_count": len(dirty),
        "python": sys.version.split()[0],
        "packages": pk,
        "model_sha256": sha256_file(model) if Path(model).exists() else None,
        "configs_sha256": cfg_hash.hexdigest(),
        "command_line": " ".join(sys.argv),
        **extra,
    }


def backfill(manifest: Path) -> None:
    d = json.loads(manifest.read_text())
    if "provenance" in d:
        return
    tl = manifest.with_suffix(".tlog")
    if not tl.exists():
        tl = Path("data/sitl/raw") / manifest.with_suffix(".tlog").name
    prov = collect(backfilled=True,
                   note="backfilled after the fact: commit/dirty/versions describe the repo at backfill time, not capture time")
    prov["tlog_sha256"] = sha256_file(tl) if tl.exists() else None
    d["provenance"] = prov
    manifest.write_text(json.dumps(d, indent=2))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backfill", nargs="+", required=True)
    a = ap.parse_args(argv)
    for m in a.backfill:
        backfill(Path(m))
        print("backfilled", m)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
