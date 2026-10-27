"""Before/after replay identity check for the estimator gate v2 (aegis-validation, 2026-10-26).

Runs ``scripts/ardupilot/replay_ap_tlog.py --no-ml --json`` on every listed tlog twice, ONE PROCESS AT A TIME:

* before = clean ``HEAD`` source, via ``PYTHONPATH=<before_src>`` (a detached worktree of HEAD; its own
  ``configs/`` is used because ``aegisflight.config.CONFIG_DIR`` resolves next to the imported package);
* after  = this working tree (``PYTHONPATH`` removed from the environment).

The two JSON outputs are compared byte for byte. Nothing is fed back into any detector; the replay script and its
inputs are not modified. Run from anywhere; subprocesses run with the repository root as the working directory so the
``tlog`` field in every JSON is the same relative path on both sides.

    .venv/Scripts/python.exe artifacts/validation/estimator_gate_v2/tools/replay_identity.py \
        --before-src <wt_head>/src --raw-dir <scratch>/identity_raw \
        --out artifacts/validation/estimator_gate_v2/replay_identity
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
REPLAY = "scripts/ardupilot/replay_ap_tlog.py"
DEFAULT_GLOBS = ("data/ardupilot/raw/*.tlog", "data/sitl/raw/benign_*.tlog")
DEFAULT_FILES = ("data/hardware/raw/telemetry_radio_005.tlog", "data/hardware/raw/telemetry_radio_007.tlog")
# committed outputs that the "after" run must reproduce (working-copy bytes, and the committed blob modulo EOL)
COMMITTED = {"data/hardware/raw/telemetry_radio_005.tlog": "artifacts/hardware/replay_p1p2_005/replay_noml.json",
             "data/hardware/raw/telemetry_radio_007.tlog": "artifacts/hardware/replay_p1p2_007/replay_noml.json"}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def git(*args: str, cwd: Path = REPO) -> bytes:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True).stdout


def env_for(before_src: str | None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    if before_src:
        env["PYTHONPATH"] = before_src
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def probe_import(before_src: str | None) -> dict[str, str]:
    code = "import aegisflight, aegisflight.config as c; print(aegisflight.__file__); print(c.CONFIG_DIR)"
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env_for(before_src), capture_output=True,
                         text=True, check=True).stdout.splitlines()
    return {"aegisflight_file": out[0], "config_dir": out[1]}


def run_one(tlog: str, out_json: Path, before_src: str | None) -> tuple[int, float]:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    if out_json.exists():
        out_json.unlink()
    t0 = time.monotonic()
    p = subprocess.run([sys.executable, "-W", "ignore", REPLAY, tlog, "--no-ml", "--json", str(out_json)],
                       cwd=REPO, env=env_for(before_src), capture_output=True)
    return p.returncode, round(time.monotonic() - t0, 2)


def redactor(**roots: Path):
    """Replace local absolute paths (repo, worktree, scratch, home) by placeholders: no user profile in artifacts."""
    pairs = sorted(((str(p.resolve()), f"<{k}>") for k, p in roots.items()), key=lambda kv: -len(kv[0]))

    def red(s: str) -> str:
        for forms in pairs:
            for src in {forms[0], forms[0].replace("\\", "/")}:
                s = s.replace(src, forms[1])
        return s
    return red


def counts(path: Path) -> dict | None:
    if not path.exists():
        return None
    d = json.loads(path.read_text(encoding="utf-8"))
    return {k: d.get(k) for k in ("decisions", "threat_decisions", "alert_decisions", "alert_types", "ml_enabled")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--before-src", required=True, help="src/ of a clean HEAD worktree")
    ap.add_argument("--raw-dir", required=True, help="where the per-file before/after JSON outputs go")
    ap.add_argument("--out", required=True, help="where identity.json / identity.md go")
    a = ap.parse_args(argv)

    files = sorted({p.relative_to(REPO).as_posix() for g in DEFAULT_GLOBS for p in REPO.glob(g)})
    files += [f for f in DEFAULT_FILES if (REPO / f).exists()]
    raw, out = Path(a.raw_dir), Path(a.out)
    before_root = Path(a.before_src).resolve().parent
    red = redactor(wt_head=before_root, repo=REPO, raw=raw, home=Path.home())

    prov = {
        "generated_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "command": red(" ".join(["python", *sys.argv])),
        "head": git("rev-parse", "HEAD").decode().strip(),
        "src_configs_diff_sha256_start": sha256(git("diff", "HEAD", "--", "src", "configs")),
        "before_worktree_head": git("rev-parse", "HEAD", cwd=before_root).decode().strip(),
        "before_worktree_dirty_files": len(git("status", "--porcelain", cwd=before_root).splitlines()),
        "before_import": {k: red(v) for k, v in probe_import(a.before_src).items()},
        "after_import": {k: red(v) for k, v in probe_import(None).items()},
        "python": platform.python_version(),
        "platform": platform.platform(),
        "replay_script_sha256": sha256((REPO / REPLAY).read_bytes()),
        "ml": "off (--no-ml)",
        "execution": "sequential, one replay process at a time (before then after, per file)",
    }

    rows = []
    for tlog in files:
        b_path, a_path = raw / "before" / (Path(tlog).name + ".json"), raw / "after" / (Path(tlog).name + ".json")
        rc_b, s_b = run_one(tlog, b_path, a.before_src)
        rc_a, s_a = run_one(tlog, a_path, None)
        bb = b_path.read_bytes() if b_path.exists() else b""
        ab = a_path.read_bytes() if a_path.exists() else b""
        row = {"tlog": tlog, "tlog_sha256": sha256((REPO / tlog).read_bytes()), "tlog_bytes": (REPO / tlog).stat().st_size,
               "exit_before": rc_b, "exit_after": rc_a, "seconds_before": s_b, "seconds_after": s_a,
               "before_sha256": sha256(bb), "after_sha256": sha256(ab),
               "identical": bool(bb) and rc_b == 0 and rc_a == 0 and bb == ab,
               "before": counts(b_path), "after": counts(a_path)}
        if tlog in COMMITTED:
            c = REPO / COMMITTED[tlog]
            blob = git("show", f"HEAD:{COMMITTED[tlog]}")
            row["committed_artifact"] = COMMITTED[tlog]
            row["after_equals_committed_working_copy_bytes"] = ab == c.read_bytes()
            row["after_equals_committed_blob_modulo_eol"] = ab.replace(b"\r\n", b"\n") == blob.replace(b"\r\n", b"\n")
        rows.append(row)
        print(f"{'SAME' if row['identical'] else 'DIFF'}  {tlog}", flush=True)

    prov["src_configs_diff_sha256_end"] = sha256(git("diff", "HEAD", "--", "src", "configs"))
    n_same = sum(r["identical"] for r in rows)
    result = {"provenance": prov, "n_files": len(rows), "n_identical": n_same,
              "different": [r["tlog"] for r in rows if not r["identical"]], "files": rows}
    out.mkdir(parents=True, exist_ok=True)
    (out / "identity.json").write_text(json.dumps(result, indent=2), encoding="utf-8", newline="\n")

    lines = ["# Replay identity, before (HEAD) vs after (estimator gate v2), ML off",
             "",
             f"Generated by `tools/replay_identity.py` at {prov['generated_utc']}. Environment: `REPLAY` (ArduPilot SITL "
             "captures, PX4 SITL captures, BENCH captures 005/007). Claim class: none (regression identity of the "
             "IDS output on benign/attacked recordings; not detection evidence).",
             "",
             f"**{n_same} / {len(rows)} identical** (byte-for-byte `replay_ap_tlog.py --no-ml --json` output).",
             f"HEAD `{prov['head']}`; `git diff HEAD -- src configs` sha256 `{prov['src_configs_diff_sha256_start']}` "
             f"at start, `{prov['src_configs_diff_sha256_end']}` at end.",
             "",
             "| tlog | decisions | threats | alerts | before = after | output sha256 (after) |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        c = r["after"] or {}
        lines.append(f"| `{r['tlog']}` | {c.get('decisions')} | {c.get('threat_decisions')} | "
                     f"{c.get('alert_decisions')} | {'identical' if r['identical'] else '**DIFFERENT**'} | "
                     f"`{r['after_sha256'][:16]}…` |")
    for r in rows:
        if "committed_artifact" in r:
            lines.append("")
            lines.append(f"- `{r['tlog']}` after vs committed `{r['committed_artifact']}`: working-copy bytes "
                         f"{'identical' if r['after_equals_committed_working_copy_bytes'] else 'DIFFERENT'}; "
                         f"committed blob modulo line endings "
                         f"{'identical' if r['after_equals_committed_blob_modulo_eol'] else 'DIFFERENT'}.")
    (out / "identity.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"{n_same}/{len(rows)} identical -> {out}")
    return 0 if n_same == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
