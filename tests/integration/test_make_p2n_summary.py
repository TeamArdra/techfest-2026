"""make_p2n_summary.py: pre-onset GNSS false alarms count both P3.4 wordings; detection stays 'lost'-only."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sitl" / "make_p2n_summary.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("make_p2n_summary", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_trial(tmp: Path, rows: list[dict]) -> Path:
    manifest = {
        "trial_id": "t1", "trial_index": 1, "frames_modified": 4,
        "parameters": {"onset_s": 10.0, "duration_s": 5.0, "fix_type": 0, "satellites_visible": 0},
        "ids_summary": {"relay_stats": {"hook_errors": 0}},
        "actual_effect": {"frames_modified": 4, "fix_type_deltas_written": [1],
                          "satellites_visible_deltas_written": [1]},
    }
    mp = tmp / "t1.manifest.json"
    mp.write_text(json.dumps(manifest))
    (tmp / "t1.ids_decisions.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return mp


def _row(t: float, ev: str | None) -> dict:
    return {"t": t, "threat": ev is not None, "type": "dos" if ev else "none", "evidence": [ev] if ev else []}


def test_pre_onset_gnss_false_alarms_count_both_wordings(tmp_path: Path) -> None:
    mod = _load_module()
    rows = [
        _row(1.0, "GNSS fix never acquired: fix_type=0, satellites=0 for 5 decisions "
                  "(no valid fix since monitoring began)"),
        _row(2.0, "GNSS fix lost: fix_type=0, satellites=0 for 5 decisions"),
        _row(3.0, None),
        _row(12.0, "GNSS fix lost: fix_type=0, satellites=0 for 5 decisions"),
    ]
    t = mod.load_trial(_write_trial(tmp_path, rows))
    assert t["fa_gnss_pre"] == 2
    assert t["fa_pre"] == 2
    assert t["detected"] is True
    assert t["values_ok"] is True


def test_in_window_never_acquired_is_not_a_detection(tmp_path: Path) -> None:
    mod = _load_module()
    rows = [
        _row(1.0, None),
        _row(12.0, "GNSS fix never acquired: fix_type=0, satellites=0 for 5 decisions "
                   "(no valid fix since monitoring began)"),
    ]
    t = mod.load_trial(_write_trial(tmp_path, rows))
    assert t["detected"] is False
    assert t["n_win_gnss"] == 0
