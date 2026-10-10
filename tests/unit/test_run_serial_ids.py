"""Tests for the receive-only serial runner (``scripts/hardware/run_serial_ids.py``). Loopback socket only."""

from __future__ import annotations

import json
import signal
import socket
import sys
import threading
import time
from pathlib import Path

import pytest
from pymavlink.dialects.v20 import common as mav

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "hardware"))

import run_serial_ids  # noqa: E402


def _frames(n: int) -> list[bytes]:
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    out = []
    for i in range(n):
        m.seq = (2 * i) & 0xFF
        out.append(bytes(m.heartbeat_encode(2, 3, 81, 0, 4, 3).pack(m)))
        m.seq = (2 * i + 1) & 0xFF
        out.append(bytes(m.attitude_encode(i * 100, 0.01, 0.02, 0.03, 0.0, 0.0, 0.0).pack(m)))
    return out


class Device:
    """A loopback 'serial device': accepts one client and streams frames at ~10 per second."""

    def __init__(self, frames: list[bytes]) -> None:
        self.frames = frames
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.srv.settimeout(10)
        self.port = self.srv.getsockname()[1]
        self.received = 0
        self.th = threading.Thread(target=self._run, daemon=True)
        self.th.start()

    def _run(self) -> None:
        try:
            conn, _ = self.srv.accept()
        except OSError:
            return
        conn.settimeout(0.01)
        try:
            for f in self.frames:
                conn.sendall(f)
                try:
                    self.received += len(conn.recv(4096))  # anything the monitor wrote would land here
                except (TimeoutError, OSError):
                    pass
                time.sleep(0.1)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.srv.close()
        self.th.join(timeout=3)


@pytest.fixture
def restore_signals():
    saved = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    yield
    for s, h in saved.items():
        signal.signal(s, h)


def test_runs_receive_only_writes_outputs_and_exits_zero(tmp_path, restore_signals):
    dev = Device(_frames(20))
    rc = run_serial_ids.main(["--port", f"socket://127.0.0.1:{dev.port}", "--allow-url", "--out-dir", str(tmp_path),
                              "--seconds", "4", "--health-interval", "1"])
    dev.close()
    assert rc == 0
    s = json.loads((tmp_path / "summary.json").read_text())
    assert s["exit_code"] == 0 and s["passive_check"] == {"bytes_sent": 0, "write_errors": 0, "passed": True}
    assert dev.received == 0  # the monitor wrote nothing to the device
    assert s["transport"]["frames_received"] >= 20 and s["transport"]["crc_rejects"] == 0
    assert s["source"]["bad_frames"] == 0 and s["ml_enabled"] is False
    assert s["decisions"] > 0 and s["hash_chain"]["ok"] is True
    assert (tmp_path / "alerts.jsonl").exists() and (tmp_path / "events.sqlite").exists()
    assert len((tmp_path / "health.jsonl").read_text().splitlines()) >= 2


def test_url_port_without_allow_url_is_refused(tmp_path, restore_signals):
    rc = run_serial_ids.main(["--port", "socket://127.0.0.1:1", "--out-dir", str(tmp_path), "--seconds", "1"])
    assert rc == 2


def test_unopenable_port_with_no_reconnect_exits_2(tmp_path, restore_signals):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    rc = run_serial_ids.main(["--port", f"socket://127.0.0.1:{port}", "--allow-url", "--no-reconnect",
                              "--out-dir", str(tmp_path), "--seconds", "1"])
    assert rc == 2


def test_dead_from_start_link_still_ticks_and_reports_silence(tmp_path, restore_signals):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    rc = run_serial_ids.main(["--port", f"socket://127.0.0.1:{port}", "--allow-url", "--out-dir", str(tmp_path),
                              "--seconds", "3", "--reconnect-interval", "0.5"])
    assert rc == 0
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["decisions"] > 0 and summary["transport"]["open_failures"] >= 2
    assert summary["transport"]["frames_received"] == 0 and summary["passive_check"]["passed"] is True


def test_refuses_to_overwrite_a_previous_run(tmp_path, restore_signals):
    (tmp_path / "events.sqlite").write_bytes(b"precious evidence")
    rc = run_serial_ids.main(["--port", "socket://127.0.0.1:1", "--allow-url", "--out-dir", str(tmp_path), "--seconds", "1"])
    assert rc == 2 and (tmp_path / "events.sqlite").read_bytes() == b"precious evidence"
