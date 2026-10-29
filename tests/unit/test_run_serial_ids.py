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


def _tlog_frames(path: Path) -> list[bytes]:
    """Split a repo tlog (8-byte big-endian microseconds + one MAVLink 2 frame, repeated) into frames."""
    raw, out, i = path.read_bytes(), [], 0
    while i < len(raw):
        i += 8
        assert raw[i] == 0xFD
        n = 12 + raw[i + 1] + (13 if raw[i + 2] & 1 else 0)
        out.append(raw[i:i + n])
        i += n
    return out


def test_tlog_tees_the_clean_downlink_and_stays_receive_only(tmp_path, restore_signals):
    sent = _frames(20)
    dev = Device(sent)
    tlog = tmp_path / "raw" / "link.tlog"
    rc = run_serial_ids.main(["--port", f"socket://127.0.0.1:{dev.port}", "--allow-url", "--out-dir", str(tmp_path / "run"),
                              "--seconds", "5", "--health-interval", "1", "--tlog", str(tlog)])
    dev.close()
    assert rc == 0 and dev.received == 0
    s = json.loads((tmp_path / "run" / "summary.json").read_text())
    assert s["passive_check"]["passed"] is True and s["tlog"] == str(tlog)
    got = _tlog_frames(tlog)
    # The transport purges stale input when it opens, so a loopback Device that streams on accept can lose its first
    # 1-3 frames (documented as latent in docs/GPS_WORKSTREAM_PROGRESS.md; ~50 % of isolated runs on 2026-10-29, also on
    # the unmodified HEAD). The invariant that matters is unchanged: the tee holds exactly the frames the transport
    # received, as one contiguous run of the stream.
    head_lost = next((k for k in range(4) if got == sent[k:k + len(got)]), None)
    assert head_lost is not None and len(got) == s["transport"]["frames_received"] >= 20


def test_existing_tlog_is_never_overwritten(tmp_path, restore_signals, capsys):
    tlog = tmp_path / "link.tlog"
    tlog.write_bytes(b"previous capture")
    rc = run_serial_ids.main(["--port", "socket://127.0.0.1:1", "--allow-url", "--out-dir", str(tmp_path / "run"),
                              "--seconds", "1", "--tlog", str(tlog)])
    assert rc == 2 and tlog.read_bytes() == b"previous capture"
    assert not (tmp_path / "run" / "events.sqlite").exists()  # refused before anything was created
    assert "already exists" in capsys.readouterr().err


def test_telemetry_coverage_is_persisted_in_summary_and_health(tmp_path, restore_signals):
    """A coverage condition (P1/P2: never-received position is not an alert by default) must still be
    persisted somewhere the operator can read: summary.json and every health.jsonl line."""
    dev = Device(_frames(20))  # HEARTBEAT + ATTITUDE only: no GLOBAL_POSITION_INT, no GPS_RAW_INT
    rc = run_serial_ids.main(["--port", f"socket://127.0.0.1:{dev.port}", "--allow-url", "--out-dir", str(tmp_path),
                              "--seconds", "4", "--health-interval", "1"])
    dev.close()
    assert rc == 0
    cov = json.loads((tmp_path / "summary.json").read_text())["telemetry_coverage"]
    assert cov["heartbeat_seen"] is True
    assert cov["global_position_seen"] is False and cov["gps_raw_seen"] is False
    assert cov["decisions_without_global_position"] > 0
    lines = [json.loads(ln) for ln in (tmp_path / "health.jsonl").read_text().splitlines()]
    assert all("telemetry_coverage" in ln for ln in lines)
    assert lines[-1]["telemetry_coverage"]["global_position_seen"] is False


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
                              "--seconds", "6", "--reconnect-interval", "0.5"])
    assert rc == 0
    summary = json.loads((tmp_path / "summary.json").read_text())
    # a refused loopback connect can take ~1 s on Windows, so allow 6 s for two failed opens
    assert summary["decisions"] > 0 and summary["transport"]["open_failures"] >= 2
    assert summary["transport"]["frames_received"] == 0 and summary["passive_check"]["passed"] is True


def test_refuses_to_overwrite_a_previous_run(tmp_path, restore_signals):
    (tmp_path / "events.sqlite").write_bytes(b"precious evidence")
    rc = run_serial_ids.main(["--port", "socket://127.0.0.1:1", "--allow-url", "--out-dir", str(tmp_path), "--seconds", "1"])
    assert rc == 2 and (tmp_path / "events.sqlite").read_bytes() == b"precious evidence"


# ---- telemetry_coverage completeness (appended 2026-10-20, aegis-validation; lead-authorised) ---------------- #

def _frames_with_position(n: int) -> list[bytes]:
    """Per group: HEARTBEAT, GLOBAL_POSITION_INT, GPS_RAW_INT (3D fix, 10 sats), ATTITUDE; one sequence counter."""
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    out = []
    for i in range(n):
        for msg in (m.heartbeat_encode(2, 3, 81, 0, 4, 3),
                    m.global_position_int_encode(i * 100, 129_000_000, 775_000_000, 900_000, 0, 0, 0, 0, 0),
                    m.gps_raw_int_encode(i * 100_000, 3, 129_000_000, 775_000_000, 900_000, 100, 100, 0, 0, 10),
                    m.attitude_encode(i * 100, 0.01, 0.02, 0.03, 0.0, 0.0, 0.0)):
            m.seq = (m.seq + 1) & 0xFF
            out.append(bytes(msg.pack(m)))
    return out


def _run_for_coverage(tmp_path, port: int, seconds: str, *extra: str) -> tuple[int, dict, list[dict]]:
    rc = run_serial_ids.main(["--port", f"socket://127.0.0.1:{port}", "--allow-url", "--out-dir", str(tmp_path),
                              "--seconds", seconds, "--health-interval", "1", *extra])
    summary = json.loads((tmp_path / "summary.json").read_text())
    health = [json.loads(ln) for ln in (tmp_path / "health.jsonl").read_text().splitlines()]
    return rc, summary, health


def _assert_health_coverage_shape(health: list[dict]) -> None:
    assert health, "no health lines"
    prev = 0
    for ln in health:
        cov = ln["telemetry_coverage"]
        assert set(cov) == {"heartbeat_seen", "global_position_seen", "gps_raw_seen",
                            "decisions_without_global_position"}
        assert 0 <= cov["decisions_without_global_position"] <= ln["decisions"]
        assert cov["decisions_without_global_position"] >= prev  # a running count, never decreases
        prev = cov["decisions_without_global_position"]


def test_telemetry_coverage_counts_every_decision_without_position(tmp_path, restore_signals):
    """HEARTBEAT + ATTITUDE only: GLOBAL_POSITION_INT is never received, so EVERY decision counts as one
    without position (count == decisions), and heartbeat_seen is carried on every health line."""
    dev = Device(_frames(20))
    rc, s, health = _run_for_coverage(tmp_path, dev.port, "4")
    dev.close()
    assert rc == 0 and s["decisions"] > 0
    cov = s["telemetry_coverage"]
    assert cov["decisions_without_global_position"] == s["decisions"]
    assert cov["heartbeat_seen"] is True and cov["global_position_seen"] is False and cov["gps_raw_seen"] is False
    _assert_health_coverage_shape(health)
    assert all(isinstance(ln["telemetry_coverage"]["heartbeat_seen"], bool) for ln in health)
    assert health[-1]["telemetry_coverage"]["heartbeat_seen"] is True
    assert all(ln["telemetry_coverage"]["decisions_without_global_position"] == ln["decisions"] for ln in health)


def test_telemetry_coverage_positive_when_position_and_gps_raw_arrive(tmp_path, restore_signals):
    """GLOBAL_POSITION_INT and GPS_RAW_INT both flow: the run ends with every flag True and no coverage alert.
    Decisions before the first position frame (the monitor ticks from start, before the device's first byte)
    may count as without position, so the count is only bounded, not zero."""
    dev = Device(_frames_with_position(10))  # 40 frames, ~4 s at 10 frames/s
    rc, s, health = _run_for_coverage(tmp_path, dev.port, "4")
    dev.close()
    assert rc == 0 and s["decisions"] > 0 and s["transport"]["crc_rejects"] == 0
    cov = s["telemetry_coverage"]
    assert cov["heartbeat_seen"] is True and cov["global_position_seen"] is True and cov["gps_raw_seen"] is True
    assert cov["decisions_without_global_position"] < s["decisions"]
    _assert_health_coverage_shape(health)
    assert health[-1]["telemetry_coverage"]["global_position_seen"] is True


def test_dead_link_coverage_is_all_false_and_heartbeat_alert_waits_for_the_timeout(tmp_path, restore_signals):
    """Nothing ever arrives: every flag False, count == decisions, and the only alert family is the
    never-received heartbeat, raised only once monitoring time exceeds heartbeat_timeout_s (no t=0 alert).
    Loopback socket, NOT hardware: this does not validate the physical monitor-start behaviour."""
    s0 = socket.socket()
    s0.bind(("127.0.0.1", 0))
    port = s0.getsockname()[1]
    s0.close()  # nothing listens: the transport keeps retrying, the source still ticks from start
    rc, s, health = _run_for_coverage(tmp_path, port, "5", "--reconnect-interval", "0.5")
    assert rc == 0 and s["transport"]["frames_received"] == 0 and s["decisions"] > 0
    cov = s["telemetry_coverage"]
    assert cov == {"heartbeat_seen": False, "global_position_seen": False, "gps_raw_seen": False,
                   "decisions_without_global_position": s["decisions"]}
    _assert_health_coverage_shape(health)
    hb_timeout = run_serial_ids.load_config().detector["protocol"]["heartbeat_timeout_s"]
    alerts = [json.loads(ln) for ln in (tmp_path / "alerts.jsonl").read_text().splitlines()]
    assert alerts, "a never-received heartbeat for > heartbeat_timeout_s must alert"
    assert all(al["t"] > hb_timeout for al in alerts)
    assert alerts[0]["type"] == "DOS"
    assert any(e.startswith("heartbeat stale (never received") for e in alerts[0]["evidence"])
    assert all("GPS dropout" not in e for al in alerts for e in al["evidence"])  # position: coverage, not alert


def test_coverage_helper_is_none_before_any_decision():
    """No decision yet (``last_frame`` None): presence is unknown, reported as None, never as False."""
    pipe = run_serial_ids.IDSPipeline(run_serial_ids.load_config(), model_path=None, firmware_dir=None)
    assert pipe.last_frame is None
    assert run_serial_ids._coverage(pipe, 0) == {"heartbeat_seen": None, "global_position_seen": None,
                                                 "gps_raw_seen": None, "decisions_without_global_position": 0}


# --- navigation_health: passive, vehicle-stated estimator / GPS health (SYNTHETIC frames, loopback socket) --- #

def _frames_with_nav_state(n: int, ekf_flags: int, gps_health_bit: int) -> list[bytes]:
    """Per group: HEARTBEAT, GPS_RAW_INT (3D fix, 7 sats, eph 809), GLOBAL_POSITION_INT, SYS_STATUS (GPS sensor
    present; health bit ``gps_health_bit``), EKF_STATUS_REPORT (``ekf_flags``), ATTITUDE. Synthetic, not hardware."""
    from pymavlink.dialects.v20 import ardupilotmega as apm

    m = apm.MAVLink(None, srcSystem=1, srcComponent=1)
    out = []
    for i in range(n):
        for msg in (m.heartbeat_encode(2, 3, 81, 0, 4, 3),
                    m.gps_raw_int_encode(i * 100_000, 3, 129_000_000, 775_000_000, 900_000, 809, 232, 0, 0, 7),
                    m.global_position_int_encode(i * 100, 129_000_000, 775_000_000, 900_000, 0, 0, 0, 0, 0),
                    m.sys_status_encode(0x20, 0x20, gps_health_bit, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                    m.ekf_status_report_encode(ekf_flags, 0.0, 0.0, 0.0, 0.0, 0.0),
                    m.attitude_encode(i * 100, 0.01, 0.02, 0.03, 0.0, 0.0, 0.0)):
            m.seq = (m.seq + 1) & 0xFF
            out.append(bytes(msg.pack(m)))
    return out


def test_navigation_health_reports_a_stated_no_solution_and_unhealthy_gps(tmp_path, restore_signals):
    """The vehicle says: 3D fix, GPS-healthy bit clear, EKF in constant-position mode (0xa7, as on the powered-on
    bench vehicle). The runner must say so in summary.json and every health line, without raising an alert for it."""
    dev = Device(_frames_with_nav_state(10, ekf_flags=0xA7, gps_health_bit=0))
    rc, s, health = _run_for_coverage(tmp_path, dev.port, "4")
    dev.close()
    assert rc == 0 and s["decisions"] > 0 and s["passive_check"]["passed"] is True
    nh = s["navigation_health"]
    assert nh["decisions"] == s["decisions"]
    assert 0 < nh["flagged_decisions"]["ekf_no_horizontal_solution"] <= s["decisions"]
    assert 0 < nh["flagged_decisions"]["gps_sensor_unhealthy"] <= s["decisions"]
    last = nh["last"]
    assert last["horizontal_solution"] is False and last["gps_healthy"] is False
    assert last["ekf_flags"] == 0xA7 and last["fix_type"] == 3 and last["satellites"] == 7 and last["hdop"] == 8.09
    assert last["quality_flags"] == ["ekf_no_horizontal_solution", "gps_sensor_unhealthy"]
    assert health and all("navigation_health" in ln for ln in health)
    # the pinned coverage block is untouched and the new block adds no alert path
    assert set(s["telemetry_coverage"]) == {"heartbeat_seen", "global_position_seen", "gps_raw_seen",
                                            "decisions_without_global_position"}
    assert "ekf_no_horizontal_solution" not in json.dumps(s["alert_types"])


def test_navigation_health_is_quiet_for_a_stated_horizontal_solution_and_healthy_gps(tmp_path, restore_signals):
    dev = Device(_frames_with_nav_state(10, ekf_flags=0x1F, gps_health_bit=0x20))
    rc, s, _ = _run_for_coverage(tmp_path, dev.port, "4")
    dev.close()
    assert rc == 0 and s["decisions"] > 0
    nh = s["navigation_health"]
    assert nh["flagged_decisions"] == {"ekf_no_horizontal_solution": 0, "gps_sensor_unhealthy": 0}
    assert nh["last"]["horizontal_solution"] is True and nh["last"]["gps_healthy"] is True
    assert nh["last"]["quality_flags"] == []


def test_navigation_health_is_unknown_not_false_when_the_link_never_sends_the_messages(tmp_path, restore_signals):
    dev = Device(_frames(20))  # HEARTBEAT + ATTITUDE only
    rc, s, _ = _run_for_coverage(tmp_path, dev.port, "4")
    dev.close()
    assert rc == 0 and s["decisions"] > 0
    nh = s["navigation_health"]
    assert nh["flagged_decisions"] == {"ekf_no_horizontal_solution": 0, "gps_sensor_unhealthy": 0}
    assert nh["last"]["horizontal_solution"] is None and nh["last"]["gps_healthy"] is None
    assert nh["last"]["ekf_flags"] is None and nh["last"]["quality_flags"] == []
