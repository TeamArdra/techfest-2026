"""End-to-end tests for the live-telemetry application path (aegis-validation, 2026-10-20).

Written against the lead's interface contract ("Live application integration", 2026-10-20): ``SourceSpec`` in
``aegisflight.backend.sources``, ``LiveEngine(spec=...)``, and the ``/health``, ``/api/status``, ``/api/events``,
``/api/simulation/*`` and ``/ws/telemetry`` endpoints. Black-box: every assertion goes through ``LiveEngine`` and the
FastAPI app; no telemetry-core internals are touched.

Injection (documented, per the assignment): each test builds a ``LiveEngine(spec=..., db_path=<tmp>)`` and assigns
it to the module-level ``aegisflight.backend.app.engine`` BEFORE entering ``TestClient(app)``. The app's lifespan then
calls ``get_engine().start()`` on that engine and ``stop()`` on exit. The previous value is restored afterwards, so the
module-scoped client in ``backend/tests/test_api.py`` (default SIM engine) is unaffected.

Environment of every result here: ``REPLAY`` (a tlog file, or bytes served over ``socket://127.0.0.1`` loopback) or
``SIM``. Nothing here is hardware and nothing is ever labelled ``BENCH``. Streams built in this file are SYNTHETIC
(pymavlink-encoded, made up here) and are named so. ``capture_007`` is the git-ignored bench capture
``data/hardware/raw/telemetry_radio_007.tlog`` replayed over loopback; those tests skip if the file is absent.
No serial port is opened; the loopback server binds 127.0.0.1 only and records every byte the client sends.

The acceptance matrix at the end of the file (clean input, malformed input, source failure, shutdown, run isolation,
``limit`` bounds, offline-replay parity, WebSocket ``run_id``) covers the lead's contract delta D1-D9 of 2026-10-20.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib.util
import json
import random
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pymavlink.dialects.v20 import common as mav
from starlette.websockets import WebSocketDisconnect

if importlib.util.find_spec("aegisflight.backend.sources") is None:  # pragma: no cover - before the lead's change lands
    pytest.skip("aegisflight.backend.sources not implemented yet", allow_module_level=True)

import aegisflight.backend.app as app_module  # noqa: E402
from aegisflight.backend import sources as backend_sources  # noqa: E402
from aegisflight.backend.engine import LiveEngine  # noqa: E402
from aegisflight.backend.sources import SourceSpec  # noqa: E402
from aegisflight.config import load_config  # noqa: E402
from aegisflight.logging import EventStore  # noqa: E402
from aegisflight.logging.store import GENESIS_HASH  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
TLOG_007 = REPO / "data" / "hardware" / "raw" / "telemetry_radio_007.tlog"
needs_007 = pytest.mark.skipif(not TLOG_007.exists(), reason="git-ignored bench capture 007 not present")
# offline reference: scripts/ardupilot/replay_ap_tlog.py --no-ml on the same capture (artifacts/hardware/replay_p1p2_007)
REF_007 = REPO / "artifacts" / "hardware" / "replay_p1p2_007" / "replay_noml.json"
sys.path.insert(0, str(REPO / "scripts" / "sitl"))
import tlog_stats  # noqa: E402

STALE_AFTER_S = load_config().detector["protocol"]["heartbeat_timeout_s"]
LINK_STATES = {"simulated", "waiting", "live", "stale", "disconnected", "ended", "error"}  # "error": delta D3
SIX_MESSAGES = {"HEARTBEAT", "SYS_STATUS", "GPS_RAW_INT", "GLOBAL_POSITION_INT", "VFR_HUD", "ATTITUDE"}
T0_UNIX = 1_792_000_000.0


# --------------------------------------------------------------------------- #
# SYNTHETIC MAVLink streams (made up here; never hardware)
# --------------------------------------------------------------------------- #

def synthetic_stream(seconds: float, *, fix: tuple[int, int] = (3, 10), hb: bool = True,
                     gpi: bool = True) -> list[tuple[float, bytes]]:
    """SYNTHETIC 10 Hz link, one sequence counter: HEARTBEAT/SYS_STATUS 1 Hz, GPS_RAW_INT 2 Hz with ``fix`` =
    (fix_type, satellites), GLOBAL_POSITION_INT/VFR_HUD 5 Hz (non-zero lat/lon), ATTITUDE 10 Hz; stationary."""
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    out: list[tuple[float, bytes]] = []
    for k in range(int(round(seconds * 10))):
        t = k / 10
        msgs = []
        if k % 10 == 0:
            if hb:
                msgs.append(m.heartbeat_encode(2, 3, 81, 0, 4, 3))
            msgs.append(m.sys_status_encode(0, 0, 0, 500, 16000, -1, 90, 0, 0, 0, 0, 0, 0))
        if k % 5 == 0:
            msgs.append(m.gps_raw_int_encode(int(t * 1e6), fix[0], 129_000_000, 775_000_000, 900_000, 100, 100,
                                             0, 0, fix[1]))
        if k % 2 == 0:
            if gpi:
                msgs.append(m.global_position_int_encode(int(t * 1000), 129_000_000, 775_000_000, 900_000, 0,
                                                         0, 0, 0, 0))
            msgs.append(m.vfr_hud_encode(0.0, 0.0, 28, 0, 900.0, 0.0))
        msgs.append(m.attitude_encode(int(t * 1000), 0.0, 0.0, 0.5, 0.0, 0.0, 0.0))
        for msg in msgs:
            m.seq = (m.seq + 1) & 0xFF
            out.append((t, bytes(msg.pack(m))))
    return out


def write_tlog(path: Path, frames: list[tuple[float, bytes]]) -> Path:
    """Repo tlog framing: big-endian uint64 unix microseconds, then the raw frame."""
    path.write_bytes(b"".join(struct.pack(">Q", int(round((T0_UNIX + t) * 1e6))) + f for t, f in frames))
    return path


def frames_007(max_t: float | None = None) -> list[tuple[float, bytes]]:
    rows = [(ts, fb) for ts, *_, fb in tlog_stats.iter_raw_frames(TLOG_007)]
    t0 = rows[0][0]
    out = [(ts - t0, fb) for ts, fb in rows]
    return [r for r in out if max_t is None or r[0] <= max_t]


# --------------------------------------------------------------------------- #
# loopback "serial device" (minimal copy of the pattern in tests/unit/test_run_serial_ids.py)
# --------------------------------------------------------------------------- #

class Device:
    """127.0.0.1 TCP server. Accepts ONE client, sends ``frames`` at original pace, then either holds the connection
    open for ``hold_s`` or (``drop=True``) closes the connection AND the listener (like an unplugged device). Every
    byte the client sends is counted in ``received`` (must stay 0: the app is receive-only). ``peer_closed`` is set
    when the CLIENT closes its end; ``peer_close_kind`` says how ("eof" = orderly FIN, "reset" = RST/abort).

    ``start``: if given, the stream (and its clock) waits after the accept until the event is set. Without it the
    first frames race the client's port open: pyserial's ``socket://`` ``open()`` ends with ``reset_input_buffer()``,
    which silently discards whatever already arrived, so a client scheduled late loses the head of the stream
    before the framer can count it. Tests that assert on the head of the stream (exact counts, or presence of a
    low-rate message such as the 1 Hz HEARTBEAT) use :func:`start_when_port_open`."""

    def __init__(self, frames: list[tuple[float, bytes]], *, hold_s: float = 0.0, drop: bool = False,
                 start: threading.Event | None = None) -> None:
        self.frames, self.hold_s, self.drop, self.start = frames, hold_s, drop, start
        self.received = 0
        self.sent = 0
        self.done_sending = threading.Event()
        self.peer_closed = threading.Event()
        self.peer_close_kind: str | None = None
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.srv.settimeout(15)
        self.port = self.srv.getsockname()[1]
        self._stop = threading.Event()
        self.th = threading.Thread(target=self._run, daemon=True)
        self.th.start()

    @property
    def url(self) -> str:
        return f"socket://127.0.0.1:{self.port}"

    def _peer_gone(self, kind: str) -> None:
        if not self.peer_closed.is_set():
            self.peer_close_kind = kind
            self.peer_closed.set()

    def _drain(self, conn: socket.socket) -> None:
        try:
            data = conn.recv(4096)
        except (TimeoutError, BlockingIOError):
            return  # nothing to read right now
        except OSError:  # connection reset / aborted by the client
            self._peer_gone("reset")
            return
        if not data:  # orderly close by the client (EOF)
            self._peer_gone("eof")
            return
        self.received += len(data)

    def _run(self) -> None:
        try:
            conn, _ = self.srv.accept()
        except OSError:
            return
        conn.settimeout(0.005)
        if self.start is not None:
            while not self.start.wait(0.02) and not self._stop.is_set():
                self._drain(conn)
        t0 = time.monotonic()
        try:
            for t, f in self.frames:
                while (wait := t0 + t - time.monotonic()) > 0 and not self._stop.is_set():
                    self._drain(conn)
                    time.sleep(min(wait, 0.02))
                if self._stop.is_set():
                    break
                conn.sendall(f)
                self.sent += 1
            self.done_sending.set()
            if not self.drop:
                end = time.monotonic() + self.hold_s
                while time.monotonic() < end and not self._stop.is_set():
                    self._drain(conn)
                    time.sleep(0.02)
            self._drain(conn)
        except OSError:  # sendall failed: the client has gone
            self._peer_gone("reset")
        finally:
            self.done_sending.set()
            with contextlib.suppress(OSError):
                conn.close()
            if self.drop:
                with contextlib.suppress(OSError):
                    self.srv.close()

    def close(self) -> None:
        self._stop.set()
        self.th.join(timeout=5)
        with contextlib.suppress(OSError):
            self.srv.close()


# --------------------------------------------------------------------------- #
# app / engine harness
# --------------------------------------------------------------------------- #

def make_engine(tmp_path: Path, spec: SourceSpec, db_name: str = "live.sqlite") -> LiveEngine:
    return LiveEngine(db_path=str(tmp_path / db_name), spec=spec)


def sample(client: TestClient, n: int, interval_s: float = 0.2) -> list[dict]:
    out = []
    for _ in range(n):
        time.sleep(interval_s)
        out.append(client.get("/api/status").json())
    return out


@contextlib.contextmanager
def serve(engine: LiveEngine) -> Iterator[TestClient]:
    """Inject ``engine`` as the app's module-level engine for the lifetime of one TestClient (see module docstring)."""
    saved = app_module.engine
    app_module.engine = engine
    try:
        with TestClient(app_module.app) as client:
            yield client
    finally:
        app_module.engine = saved


def poll(client: TestClient, pred: Callable[[dict], bool], timeout_s: float,
         interval_s: float = 0.1) -> tuple[dict, list[dict]]:
    """Poll /api/status until ``pred`` holds or ``timeout_s`` passes; return (last status, every status seen)."""
    seen: list[dict] = []
    end = time.monotonic() + timeout_s
    while True:
        st = client.get("/api/status").json()
        seen.append(st)
        if pred(st) or time.monotonic() > end:
            return st, seen
        time.sleep(interval_s)


def link(st: dict) -> dict:
    return st["link"]


def start_when_port_open(client: TestClient, dev: Device, timeout_s: float = 10.0) -> None:
    """Release ``dev``'s gated stream once /api/status reports the transport connected. ``connected`` is set only
    after pyserial's ``open()`` (and its input purge) has returned, so every byte sent afterwards reaches the framer."""
    assert dev.start is not None, "Device was built without a start gate"
    st, _ = poll(client, lambda s: (link(s).get("transport") or {}).get("connected") is True, timeout_s=timeout_s)
    assert (link(st).get("transport") or {}).get("connected") is True, link(st)
    dev.start.set()


def assert_live_implies_fresh(history: list[dict]) -> None:
    """Contract state rule: "live" only while the last frame is at most stale_after_s old."""
    for st in history:
        lk = link(st)
        assert lk["state"] in LINK_STATES, lk["state"]
        if lk["state"] == "live":
            assert lk["last_frame_age_s"] is not None and lk["last_frame_age_s"] <= lk["stale_after_s"], lk


def serial_spec(dev: Device) -> SourceSpec:
    return SourceSpec(kind="serial", port=dev.url, allow_url=True)


def replay_spec(tlog: Path) -> SourceSpec:
    return SourceSpec(kind="replay", tlog=str(tlog), speed=0.0)


# --------------------------------------------------------------------------- #
# 1. socket:// serial source -> shared pipeline -> decisions; REPLAY, never BENCH
# --------------------------------------------------------------------------- #

def test_socket_serial_source_makes_decisions_and_is_labelled_replay(tmp_path):
    dev = Device(synthetic_stream(4.0), hold_s=6.0)  # SYNTHETIC stream over loopback
    spec = serial_spec(dev)
    assert spec.environment == "REPLAY" and spec.physical is False
    try:
        with serve(make_engine(tmp_path, spec)) as client:
            st, hist = poll(client, lambda s: link(s)["frames"] > 50 and client.get("/api/metrics").json()
                            ["decisions"] >= 5, timeout_s=15)
            health = client.get("/health").json()
            metrics = client.get("/api/metrics").json()
            run_id = client.get("/api/events").json()["run_id"]
    finally:
        dev.close()
    store = EventStore(tmp_path / "live.sqlite")
    try:
        run = next(r for r in store.list_runs() if r["run_id"] == run_id)
    finally:
        store.close()
    assert run["label"] == "replay-serial" and run_id.startswith("replay-")
    assert json.loads(run["meta"])["environment"] == "REPLAY"
    assert metrics["decisions"] >= 5, metrics
    assert link(st)["frames"] > 50
    assert st["sim"] is False and health["sim"] is False
    assert st["environment"] == "REPLAY" and health["environment"] == "REPLAY"
    src = st["source"]
    assert src["kind"] == "serial" and src["environment"] == "REPLAY" and src["physical"] is False
    assert all(s["environment"] != "BENCH" and s["source"]["environment"] != "BENCH" for s in hist)
    assert_live_implies_fresh(hist)


# --------------------------------------------------------------------------- #
# 2. detection output reaches the EventStore; /api/events ids == store rows; chain OK; run label/meta
# --------------------------------------------------------------------------- #

def _bad_fix_tlog(tmp_path: Path) -> Path:
    # SYNTHETIC: position streams, receiver reports fix 0 / 0 satellites -> the GNSS rule's "never acquired" DOS alerts
    return write_tlog(tmp_path / "synthetic_bad_fix.tlog", synthetic_stream(20.0, fix=(0, 0)))


@pytest.mark.parametrize("which", ["synthetic_bad_fix", pytest.param("capture_007", marks=needs_007)])
def test_alerts_reach_event_store_and_api_events(tmp_path, which):
    tlog = _bad_fix_tlog(tmp_path) if which == "synthetic_bad_fix" else TLOG_007
    eng = make_engine(tmp_path, replay_spec(tlog))
    with serve(eng) as client:
        st, hist = poll(client, lambda s: link(s)["state"] == "ended", timeout_s=30)
        api = client.get("/api/events?limit=200").json()
    assert link(st)["state"] == "ended", link(st)
    run_id = api["run_id"]
    assert run_id.startswith("replay-")
    assert api["source"]["environment"] == "REPLAY"
    events = api["events"]
    assert events, "the stream should have produced GNSS-rule alerts"
    for e in events:
        assert e["run_id"] == run_id and e["environment"] == "REPLAY"
        assert any("GNSS fix never acquired" in x for x in e["evidence"]), e["evidence"]
        assert e["attack_type"] == "DOS"
    store = EventStore(tmp_path / "live.sqlite")
    try:
        rows = store.get_events(run_id=run_id, limit=10_000)
        assert {e["id"] for e in events} == {r["id"] for r in rows}
        chain = store.verify_chain(run_id)
        assert chain.ok and chain.length == len(rows)
        run = next(r for r in store.list_runs() if r["run_id"] == run_id)
    finally:
        store.close()
    assert run["label"] == "replay-replay"
    meta = json.loads(run["meta"])
    assert meta["environment"] == "REPLAY" and meta["kind"] == "replay"
    assert meta["physical"] is False and meta["ml"] is False
    # file name + content hash only, never the local directory layout
    assert meta["tlog"] == tlog.name and "/" not in meta["tlog"] and "\\" not in meta["tlog"]
    assert meta["tlog_sha256"] == hashlib.sha256(tlog.read_bytes()).hexdigest()
    assert_live_implies_fresh(hist)


# --------------------------------------------------------------------------- #
# 3. /api/status, /api/events, /health and the WebSocket carry the contract shapes
# --------------------------------------------------------------------------- #

def test_api_status_events_health_and_ws_shapes(tmp_path):
    # SYNTHETIC; gated: `frames > 20` arrives before the second (t = 1 s) HEARTBEAT, so the first one must not be purged
    dev = Device(synthetic_stream(4.0), hold_s=6.0, start=threading.Event())
    try:
        with serve(make_engine(tmp_path, serial_spec(dev))) as client:
            start_when_port_open(client, dev)
            st, _ = poll(
                client,
                lambda s: (
                    link(s)["frames"] > 20
                    and link(s)["gps"]["fix_type"] is not None
                    and "HEARTBEAT" in link(s)["messages"]
                ),
                timeout_s=15,
            )
            health = client.get("/health").json()
            ev = client.get("/api/events?limit=5").json()
            with client.websocket_connect("/ws/telemetry") as ws:
                msg = ws.receive_json()
    finally:
        dev.close()
    assert {"status", "version", "sim", "environment"} <= set(health)
    assert {"environment", "source", "link", "sim"} <= set(st)
    assert {"kind", "environment", "physical", "label", "detail"} <= set(st["source"])
    lk = link(st)
    assert {"state", "frames", "last_frame_age_s", "stale_after_s", "messages", "transport", "gps",
            "error"} <= set(lk)
    assert lk["error"] is None
    assert lk["stale_after_s"] == pytest.approx(STALE_AFTER_S)
    # lead 2026-10-20: last_error is exposed as last_error_history (never cleared on reopen); bad_frames added
    assert {"connected", "disconnects", "reconnects", "open_failures", "crc_rejects", "garbage_bytes",
            "bytes_sent", "write_errors", "last_error_history", "bad_frames"} <= set(lk["transport"])
    assert {"fix_type", "fix_name", "satellites", "valid_fix", "gps_raw_age_s", "position_age_s",
            "position_zero"} <= set(lk["gps"])
    for name in ("HEARTBEAT", "GPS_RAW_INT", "GLOBAL_POSITION_INT", "ATTITUDE"):
        m = lk["messages"].get(name)
        assert m is not None and m["count"] > 0 and m["age_s"] >= 0.0, (name, lk["messages"], lk["transport"],
                                                                         lk["frames"], dev.sent)
    assert {"events", "run_id", "source"} <= set(ev)
    assert msg["sim"] is False and msg["environment"] == "REPLAY"
    assert {"source", "link"} <= set(msg) and msg["source"]["environment"] == "REPLAY"


# --------------------------------------------------------------------------- #
# 4. replay source: REPLAY, ends as "ended", never "live" afterwards
# --------------------------------------------------------------------------- #

def test_replay_source_finishes_as_ended(tmp_path):
    frames = synthetic_stream(5.0)  # SYNTHETIC
    tlog = write_tlog(tmp_path / "synthetic_healthy.tlog", frames)
    with serve(make_engine(tmp_path, replay_spec(tlog))) as client:
        st, hist = poll(client, lambda s: link(s)["state"] == "ended", timeout_s=20)
        after = sample(client, 5)
    assert st["environment"] == "REPLAY" and st["source"]["kind"] == "replay" and st["sim"] is False
    assert link(st)["state"] == "ended"
    assert all(link(s)["state"] == "ended" for s in after), [link(s)["state"] for s in after]
    assert link(after[-1])["frames"] == len(frames)  # every synthetic frame decodes and is counted once
    ended_at = next(i for i, s in enumerate(hist) if link(s)["state"] == "ended")
    assert all(link(s)["state"] == "ended" for s in hist[ended_at:])
    assert_live_implies_fresh(hist + after)


def test_replay_telemetry_is_shown_as_received_and_never_thinned(tmp_path):
    """Integration review 2026-10-27: the dashboard twin and the 'compact telemetry' skip are SIM-only. A recorded
    stream with alerts (mitigation leaves NOMINAL) is broadcast tick by tick with the pipeline's own telemetry."""
    tlog = _bad_fix_tlog(tmp_path)  # SYNTHETIC: GNSS-rule DOS alerts move the mitigation state off NOMINAL
    engine = make_engine(tmp_path, replay_spec(tlog))
    processed, broadcast = [0], []
    orig_process, orig_broadcast = engine._process, engine._broadcast

    async def counting_process(tick):
        processed[0] += 1
        await orig_process(tick)

    async def recording_broadcast(msg):
        broadcast.append(msg)
        await orig_broadcast(msg)

    engine._process, engine._broadcast = counting_process, recording_broadcast
    with serve(engine) as client:
        st, _ = poll(client, lambda s: link(s)["state"] == "ended", timeout_s=30)
    assert link(st)["state"] == "ended"
    assert engine.mitigation.action_history, "the stream should have driven the mitigation state machine"
    updates = broadcast[:-1]  # the last broadcast is the end-of-feed state
    assert len(updates) == processed[0] > 0  # one broadcast per tick, none skipped
    assert engine._cp_lat is None  # the twin never ran
    final = engine.pipeline._telemetry_dict()
    shown = broadcast[-1]["telemetry"]
    for key in ("lat", "lon", "alt_msl", "rel_alt", "groundspeed", "flight_mode", "armed"):
        assert shown.get(key) == final.get(key), (key, shown.get(key), final.get(key))


# --------------------------------------------------------------------------- #
# 5. disconnect mid-stream, and an accepted connection that never sends
# --------------------------------------------------------------------------- #

def test_disconnect_mid_stream_is_disconnected_or_stale_never_live(tmp_path):
    dev = Device(synthetic_stream(2.0), drop=True)  # SYNTHETIC, then connection + listener closed
    try:
        with serve(make_engine(tmp_path, serial_spec(dev))) as client:
            _, before = poll(client, lambda s: link(s)["frames"] > 0, timeout_s=10)
            assert dev.done_sending.wait(10)
            t_drop = time.monotonic()
            st, hist = poll(client, lambda s: link(s)["state"] in ("disconnected", "stale") and
                            time.monotonic() - t_drop > STALE_AFTER_S + 1.0, timeout_s=STALE_AFTER_S + 6)
    finally:
        dev.close()
    lk = link(st)
    assert lk["state"] in ("disconnected", "stale"), lk
    if lk["state"] == "disconnected":
        assert lk["transport"]["connected"] is False
    else:
        assert lk["last_frame_age_s"] > lk["stale_after_s"]
    assert lk["transport"]["disconnects"] >= 1 or lk["transport"]["connected"] is False, lk["transport"]
    assert_live_implies_fresh(before + hist)


def test_connection_without_frames_is_waiting(tmp_path):
    dev = Device([], hold_s=STALE_AFTER_S + 4.0)  # accepts, sends nothing
    try:
        with serve(make_engine(tmp_path, serial_spec(dev))) as client:
            time.sleep(STALE_AFTER_S + 1.0)  # past the stale threshold: "waiting" must still win (no frame ever)
            st, hist = poll(client, lambda s: False, timeout_s=0.5)
    finally:
        dev.close()
    lk = link(st)
    assert lk["state"] == "waiting", lk
    assert lk["frames"] == 0 and lk["last_frame_age_s"] is None
    assert lk["transport"]["connected"] is True
    assert all(link(s)["state"] == "waiting" for s in hist)


# --------------------------------------------------------------------------- #
# 6. frames stop, connection stays open -> stale, with a growing last_frame_age_s
# --------------------------------------------------------------------------- #

def test_frames_stop_connection_open_becomes_stale(tmp_path):
    dev = Device(synthetic_stream(1.5), hold_s=STALE_AFTER_S + 6.0)  # SYNTHETIC, then silence on an open socket
    try:
        with serve(make_engine(tmp_path, serial_spec(dev))) as client:
            poll(client, lambda s: link(s)["frames"] > 0, timeout_s=10)
            assert dev.done_sending.wait(10)
            st, hist = poll(client, lambda s: link(s)["state"] == "stale", timeout_s=STALE_AFTER_S + 5)
            later, _ = poll(client, lambda s: False, timeout_s=0.6)
    finally:
        dev.close()
    lk = link(st)
    assert lk["state"] == "stale", lk
    assert lk["last_frame_age_s"] > lk["stale_after_s"]
    assert lk["transport"]["connected"] is True
    assert link(later)["state"] == "stale" and link(later)["last_frame_age_s"] > lk["last_frame_age_s"]
    ages = [link(s)["last_frame_age_s"] for s in hist if link(s)["last_frame_age_s"] is not None]
    tail = ages[-5:]
    assert tail == sorted(tail), ages  # grows (non-decreasing) once frames have stopped
    assert_live_implies_fresh(hist)


# --------------------------------------------------------------------------- #
# 7. control endpoints: 409 for non-SIM, 200 for SIM (backend/tests/test_api.py stays untouched)
# --------------------------------------------------------------------------- #

CONTROL = [("/api/simulation/start", None), ("/api/simulation/stop", None), ("/api/simulation/reset", None),
           ("/api/simulation/attack", {"attack": "gps_spoofing"})]


def test_control_endpoints_refuse_non_sim_with_409(tmp_path):
    tlog = write_tlog(tmp_path / "synthetic_healthy.tlog", synthetic_stream(3.0))  # SYNTHETIC
    with serve(make_engine(tmp_path, replay_spec(tlog))) as client:
        run_before = client.get("/api/events").json()["run_id"]
        for path, body in CONTROL:
            r = client.post(path, json=body) if body is not None else client.post(path)
            assert r.status_code == 409, (path, r.status_code, r.text)
            j = r.json()
            assert j["ok"] is False and j["environment"] == "REPLAY" and "simulation" in j["error"].lower(), j
        assert client.get("/api/events").json()["run_id"] == run_before  # reset did not start a new run


def test_control_endpoints_still_work_for_sim(tmp_path):
    with serve(make_engine(tmp_path, SourceSpec(kind="sim"))) as client:
        for path, body in CONTROL:
            r = client.post(path, json=body) if body is not None else client.post(path)
            assert r.status_code == 200 and r.json()["ok"] is True, (path, r.status_code, r.text)
        client.post("/api/simulation/attack", json={"attack": "none"})


# --------------------------------------------------------------------------- #
# 8. switching back: a new engine with the sim spec is the unchanged SIM app
# --------------------------------------------------------------------------- #

def test_new_sim_engine_after_a_live_engine_is_sim(tmp_path):
    tlog = write_tlog(tmp_path / "synthetic_healthy.tlog", synthetic_stream(2.0))  # SYNTHETIC
    with serve(make_engine(tmp_path, replay_spec(tlog), "replay.sqlite")) as first:
        assert first.get("/api/status").json()["sim"] is False
    with serve(make_engine(tmp_path, SourceSpec(), "sim.sqlite")) as client:
        st, _ = poll(client, lambda s: s.get("sim_time_s", 0) > 0.5, timeout_s=10)
        health = client.get("/health").json()
        r = client.post("/api/simulation/attack", json={"attack": "gps_spoofing"})
        client.post("/api/simulation/attack", json={"attack": "none"})
        ev = client.get("/api/events").json()
    assert st["sim"] is True and health["sim"] is True
    assert st["environment"] == "SIM" and health["environment"] == "SIM"
    assert st["source"]["kind"] == "sim" and st["source"]["environment"] == "SIM" and st["source"]["physical"] is False
    assert link(st)["state"] == "simulated"
    assert r.status_code == 200 and r.json()["ok"] is True
    assert ev["run_id"].startswith("live-")


# --------------------------------------------------------------------------- #
# 9. receive-only: nothing is ever sent towards the device
# --------------------------------------------------------------------------- #

def test_no_outbound_traffic_to_the_device(tmp_path):
    dev = Device(synthetic_stream(3.0), hold_s=2.0)  # SYNTHETIC
    try:
        with serve(make_engine(tmp_path, serial_spec(dev))) as client:
            assert dev.done_sending.wait(15)
            st, _ = poll(client, lambda s: link(s)["frames"] >= dev.sent, timeout_s=5)
    finally:
        dev.close()
    tr = link(st)["transport"]
    assert tr["bytes_sent"] == 0 and tr["write_errors"] == 0, tr
    assert dev.received == 0, f"the app sent {dev.received} bytes to the device"


# --------------------------------------------------------------------------- #
# 10. GPS display block
# --------------------------------------------------------------------------- #

@needs_007
def test_gps_display_capture_007_reports_no_gps_receiver(tmp_path):
    dev = Device(frames_007(max_t=4.0), hold_s=3.0)  # bench capture 007 bytes over loopback (REPLAY, not hardware)
    try:
        with serve(make_engine(tmp_path, serial_spec(dev))) as client:
            st, _ = poll(client, lambda s: link(s)["gps"]["fix_type"] is not None and
                         link(s)["messages"].get("GPS_RAW_INT", {}).get("count", 0) >= 3, timeout_s=10)
            streaming = not dev.done_sending.is_set()
    finally:
        dev.close()
    gps = link(st)["gps"]
    assert gps["fix_type"] == 0 and gps["fix_name"] == "NO_GPS", gps
    assert gps["valid_fix"] is False and gps["position_zero"] is True, gps
    assert st["environment"] == "REPLAY" and st["source"]["physical"] is False
    if streaming:  # GPS_RAW_INT arrives at ~2 Hz in capture 007
        assert gps["gps_raw_age_s"] is not None and gps["gps_raw_age_s"] <= 1.5, gps


def test_gps_display_synthetic_valid_fix(tmp_path):
    # SYNTHETIC fix_type 3 / 10 satellites with non-zero position: made up here, never presented as hardware
    tlog = write_tlog(tmp_path / "synthetic_fix3_10sats.tlog", synthetic_stream(4.0, fix=(3, 10)))
    with serve(make_engine(tmp_path, replay_spec(tlog))) as client:
        st, _ = poll(client, lambda s: link(s)["state"] == "ended", timeout_s=20)
    gps = link(st)["gps"]
    assert gps["fix_type"] == 3 and gps["satellites"] == 10, gps
    assert gps["valid_fix"] is True and gps["position_zero"] is False, gps
    assert gps["fix_name"] != "NO_GPS"


# --------------------------------------------------------------------------- #
# raw-tlog reader parity with scripts/sitl/tlog_stats.iter_raw_frames
# --------------------------------------------------------------------------- #

def _backend_tlog_reader() -> Callable:
    for name in ("iter_raw_frames", "iter_tlog_frames", "read_raw_tlog", "iter_tlog", "read_tlog"):
        fn = getattr(backend_sources, name, None)
        if callable(fn):
            return fn
    raise AssertionError("no raw-tlog reader found in aegisflight.backend.sources (update the name list)")


def _ts_and_bytes(item) -> tuple[float, bytes]:
    if isinstance(item, tuple):
        frame = next(x for x in reversed(item) if isinstance(x, bytes | bytearray | memoryview))
        return float(item[0]), bytes(frame)
    raise AssertionError(f"unexpected reader item {type(item)!r}")


@needs_007
def test_backend_raw_tlog_reader_matches_tlog_stats_on_capture_007():
    ours = [_ts_and_bytes(x) for x in _backend_tlog_reader()(TLOG_007)]
    ref = [(ts, bytes(fb)) for ts, *_, fb in tlog_stats.iter_raw_frames(TLOG_007)]
    assert len(ours) == len(ref) == 1620
    assert ours == ref


# --------------------------------------------------------------------------- #
# exposure: WebSocket Origin check and Host allow-list (lead request, 2026-10-20)
# --------------------------------------------------------------------------- #

def _sim_client_engine(tmp_path: Path) -> LiveEngine:
    return make_engine(tmp_path, SourceSpec(), "sim_exposure.sqlite")


def test_ws_refuses_a_foreign_origin_but_accepts_none_and_localhost(tmp_path):
    with serve(_sim_client_engine(tmp_path)) as client:
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/ws/telemetry", headers={"origin": "http://evil.example"}) as ws:
                ws.receive_json()
        assert exc.value.code == 1008
        for headers in ({}, {"origin": "http://localhost:5173"}):
            with client.websocket_connect("/ws/telemetry", headers=headers) as ws:
                assert ws.receive_json()["type"] == "update", headers


def test_ws_refuses_an_opaque_null_origin(tmp_path):
    """Browsers send ``Origin: null`` from sandboxed iframes, file:// pages and some redirects. It names no host,
    so it is not this machine and must be refused like any other foreign origin."""
    with serve(_sim_client_engine(tmp_path)) as client:
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/ws/telemetry", headers={"origin": "null"}) as ws:
                ws.receive_json()
        assert exc.value.code == 1008


def test_foreign_host_header_is_rejected_with_400(tmp_path):
    with serve(_sim_client_engine(tmp_path)) as client:
        assert client.get("/health").status_code == 200
        r = client.get("/health", headers={"host": "evil.example"})
        assert r.status_code == 400, (r.status_code, r.text)


# =========================================================================== #
# Acceptance matrix for the contract delta D1-D9 (aegis-validation, 2026-10-20 evening)
# =========================================================================== #

def malformed_stream(frames: list[tuple[float, bytes]], *, clean_tail_s: float = 1.0,
                     seed: int = 7) -> tuple[list[tuple[float, bytes]], dict[str, int]]:
    """SYNTHETIC hostile byte stream built from ``frames``: before each valid frame, a run of garbage bytes (never a
    0xFD/0xFE start byte, so garbage alone cannot open a frame candidate) and a copy of the frame with both CRC bytes
    inverted (a plausible header that must fail the CRC check). The last ``clean_tail_s`` seconds stay clean so the
    final valid frames are not held behind a false candidate. Returns the chunks and the injected counts."""
    rng = random.Random(seed)
    t_last = max(t for t, _ in frames)
    out: list[tuple[float, bytes]] = []
    injected = {"valid": 0, "corrupt": 0, "garbage_bytes": 0}
    for t, f in frames:
        if t <= t_last - clean_tail_s:
            junk = bytes(b for b in rng.randbytes(16) if b not in (0xFD, 0xFE)) or b"\x00"
            out += [(t, junk), (t, f[:-2] + bytes((f[-2] ^ 0xFF, f[-1] ^ 0xFF)))]
            injected["corrupt"] += 1
            injected["garbage_bytes"] += len(junk)
        out.append((t, f))
        injected["valid"] += 1
    return out, injected


@contextlib.contextmanager
def refusing_port() -> Iterator[int]:
    """A 127.0.0.1 TCP port that refuses connections: bound (so no other process can take it) but never listening."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    try:
        yield s.getsockname()[1]
    finally:
        s.close()


def store_rows(db: Path, run_id: str) -> list[dict]:
    store = EventStore(db)
    try:
        return store.get_events(run_id=run_id, limit=10_000)
    finally:
        store.close()


# --- T1 clean input -> no fabricated event ------------------------------------------------------------------------ #

def test_clean_synthetic_stream_produces_no_event(tmp_path):
    # SYNTHETIC healthy link (fix 3 / 10 satellites, all six message types, stationary), 20 s: the same stream and
    # length as the bad-fix stream of test_alerts_reach_event_store_and_api_events, which does alert
    tlog = write_tlog(tmp_path / "synthetic_healthy_20s.tlog", synthetic_stream(20.0, fix=(3, 10)))
    with serve(make_engine(tmp_path, replay_spec(tlog))) as client:
        st, hist = poll(client, lambda s: link(s)["state"] == "ended", timeout_s=30)
        m = client.get("/api/metrics").json()
        api = client.get("/api/events?limit=1000").json()
    assert link(st)["state"] == "ended", link(st)
    assert set(link(st)["messages"]) == SIX_MESSAGES, link(st)["messages"]
    assert m["decisions"] >= 50, m  # >= 10 s of 5 Hz decisions: past every start-up / never-received gate
    assert api["events"] == [] and api["count"] == 0, api
    assert m["alerts"] == 0 and m["event_log"]["count"] == 0, m
    store = EventStore(tmp_path / "live.sqlite")
    try:
        assert api["run_id"] in {r["run_id"] for r in store.list_runs()}  # the run exists: "0 events" is not vacuous
        assert store.count_events(api["run_id"]) == 0 and store.count_events() == 0
    finally:
        store.close()
    assert_live_implies_fresh(hist)


# --- T2 malformed input over socket:// ---------------------------------------------------------------------------- #

def test_malformed_bytes_over_socket_are_rejected_without_events(tmp_path):
    # SYNTHETIC: garbage + CRC-corrupted copies interleaved with a healthy 5.1 s stream (it ends on a heartbeat at
    # t = 5.0 s, so the measurement below happens well inside the 3 s heartbeat timeout)
    chunks, injected = malformed_stream(synthetic_stream(5.1))
    dev = Device(chunks, hold_s=8.0, start=threading.Event())  # exact counts: the stream waits for the port open
    eng = make_engine(tmp_path, serial_spec(dev))
    try:
        with serve(eng) as client:
            start_when_port_open(client, dev)
            assert dev.done_sending.wait(15)
            st, hist = poll(client, lambda s: link(s)["frames"] >= injected["valid"], timeout_s=5)
            m = client.get("/api/metrics").json()
            api = client.get("/api/events").json()
            feed_alive = eng.feed is not None and eng.feed._thread is not None and eng.feed._thread.is_alive()
    finally:
        dev.close()
    lk = link(st)
    tr = lk["transport"]
    assert feed_alive and lk["error"] is None and lk["state"] != "error", lk  # no crash
    assert lk["frames"] == injected["valid"], (lk["frames"], injected)  # only the valid frames are counted
    assert tr["frames_received"] == injected["valid"], (tr, injected)
    assert tr["crc_rejects"] >= injected["corrupt"] and tr["garbage_bytes"] >= injected["garbage_bytes"], (tr, injected)
    assert tr["disconnects"] == 0 and tr["bad_frames"] == 0, tr
    assert m["decisions"] > 0, m
    assert api["events"] == [] and api["count"] == 0 and m["alerts"] == 0, (api, m)
    assert store_rows(tmp_path / "live.sqlite", api["run_id"]) == []  # nothing persisted for the whole run either
    assert_live_implies_fresh(hist)


# --- T3 source failure: an error state, never a silent SIM ------------------------------------------------------- #

def test_replay_tlog_removed_before_start_is_error_with_redacted_message(tmp_path):
    tlog = write_tlog(tmp_path / "synthetic_vanishing.tlog", synthetic_stream(2.0))  # SYNTHETIC
    eng = make_engine(tmp_path, replay_spec(tlog))  # the spec and the run meta need the file to exist here...
    tlog.unlink()  # ...and it is gone before the source starts
    with serve(eng) as client:
        st, hist = poll(client, lambda s: link(s)["state"] == "error", timeout_s=5)
        after = sample(client, 3)
        health = client.get("/health").json()
        m = client.get("/api/metrics").json()
        api = client.get("/api/events").json()
    lk = link(st)
    assert lk["state"] == "error", lk
    assert all(link(s)["state"] == "error" for s in after), [link(s)["state"] for s in after]
    err = lk["error"]
    assert err.startswith("FileNotFoundError"), err
    home = str(Path.home())
    for form in (home, home.replace("\\", "\\\\")):  # plain and repr()-escaped forms
        assert form.lower() not in err.lower(), err
    if str(tlog).lower().startswith(home.lower()):  # true on Windows (pytest's tmp dir is in the profile): exercised
        assert "~" in err, err
    assert st["environment"] == "REPLAY" and st["sim"] is False and health["sim"] is False
    assert health["environment"] == "REPLAY"
    assert all(s["environment"] == "REPLAY" and s["sim"] is False and link(s)["state"] != "live" for s in hist + after)
    assert m["decisions"] == 0 and api["events"] == [] and api["count"] == 0


def test_unopenable_port_without_reconnect_is_error_with_no_decisions(tmp_path):
    with refusing_port() as port:
        spec = SourceSpec(kind="serial", port=f"socket://127.0.0.1:{port}", allow_url=True, reconnect=False)
        with serve(make_engine(tmp_path, spec)) as client:
            st, hist = poll(client, lambda s: link(s)["state"] == "error", timeout_s=8)
            after = sample(client, 3)
            m = client.get("/api/metrics").json()
            api = client.get("/api/events").json()
    lk = link(st)
    assert lk["state"] == "error", lk
    assert re.match(r"^\w+: \S", lk["error"] or ""), lk["error"]  # "<ExcType>: <message>"
    assert all(link(s)["state"] == "error" for s in after), [link(s)["state"] for s in after]
    assert lk["transport"]["open_failures"] >= 1 and lk["transport"]["connected"] is False, lk["transport"]
    assert m["decisions"] == 0 and m["messages_processed"] == 0 and m["alerts"] == 0, m
    assert api["events"] == [] and api["count"] == 0
    assert all(s["environment"] == "REPLAY" and s["sim"] is False and link(s)["state"] != "live" for s in hist + after)


def test_unopenable_port_with_reconnect_is_disconnected_and_retries(tmp_path):
    with refusing_port() as port:
        spec = SourceSpec(kind="serial", port=f"socket://127.0.0.1:{port}", allow_url=True, reconnect=True)
        with serve(make_engine(tmp_path, spec)) as client:
            st, hist = poll(client, lambda s: (link(s)["transport"] or {}).get("open_failures", 0) >= 1, timeout_s=8)
            end = time.monotonic() + 5
            while (m := client.get("/api/metrics").json())["decisions"] == 0 and time.monotonic() < end:
                time.sleep(0.1)
            st2, hist2 = poll(client, lambda s: False, timeout_s=0.3)
    lk = link(st2)
    assert lk["state"] == "disconnected", lk
    assert all(link(s)["state"] == "disconnected" for s in hist + hist2), {link(s)["state"] for s in hist + hist2}
    assert lk["error"] is None and lk["transport"]["connected"] is False, lk
    assert lk["transport"]["open_failures"] >= 1, lk["transport"]
    assert m["decisions"] > 0, m  # D9: ticks continue on a dead link (the runner's behaviour)
    assert all(s["environment"] == "REPLAY" and s["sim"] is False for s in hist + hist2)


# --- T4 shutdown ------------------------------------------------------------------------------------------------- #

def test_shutdown_joins_the_feed_releases_the_port_and_closes_the_store(tmp_path):
    dev = Device(synthetic_stream(2.0), hold_s=30.0)  # SYNTHETIC; the device would hold the link for 30 s
    eng = make_engine(tmp_path, serial_spec(dev))
    try:
        with serve(eng) as client:
            assert dev.done_sending.wait(10)
            poll(client, lambda s: link(s)["frames"] > 20, timeout_s=10)
            assert eng.feed is not None and eng.feed._thread is not None and eng.feed._thread.is_alive()
            assert not dev.peer_closed.is_set()
        # lifespan exit -> LiveEngine.close() (D6)
        assert not eng.feed._thread.is_alive()
        assert dev.peer_closed.wait(5), "the device never saw the app close its connection"
        assert dev.peer_close_kind == "eof", dev.peer_close_kind
        with pytest.raises(sqlite3.ProgrammingError):
            eng.store.conn.execute("SELECT 1")
        assert eng.running is False
        with pytest.raises(RuntimeError):
            asyncio.run(eng.start())  # D6: a closed engine is not restarted
    finally:
        dev.close()


# --- T5 persisted-run isolation in one DB file ------------------------------------------------------------------- #

def test_persisted_runs_are_isolated_in_a_shared_db(tmp_path):
    db = "shared.sqlite"
    with serve(make_engine(tmp_path, SourceSpec(kind="sim"), db)) as client:  # SIM, attack injected
        assert client.post("/api/simulation/attack", json={"attack": "command_injection"}).json()["ok"] is True
        end = time.monotonic() + 10
        while (sim := client.get("/api/events?limit=1000").json())["count"] < 1 and time.monotonic() < end:
            time.sleep(0.1)
        client.post("/api/simulation/attack", json={"attack": "none"})
    sim_run = sim["run_id"]
    assert sim["count"] >= 1 and sim_run.startswith("live-"), sim
    assert all(e["run_id"] == sim_run and e["environment"] == "SIM" for e in sim["events"])

    with serve(make_engine(tmp_path, replay_spec(_bad_fix_tlog(tmp_path)), db)) as client:  # REPLAY, same file
        st, _ = poll(client, lambda s: link(s)["state"] == "ended", timeout_s=30)
        api = client.get("/api/events?limit=1000").json()
        m = client.get("/api/metrics").json()
    run, events = api["run_id"], api["events"]
    assert link(st)["state"] == "ended"
    assert run.startswith("replay-") and run != sim_run
    assert events and all(e["run_id"] == run and e["environment"] == "REPLAY" for e in events)
    assert m["alerts"] == m["event_log"]["count"] == api["count"] and m["event_log"]["chain_ok"] is True, (m, api)

    store = EventStore(tmp_path / db)
    try:
        rows = store.get_events(run_id=run, limit=10_000)
        sim_rows = store.get_events(run_id=sim_run, limit=10_000)
        assert sorted(e["id"] for e in events) == sorted(r["id"] for r in rows)
        assert api["count"] == len(rows) == store.count_events(run)
        cs = store.verify_chain(run)
        assert cs.ok and cs.length == len(rows), cs
        # the SIM run is still in the file, under its own run and label, with an intact chain
        assert sim_rows and {e["id"] for e in sim["events"]} <= {r["id"] for r in sim_rows}
        assert not {r["id"] for r in sim_rows} & {e["id"] for e in events}
        labels = {r["run_id"]: r["label"] for r in store.list_runs()}
        assert labels[sim_run] == "live-demo" and labels[run] == "replay-replay", labels
        assert store.verify_chain(sim_run).ok and store.verify_chain().ok
    finally:
        store.close()
    # every API event carries its chain fields, and they link up in id order from the genesis hash
    assert all(re.fullmatch(r"[0-9a-f]{64}", e["hash"]) and re.fullmatch(r"[0-9a-f]{64}", e["prev_hash"])
               for e in events)
    chrono = sorted(events, key=lambda e: e["id"])
    assert chrono[0]["prev_hash"] == GENESIS_HASH
    assert all(cur["prev_hash"] == prev["hash"] for prev, cur in zip(chrono[:-1], chrono[1:], strict=True))


# --- T6 /api/events limit bounds --------------------------------------------------------------------------------- #

def test_api_events_limit_is_bounded(tmp_path):
    with serve(make_engine(tmp_path, replay_spec(_bad_fix_tlog(tmp_path)))) as client:  # SYNTHETIC, >= 2 alerts
        poll(client, lambda s: link(s)["state"] == "ended", timeout_s=30)
        bad = {n: client.get(f"/api/events?limit={n}").status_code for n in (0, -1, 1001)}
        one = client.get("/api/events?limit=1")
        full = client.get("/api/events?limit=1000")
    assert bad == {0: 422, -1: 422, 1001: 422}, bad
    assert one.status_code == 200 and full.status_code == 200
    ids = [e["id"] for e in full.json()["events"]]
    assert full.json()["count"] == len(ids) >= 2, full.json()["count"]  # so that limit=1 really truncates
    assert len(one.json()["events"]) == 1 and one.json()["events"][0]["id"] == max(ids)  # newest first
    assert one.json()["count"] == full.json()["count"]  # count is the run's total, not the page size


# --- T7 parity with the committed offline replay of capture 007 -------------------------------------------------- #

@needs_007
def test_capture_007_backend_replay_matches_offline_replay(tmp_path, capsys):
    if not REF_007.exists():
        pytest.skip(f"offline replay reference {REF_007.relative_to(REPO).as_posix()} not present")
    ref = json.loads(REF_007.read_text(encoding="utf-8"))
    db = tmp_path / "capture_007.sqlite"
    with serve(make_engine(tmp_path, replay_spec(TLOG_007), db.name)) as client:  # REPLAY of BENCH bytes
        st, _ = poll(client, lambda s: link(s)["state"] == "ended", timeout_s=30)
        m = client.get("/api/metrics").json()
        api = client.get("/api/events?limit=1000").json()
    assert link(st)["state"] == "ended" and link(st)["frames"] == 1620, link(st)
    assert m["decisions"] == ref["decisions"] == 300, m
    events = sorted(api["events"], key=lambda e: e["id"])  # chronological
    assert api["count"] == len(events) == m["alerts"] == ref["alert_decisions"] == 15, (api["count"], m)
    assert dict(Counter(e["attack_type"] for e in events)) == ref["alert_types"] == {"DOS": 15}
    prefixes = [p for p, _ in ref["alert_evidence_top"]]
    assert [e["evidence"][0][:80] for e in events[:len(prefixes)]] == prefixes
    # the reference's own statistic (replay_ap_tlog.summarise), recomputed from the persisted events
    top = Counter(str(x)[:80] for e in events for x in e["evidence"]).most_common(12)
    assert [list(x) for x in top] == ref["alert_evidence_top"]
    from aegisflight.cli.main import main as aegis_main

    capsys.readouterr()
    assert aegis_main(["verify-log", str(db)]) == 0
    out = capsys.readouterr().out
    assert "events: 15" in out and "chain: OK" in out, out


# --- T8 WebSocket update run_id (D5) ----------------------------------------------------------------------------- #

@pytest.mark.parametrize("kind", ["replay", "sim"])
def test_ws_update_run_id_is_the_current_run(tmp_path, kind):
    if kind == "replay":  # SYNTHETIC
        spec = replay_spec(write_tlog(tmp_path / "synthetic_healthy.tlog", synthetic_stream(3.0)))
    else:
        spec = SourceSpec(kind="sim")
    with serve(make_engine(tmp_path, spec)) as client:
        if kind == "replay":
            poll(client, lambda s: link(s)["state"] == "ended", timeout_s=20)
        run = client.get("/api/events").json()["run_id"]
        with client.websocket_connect("/ws/telemetry") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "update" and msg["run_id"] == run == client.get("/api/status").json()["run_id"]
            if kind == "sim":  # "current" run: after a reset the stream carries the NEW run id
                assert client.post("/api/simulation/reset").json()["ok"] is True
                new_run = client.get("/api/events").json()["run_id"]
                assert new_run != run
                for _ in range(100):
                    if ws.receive_json()["run_id"] == new_run:
                        break
                else:
                    pytest.fail("no WebSocket update carried the new run id after reset")
                assert all(ws.receive_json()["run_id"] == new_run for _ in range(3))
    assert run.startswith("replay-" if kind == "replay" else "live-")
