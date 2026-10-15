"""Raw-byte tap on ``SerialMavlinkTransport`` and the probe's ``--raw`` capture.

Hardware-free: every port is a scripted fake handed in through ``serial_factory`` (label
``FAKE0``). An autouse fixture makes ``serial.Serial`` / ``serial.serial_for_url`` raise, so no
code path in this file can open a real port (COM5, COM7, anything). Nothing here shows why a real
link is silent; it only shows that the bytes a read returned can be recovered exactly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
from pathlib import Path

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.sources.mavlink_serial import SerialMavlinkTransport

serial = pytest.importorskip("serial", reason="pyserial not installed (pip install 'aegisflight[serial]')")

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "hardware"))

import pixhawk_passive_probe as probe  # noqa: E402


@pytest.fixture(autouse=True)
def no_real_ports(monkeypatch):
    def boom(*a, **k):
        raise AssertionError(f"test attempted to open a real serial port: {a!r}")

    monkeypatch.setattr(serial, "Serial", boom)
    monkeypatch.setattr(serial, "serial_for_url", boom)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def hb(seq: int = 0) -> bytes:
    m = mav2.MAVLink(None, srcSystem=3, srcComponent=1)
    m.seq = seq
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, 12, 0x80, 0, 4).pack(m))


def att(seq: int = 0) -> bytes:
    m = mav2.MAVLink(None, srcSystem=3, srcComponent=1)
    m.seq = seq
    return bytes(m.attitude_encode(1000, 0.1, -0.2, 1.5, 0.0, 0.0, 0.0).pack(m))


class FakePort:
    """Scripted port: bytes item = one read returns it; Exception = raised; idle line afterwards."""

    def __init__(self, script: list | None = None) -> None:
        self.script = list(script or [])
        self.lock = threading.Lock()
        self.closed = False
        self.written: list[bytes] = []

    @property
    def in_waiting(self) -> int:
        with self.lock:
            return len(self.script[0]) if self.script and isinstance(self.script[0], bytes) else 0

    def read(self, size: int = 1) -> bytes:
        with self.lock:
            item = self.script.pop(0) if self.script else None
        if isinstance(item, BaseException):
            raise item
        if item is None:
            time.sleep(0.002)
            return b""
        return item

    def write(self, data: bytes) -> int:
        self.written.append(data)
        return len(data)

    def close(self) -> None:
        self.closed = True


def wait_for(cond, timeout: float = 5.0, what: str = "condition") -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return
        time.sleep(0.005)
    raise AssertionError(f"timed out waiting for {what}")


class StepClock:
    """Strictly increasing fake clock: every call returns a new value."""

    def __init__(self) -> None:
        self.n = 1000
        self.lock = threading.Lock()

    def __call__(self) -> int:
        with self.lock:
            self.n += 7
            return self.n


def make_tr(port: FakePort, **kw) -> SerialMavlinkTransport:
    return SerialMavlinkTransport("FAKE0", serial_factory=lambda: port, reconnect_interval_s=0.01, **kw)


def drain(tr: SerialMavlinkTransport, n: int) -> list[tuple[int, bytes]]:
    got: list[tuple[int, bytes]] = []
    wait_for(lambda: (got.extend(tr.poll()), len(got) >= n)[1], what=f"{n} frames")
    return got


# --------------------------------------------------------------------------- #
# transport tap
# --------------------------------------------------------------------------- #


def test_tap_receives_exact_bytes_order_and_stamps_including_garbage_and_split_frames():
    h, a = hb(0), att(1)
    reads = [b"\x00\x11garbage", h[:5], h[5:] + b"\xaa\xbb" + a[:3], a[3:], b"\xfd\x00"]
    port = FakePort(list(reads))
    seen: list[tuple[int, bytes]] = []
    tr = make_tr(port, clock_ns=StepClock(), raw_tap=lambda s, d: seen.append((s, d)))
    with tr:
        frames = drain(tr, 2)
        wait_for(lambda: len(seen) == len(reads), what="all reads tapped")
    assert [d for _, d in seen] == reads  # exact bytes, exact read boundaries, exact order
    stamps = [s for s, _ in seen]
    assert stamps == sorted(set(stamps))  # strictly increasing
    # the stamp the tap saw is the stamp the framer path used for the frame that read completed
    assert frames == [(stamps[2], h), (stamps[3], a)]
    assert tr.stats["bytes_received"] == sum(map(len, reads))
    assert tr.stats["raw_tap_errors"] == 0 and tr.stats["raw_tap_disabled"] is False


def test_tap_is_not_called_for_empty_reads_or_read_failures():
    port = FakePort([b"abc", None, None, OSError("unplugged")])
    seen: list[bytes] = []
    tr = make_tr(port, raw_tap=lambda s, d: seen.append(d), reconnect=False)
    with tr:
        wait_for(lambda: tr.disconnects == 1, what="disconnect")
    assert seen == [b"abc"]


def test_default_no_tap_is_unchanged_and_tap_does_not_alter_framing():
    h, a = hb(0), att(1)
    reads = [b"zz", h[:4], h[4:] + a, b"\xfd\x01\x00\x00", b"q"]

    def run(**kw):
        tr = make_tr(FakePort(list(reads)), partial_timeout_s=0.05, **kw)
        with tr:
            frames = drain(tr, 2)
            wait_for(lambda: tr.stats["bytes_received"] == sum(map(len, reads)), what="reads")
            time.sleep(0.15)  # let the stale-partial flush fire
        s = tr.stats
        return [d for _, d in frames], {k: s[k] for k in (
            "bytes_received", "frames_received", "garbage_bytes", "resync_events", "header_rejects",
            "crc_rejects", "partial_timeouts", "last_error", "bytes_sent", "write_errors")}

    plain = run()
    tapped = run(raw_tap=lambda s, d: None)
    assert plain == tapped
    assert plain[0] == [h, a]
    tr = make_tr(FakePort([h]))
    with tr:
        drain(tr, 1)
    s = tr.stats  # additive keys exist and are quiet without a tap
    assert s["raw_tap_errors"] == 0 and s["raw_tap_disabled"] is False and s["raw_tap_last_error"] is None


def test_raising_tap_never_stops_framing_is_counted_and_disabled_after_consecutive_failures():
    frames_in = [hb(i) for i in range(8)]
    calls: list[int] = []

    def bad(stamp, data):
        calls.append(stamp)
        raise RuntimeError("sink exploded")

    port = FakePort(list(frames_in))
    tr = make_tr(port, raw_tap=bad, raw_tap_max_consecutive_errors=3)
    with tr:
        got = drain(tr, 8)
    assert [d for _, d in got] == frames_in  # every frame still framed and queued
    s = tr.stats
    assert len(calls) == 3  # disabled after 3 failures in a row: no further calls
    assert s["raw_tap_errors"] == 3 and s["raw_tap_disabled"] is True
    assert "sink exploded" in s["raw_tap_last_error"]
    assert s["last_error"] is None  # link-error slot not clobbered
    assert s["reader_faults"] == 0 and s["disconnects"] == 0 and s["frames_received"] == 8


def test_intermittent_tap_failures_reset_the_run_and_never_disable():
    n = {"i": 0}

    def flaky(stamp, data):
        n["i"] += 1
        if n["i"] % 2:
            raise ValueError("odd call")

    frames_in = [hb(i) for i in range(10)]
    tr = make_tr(FakePort(list(frames_in)), raw_tap=flaky, raw_tap_max_consecutive_errors=2)
    with tr:
        got = drain(tr, 10)
    assert len(got) == 10
    s = tr.stats
    assert s["raw_tap_errors"] == 5 and s["raw_tap_disabled"] is False and n["i"] == 10


def test_tap_failure_keeps_a_real_link_error_in_last_error():
    port = FakePort([hb(0), OSError("cable pulled")])
    tr = make_tr(port, raw_tap=lambda s, d: (_ for _ in ()).throw(RuntimeError("tap")), reconnect=False)
    with tr:
        wait_for(lambda: tr.disconnects == 1, what="disconnect")
    s = tr.stats
    assert "cable pulled" in s["last_error"] and "tap" in s["raw_tap_last_error"]


def test_tap_never_writes_bytes_sent_stays_zero():
    port = FakePort([hb(0), att(1), b"junk"])
    seen: list[bytes] = []
    tr = make_tr(port, raw_tap=lambda s, d: seen.append(d))
    with tr:
        drain(tr, 2)
    assert port.written == [] and tr.stats["bytes_sent"] == 0 and tr.stats["write_errors"] == 0


def test_invalid_tap_failure_limit_is_rejected():
    with pytest.raises(ValueError):
        SerialMavlinkTransport("FAKE0", serial_factory=lambda: FakePort(), raw_tap_max_consecutive_errors=0)


# --------------------------------------------------------------------------- #
# raw-record file format
# --------------------------------------------------------------------------- #


def test_raw_capture_roundtrip_and_reader_edge_cases(tmp_path):
    p = tmp_path / "sub" / "dir" / "cap.rawbin"  # parent directories are created
    rc = probe.RawCapture(p, 1024)
    recs = [(5, b"\x00\xfd\xff"), (9, b"x" * 200), (2**63, bytes(range(256)))]
    for s, d in recs:
        rc.write(s, d)
    rc.close()
    rc.close()  # idempotent
    assert probe.read_raw_records(p) == recs
    assert rc.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()
    blob = p.read_bytes()
    with pytest.raises(ValueError):
        probe.read_raw_records(blob[:-1])
    assert probe.read_raw_records(blob[:-1], allow_truncated_tail=True) == recs[:-1]
    with pytest.raises(ValueError):
        probe.read_raw_records(blob[:5])
    assert probe.read_raw_records(b"") == []
    with pytest.raises(ValueError):
        probe.read_raw_records(probe.RAW_HEADER.pack(1, 0))  # zero-length record is invalid


def test_raw_capture_cap_boundary_is_exact_and_headers_count(tmp_path):
    h = probe.RAW_HEADER.size
    rc = probe.RawCapture(tmp_path / "c.rawbin", 2 * (h + 10))
    rc.write(1, b"a" * 10)
    rc.write(2, b"b" * 10)  # exactly fills the cap
    assert not rc.cap_hit
    rc.write(3, b"c")  # does not fit
    rc.write(4, b"d" * 3)
    rc.close()
    assert rc.cap_hit and rc.records == 2 and rc.reads_not_recorded == 2 and rc.bytes_not_recorded == 4
    assert (tmp_path / "c.rawbin").stat().st_size == 2 * (h + 10)


def test_raw_capture_exclusive_create_and_write_after_close(tmp_path):
    p = tmp_path / "c.rawbin"
    p.write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        probe.RawCapture(p)
    assert p.read_bytes() == b"precious"
    q = probe.RawCapture(tmp_path / "d.rawbin")
    q.close()
    q.write(1, b"late")  # ignored, no exception
    assert q.records == 0 and q.closed


# --------------------------------------------------------------------------- #
# probe run() with a fake port
# --------------------------------------------------------------------------- #


@pytest.fixture
def fake_probe(monkeypatch):
    """Route the probe's transport onto a scripted fake. Returns a controller."""

    class Ctl:
        port = FakePort()
        built = 0
        kwargs: dict = {}

    def build(port, **kw):
        Ctl.built += 1
        Ctl.kwargs = kw
        return SerialMavlinkTransport(port, serial_factory=lambda: Ctl.port, **kw)

    Ctl.built = 0
    monkeypatch.setattr(probe, "SerialMavlinkTransport", build)
    monkeypatch.setattr(probe, "_git_commit", lambda: None)
    return Ctl


def make_args(tmp_path: Path, **over) -> argparse.Namespace:
    d = {"port": "FAKE0", "baud": 57600, "duration": 0.6, "json": str(tmp_path / "report.json"),
         "tlog": None, "raw": None, "raw_max_bytes": probe.DEFAULT_RAW_MAX_BYTES,
         "reconnect_interval": 0.01, "gap_report_s": 2.5, "keep_trying": False}
    d.update(over)
    return argparse.Namespace(**d)


def report_of(args) -> dict:
    return json.loads(Path(args.json).read_text(encoding="utf-8"))


def test_probe_raw_file_roundtrips_byte_exact_with_read_boundaries_and_report(fake_probe, tmp_path):
    h, a = hb(0), att(1)
    reads = [b"\x01garbage\x02", h[:6], h[6:] + b"\xaa", a, b"\xfd\x09\x00"]
    fake_probe.port = FakePort(list(reads))
    raw = tmp_path / "out" / "raw" / "cap.rawbin"
    args = make_args(tmp_path, raw=str(raw))
    assert probe.run(args) == 0
    recs = probe.read_raw_records(raw)
    assert [d for _, d in recs] == reads
    stamps = [s for s, _ in recs]
    assert stamps == sorted(stamps)
    rep = report_of(args)
    rc = rep["raw_capture"]
    assert rc["path"] == str(raw) and rc["records"] == len(reads) and rc["cap_hit"] is False
    assert rc["data_bytes"] == sum(map(len, reads)) and rc["file_bytes"] == raw.stat().st_size
    assert rc["sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest()
    assert stamps[0] >= rc["mono_ns_at_start"]
    assert rep["transport_stats"]["raw_tap_errors"] == 0
    assert rep["passive_check"] == {"bytes_sent": 0, "write_errors": 0, "passed": True}
    assert rep["frames"] == 2 and rep["transport_stats"]["garbage_bytes"] > 0
    assert fake_probe.port.written == []


def test_probe_reports_connected_and_reader_running_as_of_the_run_not_after_close(fake_probe, tmp_path):
    fake_probe.port = FakePort([hb(0)])
    args = make_args(tmp_path)
    assert probe.run(args) == 0
    st = report_of(args)["transport_stats"]
    assert st["connected"] is True and st["reader_running"] is True
    assert "sampled just before" in report_of(args)["transport_state_sampled"]
    assert fake_probe.port.closed  # and the port really was closed afterwards


def test_probe_default_run_creates_no_raw_file_and_passes_no_tap(fake_probe, tmp_path):
    fake_probe.port = FakePort([hb(0)])
    args = make_args(tmp_path)  # raw=None
    assert probe.run(args) == 0
    assert fake_probe.kwargs["raw_tap"] is None
    assert [p.name for p in tmp_path.iterdir()] == ["report.json"]
    assert report_of(args)["raw_capture"] is None


def test_probe_refuses_existing_raw_file_before_the_port_is_touched(fake_probe, tmp_path, capsys):
    raw = tmp_path / "cap.rawbin"
    raw.write_bytes(b"keep me")
    before = raw.stat().st_mtime_ns
    args = make_args(tmp_path, raw=str(raw), tlog=str(tmp_path / "x.tlog"))
    assert probe.run(args) == 2
    assert raw.read_bytes() == b"keep me" and raw.stat().st_mtime_ns == before
    assert fake_probe.built == 0  # transport (and so the port) never constructed
    assert not (tmp_path / "x.tlog").exists() and not Path(args.json).exists()
    assert "refusing to overwrite" in capsys.readouterr().err


@pytest.mark.parametrize("bad", [0, -5, 12])
def test_probe_rejects_unusable_raw_cap_without_creating_a_file(fake_probe, tmp_path, bad):
    raw = tmp_path / "cap.rawbin"
    assert probe.run(make_args(tmp_path, raw=str(raw), raw_max_bytes=bad)) == 2
    assert not raw.exists() and fake_probe.built == 0


def test_probe_rejects_raw_path_colliding_with_json_or_tlog(fake_probe, tmp_path):
    same = tmp_path / "same.out"
    assert probe.run(make_args(tmp_path, raw=str(same), json=str(same))) == 2
    assert probe.run(make_args(tmp_path, raw=str(same), tlog=str(same))) == 2
    assert not same.exists() and fake_probe.built == 0


def test_probe_size_cap_stops_writing_flags_it_and_the_run_keeps_going(fake_probe, tmp_path):
    h = probe.RAW_HEADER.size
    h0, a0 = hb(0), att(1)
    reads = [b"A" * 10, b"B" * 10, b"C" * 10, h0, a0]
    fake_probe.port = FakePort(list(reads))
    raw = tmp_path / "cap.rawbin"
    args = make_args(tmp_path, raw=str(raw), raw_max_bytes=2 * (h + 10) + 3)
    assert probe.run(args) == 0
    assert [d for _, d in probe.read_raw_records(raw)] == reads[:2]
    rc = report_of(args)["raw_capture"]
    assert rc["cap_hit"] is True and rc["records"] == 2
    assert rc["reads_not_recorded"] == 3 and rc["bytes_not_recorded"] == 10 + len(h0) + len(a0)
    assert raw.stat().st_size <= args.raw_max_bytes
    assert report_of(args)["frames"] == 2  # framing and the report were unaffected by the cap


def test_probe_closes_raw_file_when_the_run_raises(fake_probe, tmp_path, monkeypatch):
    made: list = []
    real = probe.RawCapture

    class Spy(real):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            made.append(self)

    class Boom:
        def __init__(self, stats):
            pass

        def parse(self, frame, t):
            raise RuntimeError("parser blew up")

    monkeypatch.setattr(probe, "RawCapture", Spy)
    monkeypatch.setattr(probe, "MavlinkFrameParser", Boom)
    reads = [b"zzz", hb(0)]
    fake_probe.port = FakePort(list(reads))
    raw = tmp_path / "cap.rawbin"
    with pytest.raises(RuntimeError, match="parser blew up"):
        probe.run(make_args(tmp_path, raw=str(raw)))
    assert made[0].closed and made[0]._fh is None
    assert made[0].sha256 == hashlib.sha256(raw.read_bytes()).hexdigest()
    assert [d for _, d in probe.read_raw_records(raw)] == reads  # flushed data is intact
    assert fake_probe.port.closed


def test_probe_keyboard_interrupt_still_finalises_and_closes_raw(fake_probe, tmp_path, monkeypatch):
    class Interrupt:
        def __init__(self, stats):
            pass

        def parse(self, frame, t):
            raise KeyboardInterrupt

    monkeypatch.setattr(probe, "MavlinkFrameParser", Interrupt)
    fake_probe.port = FakePort([b"q", hb(0)])
    raw = tmp_path / "cap.rawbin"
    args = make_args(tmp_path, raw=str(raw))
    assert probe.run(args) == 0
    assert report_of(args)["raw_capture"]["sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest()
    assert len(probe.read_raw_records(raw)) == 2


def test_probe_broken_raw_sink_does_not_stop_framing_and_is_reported(fake_probe, tmp_path, monkeypatch):
    def failing_write(self, stamp_ns, data):
        raise OSError("disk full")

    monkeypatch.setattr(probe.RawCapture, "write", failing_write)
    fake_probe.port = FakePort([hb(0), att(1), hb(2)])
    args = make_args(tmp_path, raw=str(tmp_path / "cap.rawbin"))
    assert probe.run(args) == 0
    rep = report_of(args)
    assert rep["frames"] == 3 and rep["transport_stats"]["raw_tap_errors"] == 3
    assert "disk full" in rep["transport_stats"]["raw_tap_last_error"]
    assert rep["raw_capture"]["records"] == 0


def test_main_defaults_raw_off_with_16mib_cap(monkeypatch):
    got = {}
    monkeypatch.setattr(probe, "run", lambda a: got.setdefault("args", a) and 0)
    monkeypatch.setattr(sys, "argv", ["probe", "--port", "FAKE0"])
    assert probe.main() == 0
    assert got["args"].raw is None and got["args"].raw_max_bytes == 16 * 1024 * 1024
