"""Cross-end check on SYNTHETIC frames and fake transports: nothing opens a port or touches a vehicle."""

from __future__ import annotations

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.core.enums import AttackType
from aegisflight.detectors.crossend import CrossEndMonitor, gpi_from_frame
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.proxy.transport import split_frames
from aegisflight.sources.mavlink_live import MavlinkFrameParser

KEY = bytes(range(32))


def gpi(tbm: int, lat: int = 473977420, lon: int = 85455940, alt: int = 500000, rel: int = 10000,
        vx: int = 100, vy: int = -50) -> bytes:
    m = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
    m.robust_parsing = True
    return bytes(m.global_position_int_encode(tbm, lat, lon, alt, rel, vx, vy, 0, 9000).pack(m))


class Link:
    def __init__(self) -> None:
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True

    def close(self) -> None:
        return None


class Clock:
    def __init__(self) -> None:
        self.ns = 10_000_000_000

    def __call__(self) -> int:
        return self.ns


def run_bridge(key=None, frames=(gpi(1000),)):
    fc, gcs, clk = Link(), Link(), Clock()
    b = InlineIpsBridge(fc, gcs, secret_key=key, clock_ns=clk)
    fc.inbox = [(1, f) for f in frames]
    b.pump_once()
    gcs.sent.clear()
    assert b.emit_crossend()
    return b, fc, gcs, clk


def envs(raw_frames, t0=0.0, key=None):
    p = MavlinkFrameParser(secret_key=key)
    out = []
    for i, f in enumerate(raw_frames):
        out += p.parse(f, t0 + i * 0.1)
    return out


def summary_of(gcs: Link) -> bytes:
    assert len(gcs.sent) == 1
    return gcs.sent[0]


def test_unused_monitor_is_inert():
    m = CrossEndMonitor()
    for e in envs([gpi(1)]):
        m.update(e)
    assert m.assess(0.0) is None


def test_match_then_alter_in_transit():
    _, _, gcs, _ = run_bridge()
    s = summary_of(gcs)
    m = CrossEndMonitor()
    for e in envs([gpi(1000), s]):
        m.update(e)
    r = m.assess(0.0)
    assert r is not None and r.score == 0.0 and not r.evidence
    # same time_boot_ms, forged latitude
    m2 = CrossEndMonitor()
    for e in envs([gpi(1000, lat=473977999), s]):
        m2.update(e)
    r = m2.assess(0.0)
    assert r.score == 0.9 and r.votes == {AttackType.TELEMETRY_MANIPULATION: 0.9}
    assert "field lat: bridge 473977420, GCS 473977999" in r.evidence[0]


def test_summary_before_frame_and_unmatched():
    _, _, gcs, _ = run_bridge()
    m = CrossEndMonitor()
    for e in envs([summary_of(gcs), gpi(1000, vy=7)]):
        m.update(e)
    assert m.assess(0.0).score == 0.9
    m2 = CrossEndMonitor()
    for e in envs([summary_of(gcs), gpi(2000)]):  # different time_boot_ms: not compared, not an alert
        m2.update(e)
    assert m2.assess(0.0).score == 0.0


def test_silence_after_summaries():
    _, _, gcs, _ = run_bridge()
    m = CrossEndMonitor()
    for e in envs([gpi(1000), summary_of(gcs)]):
        m.update(e)
    for e in envs([gpi(1100 + i) for i in range(1)], t0=9.0):
        m.update(e)
    r = m.assess(9.0)
    assert r.score == 0.3 and r.votes == {AttackType.MAVLINK_ANOMALY: 0.3}


def test_signed_summary_verified_and_forgery_flagged():
    _, _, gcs, _ = run_bridge(key=KEY)
    s = summary_of(gcs)
    assert s[2] & 1  # MAVLink signing flag
    m = CrossEndMonitor(KEY)
    for e in envs([gpi(1000), s]):
        m.update(e)
    assert m.assess(0.0).score == 0.0
    # a forged summary (unsigned, no tag) is anomaly evidence, never compared
    _, _, gcs2, _ = run_bridge(key=None, frames=(gpi(1000, lat=1),))
    m2 = CrossEndMonitor(KEY)
    for e in envs([gpi(1000), summary_of(gcs2)]):
        m2.update(e)
    r = m2.assess(0.0)
    assert r.score == 0.3 and r.votes == {AttackType.MAVLINK_ANOMALY: 0.3}


def test_bridge_summary_goes_to_gcs_only_and_matches_last_gpi():
    fc, gcs, clk = Link(), Link(), Clock()
    b = InlineIpsBridge(fc, gcs, clock_ns=clk)
    fc.inbox = [(1, gpi(1000)), (2, gpi(1100, lat=5))]
    b.pump_once()
    gcs.sent.clear()
    tap_before = b.tap.poll()
    assert b.emit_crossend()
    assert fc.sent == [] and b.tap.poll() == []
    assert tap_before  # the original frames were tapped, the summary was not
    (fr,) = split_frames(gcs.sent[0])[0]
    assert (fr.msgid, fr.sysid, fr.compid) == (249, 1, 191)
    m = CrossEndMonitor()
    for e in envs([gpi(1100, lat=5), gcs.sent[0]]):
        m.update(e)
    assert m.compared == 1 and m.mismatches == 0
    assert gpi_from_frame(gpi(1100, lat=5))[1] == 5
    # no new frame -> nothing more; interval respected
    assert not b.emit_crossend()
    fc.inbox = [(3, gpi(1200))]
    b.pump_once()
    assert not b.emit_crossend()
    clk.ns += 1_000_000_000
    assert b.emit_crossend()


def test_interval_zero_is_off():
    fc, gcs = Link(), Link()
    b = InlineIpsBridge(fc, gcs, crossend_interval_s=0)
    fc.inbox = [(1, gpi(1))]
    b.pump_once()
    assert not b.emit_crossend() and gcs.sent == [gpi(1)]


def test_pipeline_merges_into_protocol_and_is_identical_without_summary():
    from aegisflight.config import load_config
    from aegisflight.pipeline import IDSPipeline
    from aegisflight.sources.mavlink_live import frame_ticks

    _, _, gcs, _ = run_bridge()
    s = summary_of(gcs)

    def run(frames, monitor):
        p = IDSPipeline(load_config(), crossend=monitor)
        res = []
        for tk in frame_ticks([(0.1 * i, f) for i, f in enumerate(frames)], sample_rate_hz=10.0):
            a = p.process_tick(tk)
            if a is not None:
                res.append(a)
        return res

    plain = [gpi(1000)] * 1 + [gpi(1000 + 100 * i) for i in range(1, 30)]
    a0 = run(plain, None)
    a1 = run(plain, CrossEndMonitor())
    assert [(x.threat_score, x.evidence) for x in a0] == [(x.threat_score, x.evidence) for x in a1]
    forged = [gpi(1000, lat=1)] + plain[1:]
    forged.insert(2, s)
    res = run(forged, CrossEndMonitor())
    assert any("downlink position differs" in " ".join(x.evidence) for x in res)


@pytest.mark.parametrize("bad", [b"", b"\x00" * 3])
def test_gpi_from_frame_rejects_garbage(bad):
    assert gpi_from_frame(bad) is None
