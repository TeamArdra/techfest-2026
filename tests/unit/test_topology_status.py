"""Detected topology: pure builders, LiveEngine per source, and the inline bridge (no hardware, no servers)."""
from __future__ import annotations

import json
import urllib.request

import pytest

from aegisflight.backend.engine import LinkMonitor, LiveEngine
from aegisflight.backend.sources import SourceSpec
from aegisflight.core.types import MessageEnvelope
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.hal.status_server import BridgeStatusServer
from aegisflight.hal.topology_status import (
    bridge_topology,
    replay_topology,
    sidecar_topology,
    sim_topology,
)
from aegisflight.sources.stream import TelemetryTick

KEYS = {"kind", "label", "source", "posture", "links", "uplink_visible", "can_block_frames",
        "can_send_counter_commands", "reasons"}


def _env(sysid: int, name: str) -> MessageEnvelope:
    return MessageEnvelope(recv_time=0.0, sysid=sysid, compid=1, msgid=0, msgname=name, seq=0, signed=False,
                           byte_len=10, fields={})


def _tick(*envs: MessageEnvelope) -> TelemetryTick:
    return TelemetryTick(t=1.0, tick=0, messages=list(envs))


def _engine(tmp_path, **kw) -> LiveEngine:
    return LiveEngine(spec=SourceSpec(kind="udp", udp_port=14999, **kw), db_path=str(tmp_path / "t.sqlite"))


def test_sidecar_without_ground_station_frames(tmp_path):
    eng = _engine(tmp_path)
    eng.link.observe(_tick(_env(1, "HEARTBEAT"), _env(1, "GLOBAL_POSITION_INT")))
    info = eng.topology_info()
    assert set(info) == KEYS
    assert info["kind"] == "A" and info["source"] == "detected"
    assert info["uplink_visible"] is False and info["can_block_frames"] is False
    assert info["can_send_counter_commands"] is False  # passive
    assert info["links"]["gcs"] == {"connected": None, "name": None}
    assert any("uplink not visible" in r for r in info["reasons"])


@pytest.mark.parametrize("env", [_env(255, "HEARTBEAT"), _env(1, "COMMAND_LONG"), _env(1, "SET_MODE")])
def test_sidecar_with_uplink_evidence(tmp_path, env):
    eng = _engine(tmp_path)
    eng.link.observe(_tick(_env(1, "HEARTBEAT"), env))
    assert eng.topology_info()["uplink_visible"] is True


def test_sidecar_posture_changes_counter_commands_but_never_blocking(tmp_path):
    eng = _engine(tmp_path)
    for mode, counter in (("passive", False), ("advisory", False), ("active-ips", True)):
        eng.set_defense_mode(mode)
        info = eng.topology_info()
        assert info["posture"] == mode and info["can_send_counter_commands"] is counter
        assert info["can_block_frames"] is False


def test_replay_and_sim():
    r = replay_topology("active-ips")
    assert (r["kind"], r["source"], r["can_block_frames"], r["can_send_counter_commands"]) == ("REPLAY", "none", False, False)
    s = sim_topology("active-ips")
    assert (s["kind"], s["source"], s["can_block_frames"], s["can_send_counter_commands"]) == ("SIM", "modelled", False, False)


def test_sim_engine_reports_sim_and_inline_twin(tmp_path):
    eng = LiveEngine(spec=SourceSpec(kind="sim"), db_path=str(tmp_path / "s.sqlite"))
    assert eng.topology_info()["kind"] == "SIM" and eng.topology == "a+b"
    assert not hasattr(eng, "set_topology")


def test_replay_engine(tmp_path):
    tlog = tmp_path / "x.tlog"
    tlog.write_bytes(b"")
    eng = LiveEngine(spec=SourceSpec(kind="replay", tlog=str(tlog), speed=0.0), db_path=str(tmp_path / "r.sqlite"))
    assert eng.topology_info()["kind"] == "REPLAY"


def test_link_monitor_counts_only_uplink_evidence():
    m = LinkMonitor(3.0, 3, 5)
    m.observe(_tick(_env(1, "HEARTBEAT")))
    assert m.uplink_frames == 0
    m.observe(_tick(_env(254, "HEARTBEAT")))
    assert m.uplink_frames == 1


def test_sidecar_builder_without_writable_transport():
    info = sidecar_topology("active-ips", connected=True, name="COM7", uplink_seen=False, writable=False)
    assert info["can_send_counter_commands"] is False and info["links"]["fc"] == {"connected": True, "name": "COM7"}


class Link:
    def __init__(self, connected=None):
        if connected is not None:
            self.connected = connected
        self.inbox, self.sent = [], []

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def send(self, data):
        self.sent.append(bytes(data))
        return True

    def close(self):
        return None


def test_bridge_both_links_up_posture_matrix():
    for mode, block, counter in (("passive", False, False), ("advisory", False, False), ("active-ips", True, True)):
        t = InlineIpsBridge(Link(True), Link(True), mode=mode).status()["topology"]
        assert set(t) == KEYS and t["kind"] == "A+B" and t["source"] == "detected"
        assert t["links"]["fc"]["connected"] is True and t["links"]["gcs"]["connected"] is True
        assert t["uplink_visible"] is True
        assert (t["can_block_frames"], t["can_send_counter_commands"]) == (block, counter)


def test_bridge_one_link_down():
    t = InlineIpsBridge(Link(False), Link(True), mode="active-ips").status()["topology"]
    assert t["kind"] == "A+B" and t["can_block_frames"] is False and t["can_send_counter_commands"] is False
    assert any("DOWN" in r for r in t["reasons"])
    t = InlineIpsBridge(Link(True), Link(False), mode="active-ips").status()["topology"]
    assert t["can_send_counter_commands"] is True and t["can_block_frames"] is False
    assert t["uplink_visible"] is False


def test_bridge_unknown_connected_state_is_none_and_not_claimed():
    t = bridge_topology("active-ips", fc_connected=None, gcs_connected=None, gcs_frames_seen=0)
    assert t["links"]["fc"]["connected"] is None and t["can_block_frames"] is False
    assert bridge_topology("passive", fc_connected=None, gcs_connected=None, gcs_frames_seen=3)["uplink_visible"] is True


def test_bridge_status_server_exposes_topology_and_legacy_crossend():
    b = InlineIpsBridge(Link(True), Link(True), mode="passive")
    srv = BridgeStatusServer(b).start()
    try:
        body = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/status", timeout=5).read())
    finally:
        srv.close()
    assert body["topology"]["kind"] == "A+B" and body["crossend"] == {"sent": 0}
