"""Signing gate: active-ips on a real link without signing is an explicit, acknowledged choice."""
from __future__ import annotations

import importlib
import json
import urllib.error
import urllib.request

import pytest
from fastapi.testclient import TestClient

from aegisflight.backend import app as app_mod
from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.sources import SourceSpec
from aegisflight.hal.status_server import BridgeStatusServer
from aegisflight.mitigation import DefenseMode

cli = importlib.import_module("aegisflight.cli.main")
KEY = bytes(range(32))


def _client(monkeypatch, tmp_path, *, sim: bool, key: bool):
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    if sim:
        spec = SourceSpec()
    else:
        tl = tmp_path / "x.tlog"
        tl.write_bytes(b"")
        kf = None
        if key:
            kf = tmp_path / "k.bin"
            kf.write_bytes(KEY)
        spec = SourceSpec(kind="replay", tlog=str(tl), signing_key_file=str(kf) if kf else None)
    eng = LiveEngine(spec=spec)
    monkeypatch.setattr(app_mod, "engine", eng)
    return TestClient(app_mod.app), eng


def _post(c, mode, **extra):
    return c.post("/api/defense/mode", json={"mode": mode, **extra})


def test_sim_never_gated(monkeypatch, tmp_path):
    c, _ = _client(monkeypatch, tmp_path, sim=True, key=False)
    assert _post(c, "active-ips").status_code == 200
    assert c.get("/api/status").json()["signing"] == {"configured": False}


def test_live_without_key_is_refused(monkeypatch, tmp_path):
    c, eng = _client(monkeypatch, tmp_path, sim=False, key=False)
    r = _post(c, "active-ips")
    assert r.status_code == 409
    b = r.json()
    assert b["ok"] is False and b["error"] == "signing_required" and b["signing"] == {"configured": False} and b["message"]
    assert eng.mitigation.mode != DefenseMode.ACTIVE_IPS
    for bad in ("true", 1, "yes"):
        assert _post(c, "active-ips", allow_unsigned=bad).status_code in (400, 409)
    assert eng.mitigation.mode != DefenseMode.ACTIVE_IPS


@pytest.mark.parametrize("mode", ["passive", "advisory"])
def test_live_non_active_modes_not_gated(monkeypatch, tmp_path, mode):
    c, _ = _client(monkeypatch, tmp_path, sim=False, key=False)
    assert _post(c, mode).status_code == 200


def test_live_with_allow_unsigned_proceeds_and_is_recorded(monkeypatch, tmp_path):
    c, eng = _client(monkeypatch, tmp_path, sim=False, key=False)
    assert _post(c, "active-ips", allow_unsigned=True).status_code == 200
    assert eng.mitigation.mode == DefenseMode.ACTIVE_IPS
    st = c.get("/api/status").json()
    assert st["unsigned_acknowledged"] is True and st["signing"]["configured"] is False
    assert any(a["tag"] == "UNSIGNED_ACK" for a in eng.mitigation.action_history)
    _post(c, "passive")
    assert c.get("/api/status").json()["unsigned_acknowledged"] is False


def test_live_with_key_proceeds_and_counter_frames_are_signed(monkeypatch, tmp_path):
    c, eng = _client(monkeypatch, tmp_path, sim=False, key=True)
    assert c.get("/api/status").json()["signing"] == {"configured": True}
    assert _post(c, "active-ips").status_code == 200
    frame = eng.mitigation.actuator.encode_ekf_source_switch(source_set=2)
    assert frame[2] & 1, "counter-frames must carry the MAVLink-2 signature flag"
    unsigned = LiveEngine(spec=SourceSpec()).mitigation.actuator.encode_ekf_source_switch(source_set=2)
    assert not unsigned[2] & 1


# --- aegis ips-bridge CLI ------------------------------------------------------------------------------------- #

_BASE = ["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2", "--allow-url",
         "--seconds", "0.1", "--status-interval", "0.1"]


def test_cli_refuses_unsigned_active_ips(capsys):
    assert cli.main([*_BASE, "--defense-mode", "active-ips"]) == 2
    assert "--allow-unsigned" in capsys.readouterr().err


def test_cli_refuses_non_loopback_status_host_without_token(capsys):
    rc = cli.main([*_BASE, "--status-host", "0.0.0.0", "--status-port", "1"])
    assert rc == 2 and "--control-token-file" in capsys.readouterr().err


def test_cli_bad_token_file(tmp_path, capsys):
    rc = cli.main([*_BASE, "--control-token-file", str(tmp_path / "missing")])
    assert rc == 2 and "control-token-file" in capsys.readouterr().err


def test_cli_acknowledged_unsigned_runs_with_notice(monkeypatch, capsys):
    from aegisflight.hal import inline_ips
    from aegisflight.sources import mavlink_serial
    started = []

    class FakeBr:
        def __init__(self, *a, **kw):
            started.append(kw["mode"])

        def start(self):
            pass

        def close(self):
            pass

        def status(self):
            return {}

    class FakeT:
        def __init__(self, *a, **kw):
            pass

        def start(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(inline_ips, "InlineIpsBridge", FakeBr)
    monkeypatch.setattr(mavlink_serial, "SerialMavlinkTransport", FakeT)
    rc = cli.main([*_BASE, "--defense-mode", "active-ips", "--allow-unsigned"])
    assert rc == 0 and started == ["active-ips"]
    assert "acknowledged" in capsys.readouterr().out


# --- bridge status server: POST /posture ---------------------------------------------------------------------- #

class _Ctl:
    def __init__(self):
        self.mode = DefenseMode.PASSIVE


class FakeBridge:
    crossend_sent = 0

    def __init__(self):
        self.controller = _Ctl()
        self.calls = []

    def set_mode(self, m):
        self.calls.append(m)
        self.controller.mode = DefenseMode(m)

    def status(self):
        return {"mode": self.controller.mode.value}


def _http(port, method="POST", path="/posture", body=None, headers=None):
    data = json.dumps(body).encode() if isinstance(body, dict | list) else body
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None), resp.headers
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, (json.loads(raw) if raw else None), e.headers


@pytest.fixture
def srv_factory():
    made = []

    def make(**kw):
        b = FakeBridge()
        s = BridgeStatusServer(b, **kw).start()
        made.append(s)
        return s, b

    yield make
    for s in made:
        s.close()


def test_posture_control_disabled(srv_factory):
    s, b = srv_factory()
    code, body, _ = _http(s.port, body={"mode": "advisory"}, headers={"Authorization": "Bearer x"})
    assert code == 403 and body == {"error": "control_disabled"} and b.calls == []
    assert _http(s.port, "GET", "/status")[1]["control"] == {"enabled": False}


def test_posture_auth_and_validation(srv_factory):
    s, b = srv_factory(control_token="s3cret", signing_configured=False)
    assert _http(s.port, body={"mode": "advisory"})[0] == 401
    assert _http(s.port, body={"mode": "advisory"}, headers={"Authorization": "Bearer nope"})[0] == 401
    assert _http(s.port, body={"mode": "advisory"}, headers={"X-Aegis-Token": "nope"})[0] == 401
    h = {"Authorization": "Bearer s3cret"}
    assert _http(s.port, body={"mode": "weird"}, headers=h)[0] == 400
    assert _http(s.port, body={"mode": "advisory", "allow_unsigned": "yes"}, headers=h)[0] == 400
    assert _http(s.port, body=b"not json", headers=h)[0] == 400
    assert _http(s.port, body=[1], headers=h)[0] == 400
    code, body, _ = _http(s.port, body={"mode": "active-ips"}, headers=h)
    assert code == 409 and body["error"] == "signing_required" and body["ok"] is False and body["message"]
    assert b.calls == []
    code, body, _ = _http(s.port, body={"mode": "advisory"}, headers={"X-Aegis-Token": "s3cret"})
    assert code == 200 and body["ok"] is True and body["status"]["mode"] == "advisory" and b.calls == ["advisory"]


def test_posture_unsigned_ack_and_leave(srv_factory):
    s, b = srv_factory(control_token="t")
    h = {"Authorization": "Bearer t"}
    code, body, _ = _http(s.port, body={"mode": "active-ips", "allow_unsigned": True}, headers=h)
    assert code == 200 and body["status"]["signing"] == {"configured": False, "unsigned_acknowledged": True}
    code, body, _ = _http(s.port, body={"mode": "passive"}, headers=h)
    assert code == 200 and body["status"]["signing"]["unsigned_acknowledged"] is False
    assert b.calls == ["active-ips", "passive"]


def test_posture_signed_bridge_needs_no_ack(srv_factory):
    s, b = srv_factory(control_token="t", signing_configured=True)
    code, body, _ = _http(s.port, body={"mode": "active-ips"}, headers={"Authorization": "Bearer t"})
    assert code == 200 and body["status"]["signing"] == {"configured": True, "unsigned_acknowledged": False}


def test_posture_cors_and_methods(srv_factory):
    s, b = srv_factory(control_token="t")
    code, _, h = _http(s.port, "OPTIONS", headers={"Origin": "tauri://localhost"})
    assert code == 204 and h["Access-Control-Allow-Origin"] == "tauri://localhost"
    assert "POST" in h["Access-Control-Allow-Methods"]
    for hdr in ("Authorization", "X-Aegis-Token", "Content-Type"):
        assert hdr in h["Access-Control-Allow-Headers"]
    _, _, h = _http(s.port, "OPTIONS", headers={"Origin": "http://evil.example"})
    assert h["Access-Control-Allow-Origin"] is None
    code, _, _ = _http(s.port, body={"mode": "advisory"}, headers={"Origin": "http://evil.example",
                                                                    "Authorization": "Bearer t"})
    assert code == 403 and b.calls == []
    code, _, h = _http(s.port, "GET", "/status", headers={"Origin": "http://localhost:5173"})
    assert code == 200 and h["Access-Control-Allow-Origin"] == "http://localhost:5173"
    for m in ("PUT", "DELETE", "PATCH"):
        assert _http(s.port, m, "/posture")[0] == 405
    assert _http(s.port, "POST", "/status", body={})[0] == 405
