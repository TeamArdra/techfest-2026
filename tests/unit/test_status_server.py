import json
import urllib.error
import urllib.request

from aegisflight.hal.status_server import BridgeStatusServer


class FakeBridge:
    crossend_sent = 7

    def status(self):
        return {"mode": "passive", "state": "running", "frames": 3, "latency_us": {}, "policy": {},
                "analyser": {}, "last_error": None}


def _req(port, method="GET", origin=None, path="/status"):
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method, data=b"" if method == "POST" else None)
    if origin:
        r.add_header("Origin", origin)
    return urllib.request.urlopen(r, timeout=5)


def _code(port, **kw):
    try:
        _req(port, **kw)
    except urllib.error.HTTPError as e:
        return e.code
    return 200


def test_status_shape_cors_and_methods():
    srv = BridgeStatusServer(FakeBridge()).start()
    try:
        assert srv._httpd.server_address[0] == "127.0.0.1"
        with _req(srv.port, origin="tauri://localhost") as resp:
            body = json.load(resp)
            assert resp.headers["Access-Control-Allow-Origin"] == "tauri://localhost"
        assert body["crossend"] == {"sent": 7} and body["frames"] == 3 and body["mode"] == "passive"
        with _req(srv.port, origin="http://evil.example") as resp:
            assert resp.headers["Access-Control-Allow-Origin"] is None
        for method in ("POST", "PUT", "DELETE"):
            assert _code(srv.port, method=method) == 405
        assert _code(srv.port, path="/other") == 404
    finally:
        srv.close()
