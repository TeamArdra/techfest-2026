"""FastAPI backend for the AegisFlight dashboard.

Exposes REST status endpoints and a WebSocket that streams live telemetry +
threat assessments from the :class:`LiveEngine`. If a built frontend exists at
``frontend/dist`` it is served at ``/`` so ``aegis serve`` hosts the whole app;
otherwise ``/`` returns a small JSON banner.

The telemetry source is chosen at startup (``aegis serve --source``, read here
from ``AEGIS_*`` variables); no endpoint can open or switch it. Every payload
carries ``environment`` (SIM / REPLAY / SITL / BENCH) and ``sim`` (true only for
SIM), so the dashboard can never present simulated or replayed activity as a
real airframe. The control and attack endpoints are simulation-only (HTTP 409
otherwise): a real or replayed source is read-only.

Exposure: same-origin only. There is no CORS middleware (the built frontend is
served from this origin and the Vite dev server proxies ``/api``, ``/health`` and
``/ws``), the Host header must be local (DNS-rebinding guard), and the WebSocket
refuses a browser Origin that is not local -- live bench telemetry (possibly a
real position) must not be readable by an arbitrary web page.
"""

from __future__ import annotations

import contextlib
import hmac
import math
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..attacks import ATTACK_REGISTRY
from .engine import LiveEngine
from .sources import spec_from_env

engine: LiveEngine | None = None

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "tauri.localhost"}

_ALLOWED_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8008",
    "http://127.0.0.1:8008",
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
]


def _local_hosts() -> set[str]:
    # AEGIS_SERVE_HOST is the operator's own --host (non-loopback only for SIM); an unset one adds nothing
    # (adding None would match the hostname-less ``Origin: null``)
    extra = os.environ.get("AEGIS_SERVE_HOST")
    return _LOCAL_HOSTS | ({extra} if extra else set())


_ATTACK_MODE_RE = re.compile(r"[a-z0-9_]{1,40}")
_MAX_DRIFT_RATE_MS = 100.0


def _allowed_hosts() -> list[str]:
    # "testserver" is Starlette's TestClient host
    return sorted(_local_hosts() | {"[::1]", "testserver"})


def _origin_allowed(origin: str, request: Request) -> bool:
    """A browser Origin may drive the control plane only if it is an allow-listed dev/dashboard origin, or
    the exact same origin (scheme + host + port) as this server on a local host. Comparing the hostname
    alone would let a page served by any other localhost port fire the body-less POSTs."""
    if origin in _ALLOWED_CORS_ORIGINS:
        return True
    parsed = urlparse(origin)
    return (parsed.hostname in _local_hosts() and parsed.scheme == request.url.scheme
            and parsed.netloc == request.headers.get("host", ""))


def _require_control_auth(request: Request) -> JSONResponse | None:
    """Validate Origin and optional X-Aegis-Token / Bearer HMAC on mutating control-plane POST routes."""
    origin = request.headers.get("origin")
    if origin is not None and not _origin_allowed(origin, request):
        return JSONResponse(
            status_code=403,
            content={"ok": False, "error": "forbidden cross-origin control-plane request"},
        )

    expected_token = os.environ.get("AEGIS_API_TOKEN", "").strip()
    if expected_token:
        provided = request.headers.get("x-aegis-token", "").strip()
        if not provided:
            auth_hdr = request.headers.get("authorization", "").strip()
            if auth_hdr.lower().startswith("bearer "):
                provided = auth_hdr[7:].strip()
        if not provided or not hmac.compare_digest(provided.encode("utf-8"), expected_token.encode("utf-8")):
            return JSONResponse(
                status_code=401,
                content={"ok": False, "error": "unauthorized: valid X-Aegis-Token or Bearer token required"},
            )
    return None


def get_engine() -> LiveEngine:
    """The single engine; a pre-set ``engine`` (tests) wins, else it is built from ``AEGIS_*``."""
    global engine
    if engine is None:
        engine = LiveEngine(spec=spec_from_env(), db_path=os.environ.get("AEGIS_DB") or None)
    return engine


def _sim_only(action: str) -> JSONResponse | None:
    eng = get_engine()
    if eng.is_sim:
        return None
    return JSONResponse(status_code=409, content={
        "ok": False, "environment": eng.spec.environment,
        "error": f"{action} is simulation-only; the source is {eng.spec.environment} (read-only)"})


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await get_engine().start()  # auto-start the configured source
    yield
    if engine is not None:
        await engine.close()  # loop and source stopped, port released, event store closed


app = FastAPI(title="AegisFlight IDS", version=__version__, lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts())
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Aegis-Token", "Authorization"],
)


# --------------------------------------------------------------------------- #
# REST API
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict:
    eng = get_engine()
    return {"status": "ok", "version": __version__, "sim": eng.is_sim, "environment": eng.spec.environment}


@app.get("/api/status")
def status() -> dict:
    return get_engine().status()


# metrics / events are async on purpose: every EventStore read then runs on the event-loop thread, the same
# thread that appends the alerts (no SQLite connection is shared across threads).
@app.get("/api/metrics")
async def metrics() -> dict:
    return get_engine().metrics()


@app.get("/api/events")
async def events(limit: int = Query(50, ge=1, le=1000)) -> dict:
    """The CURRENT run's persisted alerts, newest first, read back from the event store (hash-chain fields
    included); ``count`` is the run's total. Bounded ``limit``: SQLite treats a negative LIMIT as unlimited."""
    eng = get_engine()
    return {"events": eng.recent_alerts(limit), "run_id": eng._run_id, "source": eng.spec.describe(),
            "count": eng.store.count_events(eng._run_id)}


@app.get("/api/events/forensic")
async def events_forensic(limit: int = Query(200, ge=1, le=1000)) -> dict:
    """Return cryptographically verified SHA-256 hash-chain status + forensic alert & mitigation bundle."""
    return get_engine().forensic_bundle(limit=limit)


@app.get("/api/config")
def config() -> dict:
    cfg = get_engine().cfg  # the configuration actually in use (a --config-dir profile, if any)
    det = cfg.detector
    return {
        "attacks": sorted(ATTACK_REGISTRY.keys()),
        "decision_rate_hz": det.get("decision_rate_hz"),
        "sample_rate_hz": cfg.simulation.get("sample_rate_hz"),
        "fusion": {
            "threat_threshold": det["fusion"]["threat_threshold"],
            "weights": det["fusion"]["weights"],
            "severity_bands": det["fusion"]["severity_bands"],
        },
        "home": cfg.simulation.get("home"),
    }


@app.post("/api/simulation/start", response_model=None)
async def sim_start(request: Request) -> dict | JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    if (refused := _sim_only("start")) is not None:
        return refused
    await get_engine().start()
    return {"ok": True, "running": True}


@app.post("/api/simulation/stop", response_model=None)
async def sim_stop(request: Request) -> dict | JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    if (refused := _sim_only("stop")) is not None:
        return refused
    await get_engine().stop()
    return {"ok": True, "running": False}


@app.post("/api/simulation/reset", response_model=None)
async def sim_reset(request: Request) -> dict | JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    # Refused for a live source: pipeline.reset() would erase detector memory (docs/THREAT_MODEL.md).
    if (refused := _sim_only("reset")) is not None:
        return refused
    # Stop the running loop, restore a clean baseline, then start a fresh loop.
    # Async (not sync) so start()'s create_task runs on the event loop.
    eng = get_engine()
    await eng.stop()
    eng.reset()
    await eng.start()
    return {"ok": True, "reset": True}


@app.post("/api/simulation/attack")
def sim_attack(payload: dict, request: Request) -> JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    if (refused := _sim_only("attack injection")) is not None:
        return refused
    name = (payload or {}).get("attack")
    mode = (payload or {}).get("mode")
    drift_rate_ms = (payload or {}).get("drift_rate_ms")
    # validated here: a bad value would otherwise raise inside the engine loop and stop the simulation
    if mode is not None and not (isinstance(mode, str) and _ATTACK_MODE_RE.fullmatch(mode)):
        return JSONResponse(status_code=400, content={"ok": False, "error": "mode must be a short identifier"})
    if drift_rate_ms is not None:
        if isinstance(drift_rate_ms, bool) or not isinstance(drift_rate_ms, int | float)                 or not math.isfinite(drift_rate_ms) or not 0.0 < drift_rate_ms <= _MAX_DRIFT_RATE_MS:
            return JSONResponse(status_code=400, content={
                "ok": False, "error": f"drift_rate_ms must be a number in (0, {_MAX_DRIFT_RATE_MS:g}]"})
    if name and name not in ATTACK_REGISTRY and name not in ("none", "benign"):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"unknown attack '{name}'",
                     "choices": sorted(ATTACK_REGISTRY.keys())},
        )
    get_engine().set_attack(name, mode=mode, drift_rate_ms=drift_rate_ms)
    return JSONResponse(content={"ok": True, "attack": name or "cleared", "mode": mode})


@app.post("/api/defense/mode")
def set_defense_mode(payload: dict, request: Request) -> JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    mode = (payload or {}).get("mode")
    if mode not in ("passive", "advisory", "active-ips"):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"unknown defense mode '{mode}'",
                     "choices": ["passive", "advisory", "active-ips"]},
        )
    res = get_engine().set_defense_mode(mode)
    return JSONResponse(content={"ok": True, **res})


@app.post("/api/defense/override")
def defense_override(payload: dict, request: Request) -> JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    action = (payload or {}).get("action")
    if action not in ("safe_hold", "reset_quarantine", "ack_takeover"):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"unknown override action '{action}'",
                     "choices": ["safe_hold", "reset_quarantine", "ack_takeover"]},
        )
    res = get_engine().defense_override(action)
    return JSONResponse(content={"ok": True, "action": action, "mitigation": res})


@app.get("/api/topology")
def get_topology() -> dict:
    eng = get_engine()
    return {
        "ok": True,
        "topology": getattr(eng, "topology", "b"),
        "reasons": getattr(eng, "topology_reasons", []),
        "available": ["auto", "a", "b", "a+b", "ids"],
    }


@app.post("/api/topology")
def set_topology(payload: dict, request: Request) -> JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    top = (payload or {}).get("topology")
    if not top or str(top).lower() not in ("auto", "a", "b", "a+b", "ids"):
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": f"unknown topology '{top}'",
                "choices": ["auto", "a", "b", "a+b", "ids"],
            },
        )
    try:
        res = get_engine().set_topology(str(top).lower())
        return JSONResponse(content={"ok": True, **res})
    except Exception as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})


# --------------------------------------------------------------------------- #
# WebSocket — live telemetry + threat stream
# --------------------------------------------------------------------------- #
@app.websocket("/ws/telemetry")
async def ws_telemetry(ws: WebSocket) -> None:
    # CORS does not apply to WebSockets: refuse a browser Origin that is not this machine. No Origin
    # (non-browser clients, TestClient) is allowed. Client messages are never read.
    origin = ws.headers.get("origin")
    if origin is not None and urlparse(origin).hostname not in _local_hosts():  # "null" -> hostname None
        await ws.close(code=1008)
        return
    await ws.accept()
    eng = get_engine()
    q = eng.subscribe()
    try:
        while True:
            msg = await q.get()
            await ws.send_json(msg)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - client vanished mid-send
        pass
    finally:
        eng.unsubscribe(q)
        with contextlib.suppress(Exception):
            await ws.close()


# --------------------------------------------------------------------------- #
# Static frontend (if built)
# --------------------------------------------------------------------------- #
_DIST = Path(__file__).resolve().parents[3] / "frontend" / "dist"
if _DIST.exists():
    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="frontend")
else:
    @app.get("/")
    def root() -> dict:
        eng = get_engine()
        return {
            "name": "AegisFlight IDS",
            "version": __version__,
            "sim": eng.is_sim,
            "environment": eng.spec.environment,
            "note": "frontend not built; run `npm --prefix frontend install && "
                    "npm --prefix frontend run build`, or use the dev server",
            "endpoints": ["/health", "/api/status", "/api/metrics", "/api/events",
                          "/api/config", "/ws/telemetry"],
        }
