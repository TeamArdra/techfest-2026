"""Telemetry-source selection for the dashboard backend (SIM / REPLAY / SITL / BENCH).

The backend runs ONE source, chosen at startup (``aegis serve --source ...`` or ``AEGIS_*`` environment
variables); no HTTP endpoint can open, select or switch a source. Every non-simulated source reuses the
existing ingestion stack unchanged -- the same components ``scripts/hardware/run_serial_ids.py`` runs:

* ``serial``: ``SerialMavlinkTransport`` -> ``LiveMavlinkSource(origin="start")`` (a dead link still ticks)
* ``udp``:    ``UdpMavlinkTransport`` bound to loopback, passive (no GCS heartbeat) -> ``LiveMavlinkSource``
* ``replay``: a repo-framed tlog (``>Q`` unix microseconds + one frame) -> ``frame_ticks``, paced in time

The environment label is DERIVED, never user-settable, so replayed or loopback data cannot be presented
as physical telemetry: a ``socket://`` virtual serial port is ``REPLAY``, only a real serial port is
``BENCH``. Nothing here transmits: ``transport.send`` is never called (the transports count bytes_sent).
"""

from __future__ import annotations

import hashlib
import os
import struct
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..mavlink.gcs_notifier import is_loopback_host
from ..sources.stream import TelemetryTick

KINDS = ("sim", "replay", "serial", "udp")
_URL_PREFIX = "socket://"
# well-known VIRTUAL serial devices (PTY pairs, com0com, tty0tty): never labelled physical. A plain OS port
# name still does not PROVE a physical board -- BENCH means "an OS serial device was configured".
_VIRTUAL_PORT_PREFIXES = ("/dev/pts/", "/dev/tnt", "cnca", "cncb")


@dataclass(frozen=True)
class SourceSpec:
    kind: str = "sim"
    port: str | None = None  # serial: COM7 / /dev/ttyAMA0, or socket://127.0.0.1:N (needs allow_url)
    baud: int = 115200
    allow_url: bool = False
    tlog: str | None = None  # replay input
    speed: float = 1.0  # replay pacing: 1.0 = capture time, 0 = as fast as possible (tests)
    udp_port: int | None = None  # udp: listen on 127.0.0.1:<udp_port>
    config_dir: str | None = None
    ml: bool | None = None  # None -> on for sim (Stage-1 behaviour), off for every other kind
    # serial: retry an unopenable / unplugged port (link "disconnected", ticks continue, as in run_serial_ids.py);
    # False = its --no-reconnect: a port that cannot be opened is a source error (no ticks, so no alerts)
    reconnect: bool = True
    gcs_notify: bool = False
    gcs_notify_host: str = "127.0.0.1"
    gcs_notify_port: int = 14550
    defense_mode: str = "passive"

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown source kind {self.kind!r}; choose one of {KINDS}")
        if self.defense_mode not in ("passive", "advisory", "active-ips"):
            raise ValueError(f"unknown defense_mode {self.defense_mode!r}; choose one of 'passive', 'advisory', 'active-ips'")
        if self.kind != "sim" and self.defense_mode == "active-ips":
            # live sources are receive-only: counter-commands are never transmitted to a real or SITL autopilot
            raise ValueError("defense_mode 'active-ips' is simulation-only; live sources are receive-only")
        if self.gcs_notify and not is_loopback_host(self.gcs_notify_host):
            raise ValueError(f"gcs_notify_host must be a loopback address (got {self.gcs_notify_host!r})")
        if self.kind == "serial":
            if not self.port:
                raise ValueError("serial source needs a port (e.g. COM7)")
            if self._is_url and not self.allow_url:
                raise ValueError("a socket:// port is a virtual (non-physical) link; pass allow_url to use it")
        if self.kind == "replay" and (not self.tlog or not Path(self.tlog).is_file()):
            raise ValueError(f"replay source needs an existing tlog file, got {self.tlog!r}")
        if self.kind == "udp" and not self.udp_port:
            raise ValueError("udp source needs a udp_port")
        if self.speed < 0:
            raise ValueError("replay speed must be >= 0")
        if self.kind != "sim" and self.ml:
            # the Stage-1 model does not transfer to real stacks (docs/ARDUPILOT_SITL.md, PX4 calibration);
            # run_serial_ids.py defaults it off for the same reason
            raise ValueError("ML is simulation-only in the dashboard: the Stage-1 model is not valid on real telemetry")

    @property
    def _is_url(self) -> bool:
        return bool(self.port) and str(self.port).lower().startswith(_URL_PREFIX)

    @property
    def _is_virtual_name(self) -> bool:
        return bool(self.port) and str(self.port).lower().startswith(_VIRTUAL_PORT_PREFIXES)

    @property
    def physical(self) -> bool:
        """True only for an OS serial device that is not a known virtual one (never a URL, replay, UDP or
        the simulator). Configured, not proven: the frames' origin is not verifiable on an unsigned link."""
        return self.kind == "serial" and not self._is_url and not self._is_virtual_name

    @property
    def environment(self) -> str:
        if self.kind == "sim":
            return "SIM"
        if self.kind == "udp":
            return "SITL"
        if self.kind == "serial" and self.physical:
            return "BENCH"
        return "REPLAY"  # tlog replay, or a socket:// virtual serial port

    @property
    def ml_enabled(self) -> bool:
        return self.kind == "sim" if self.ml is None else bool(self.ml)

    def describe(self) -> dict[str, Any]:
        detail: dict[str, Any] = {}
        if self.kind == "serial":
            detail = {"port": self.port, "baud": self.baud, "virtual": not self.physical, "reconnect": self.reconnect}
        elif self.kind == "replay":
            detail = {"tlog": Path(self.tlog).name if self.tlog else None, "speed": self.speed}
        elif self.kind == "udp":
            # the sender behind a UDP socket cannot be verified: SITL is the operator's stated setup
            detail = {"bind": f"127.0.0.1:{self.udp_port}", "passive": True, "sender_verified": False}
        label = {"SIM": "Simulation", "REPLAY": "Replay (recorded / virtual link)",
                 "SITL": "SITL (UDP loopback; sender not verified)",
                 "BENCH": "Physical bench (live serial)"}[self.environment]
        return {"kind": self.kind, "environment": self.environment, "physical": self.physical,
                "label": label, "detail": detail, "ml": self.ml_enabled,
                "gcs_notify": self.gcs_notify, "defense_mode": self.defense_mode,
                "config_dir": self.config_dir or "configs (Stage-1 default)"}

    def run_meta(self) -> dict[str, Any]:
        d = asdict(self)
        if d.get("tlog"):  # file name + content hash only: no local directory layout in the event DB
            d["tlog_sha256"] = hashlib.sha256(Path(d["tlog"]).read_bytes()).hexdigest()
            d["tlog"] = Path(d["tlog"]).name
        if d.get("config_dir") and Path(d["config_dir"]).is_absolute():
            d["config_dir"] = Path(d["config_dir"]).name
        d.update(environment=self.environment, physical=self.physical, ml=self.ml_enabled)
        if self.kind == "serial" and self.physical:
            d["usb"] = serial_port_identity(self.port)
        return d


def serial_port_identity(port: str | None) -> dict[str, Any] | None:
    """USB identity of a serial port from the OS device list (pyserial ``list_ports``: enumerates, never
    opens the port). ``None`` if unavailable. Provenance only -- it identifies the adapter, not the vehicle."""
    if not port:
        return None
    try:
        from serial.tools import list_ports
    except ImportError:
        return None
    for p in list_ports.comports():
        if p.device.lower() == str(port).lower():
            return {"description": p.description, "vid": f"{p.vid:04X}" if p.vid is not None else None,
                    "pid": f"{p.pid:04X}" if p.pid is not None else None, "manufacturer": p.manufacturer}
    return {"description": "not in the OS device list", "vid": None, "pid": None, "manufacturer": None}


def _flag(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def _redact(text: str) -> str:
    """Replace the local home directory in an error message with ``~``: API payloads end up in shared evidence."""
    home = str(Path.home())
    return text.replace(home.replace("\\", "\\\\"), "~").replace(home, "~")  # repr()-escaped form first


def spec_from_env(env: dict[str, str] | None = None) -> SourceSpec:
    """Build the startup source from ``AEGIS_*`` variables (set by ``aegis serve``); default = sim."""
    e = os.environ if env is None else env
    ml_raw = e.get("AEGIS_ML")
    return SourceSpec(
        kind=e.get("AEGIS_SOURCE", "sim") or "sim",
        port=e.get("AEGIS_SERIAL_PORT") or None,
        baud=int(e.get("AEGIS_BAUD") or "115200"),  # "" = unset, like every other key
        allow_url=_flag(e.get("AEGIS_ALLOW_URL")),
        tlog=e.get("AEGIS_TLOG") or None,
        speed=float(e.get("AEGIS_REPLAY_SPEED") or "1.0"),
        udp_port=int(e["AEGIS_UDP_PORT"]) if e.get("AEGIS_UDP_PORT") else None,
        config_dir=e.get("AEGIS_CONFIG_DIR") or None,
        ml=None if ml_raw in (None, "") else _flag(ml_raw),
        reconnect=_flag(e.get("AEGIS_RECONNECT") or "1"),
        gcs_notify=_flag(e.get("AEGIS_GCS_NOTIFY")),
        gcs_notify_host=e.get("AEGIS_GCS_NOTIFY_HOST") or "127.0.0.1",
        gcs_notify_port=int(e.get("AEGIS_GCS_NOTIFY_PORT") or "14550"),
        defense_mode=e.get("AEGIS_DEFENSE_MODE", "passive") or "passive",
    )


def iter_tlog_frames(path: str | Path) -> Iterator[tuple[float, bytes]]:
    """``(recv_unix_s, frame_bytes)`` from the repo's tlog framing (same rules as
    ``scripts/sitl/tlog_stats.iter_raw_frames``; MAVLink 1 and 2, signed frames carry a 13-byte signature).
    Stops at the first byte that is not a frame start (truncated / corrupt tail)."""
    data = Path(path).read_bytes()
    i = 0
    while i + 8 + 3 <= len(data):  # stamp + magic, len and (v2) incompat byte
        ts = struct.unpack(">Q", data[i:i + 8])[0] / 1e6
        f = i + 8
        if data[f] == 0xFE:
            n = 8 + data[f + 1]
        elif data[f] == 0xFD:
            n = 12 + data[f + 1] + (13 if data[f + 2] & 1 else 0)
        else:
            return
        if f + n > len(data):  # truncated final frame
            return
        yield ts, data[f:f + n]
        i = f + n


class LiveFeed:
    """A non-simulated source running in a background thread, delivering ``TelemetryTick``s to a callback.

    ``deliver(tick)`` is called from the producer thread (the engine marshals it onto its event loop);
    ``deliver(None)`` marks the end of a finite source (replay). ``transport_stats()`` is the transport's
    own counters (``None`` for replay). ``close()`` stops the producer and closes the transport.
    """

    def __init__(self, spec: SourceSpec, sample_rate_hz: float) -> None:
        if spec.kind == "sim":
            raise ValueError("LiveFeed is for non-simulated sources")
        self.spec = spec
        self.rate = sample_rate_hz
        self.transport: Any = None
        self.source: Any = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.ended = False
        self.error: str | None = None

    def start(self, deliver: Callable[[TelemetryTick | None], None]) -> None:
        if self._thread is not None:
            return
        from ..sources.mavlink_live import LiveMavlinkSource, UdpMavlinkTransport, frame_ticks

        s = self.spec
        if s.kind == "serial":
            from ..sources.mavlink_serial import SerialMavlinkTransport

            # reconnect on: an unopenable / unplugged port is reported (connected False) instead of ending;
            # off: stream() -> transport.start() raises in run(), so the feed ends with an error and no ticks
            self.transport = SerialMavlinkTransport(s.port, baudrate=s.baud, reconnect=s.reconnect,
                                                    allow_url=s.allow_url)
            self.source = LiveMavlinkSource(self.transport, sample_rate_hz=self.rate, origin="start")
            gen: Callable[[], Iterator[TelemetryTick]] = self.source.stream
        elif s.kind == "udp":
            self.transport = UdpMavlinkTransport(bind=("127.0.0.1", int(s.udp_port or 0)), gcs_heartbeat=False)
            self.source = LiveMavlinkSource(self.transport, sample_rate_hz=self.rate, origin="start")
            gen = self.source.stream
        else:  # replay
            dt = 1.0 / self.rate

            def gen() -> Iterator[TelemetryTick]:
                for tick in frame_ticks(iter_tlog_frames(s.tlog), sample_rate_hz=self.rate):
                    if self._stop.is_set():
                        return
                    if s.speed > 0:
                        time.sleep(dt / s.speed)
                    yield tick

        def run() -> None:
            try:
                for tick in gen():
                    if self._stop.is_set():
                        break
                    deliver(tick)
            except Exception as exc:  # noqa: BLE001 - surfaced in status, never silently live
                self.error = _redact(f"{type(exc).__name__}: {exc}")
            finally:
                self.ended = True
                deliver(None)

        self._thread = threading.Thread(target=run, name=f"aegis-feed-{s.kind}", daemon=True)
        self._thread.start()

    def transport_stats(self) -> dict[str, Any] | None:
        tr = self.transport
        if tr is None:
            return None
        st = dict(getattr(tr, "stats", {}) or {})
        keep = ("connected", "disconnects", "reconnects", "open_failures", "crc_rejects", "garbage_bytes",
                "frames_received", "bytes_received", "bytes_sent", "write_errors")
        out: dict[str, Any] = {k: st[k] for k in keep if k in st}
        out.setdefault("connected", None)  # UDP has no connection: unknown, judged by frame age only
        if "last_error" in st:  # never cleared on reopen: history, not current state
            err = st["last_error"]
            out["last_error_history"] = _redact(err) if isinstance(err, str) else err
        for attr in ("heartbeats_sent", "dropped_foreign", "recv_errors"):  # UDP-only counters, if present
            if hasattr(tr, attr):
                out[attr] = getattr(tr, attr)
        if self.source is not None:
            out["bad_frames"] = self.source.stats.get("bad_frames")
        return out

    def close(self) -> None:
        self._stop.set()
        if self.source is not None:
            self.source.stop()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        if self.transport is not None:
            self.transport.close()
