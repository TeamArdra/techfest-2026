"""Inline IPS bridge (Topology B): a real bump-in-the-wire between a flight controller and its GCS link.

::

    FC  <--fc transport-->  [ InlineIpsBridge ]  <--gcs transport-->  GCS / radio
                              |  forwarder thread: frame -> InlinePolicy -> other side
                              |  tap (copy of every ORIGINAL frame, both directions)
                              v
                           analyser thread: LiveMavlinkSource -> IDSPipeline -> MitigationController
                              |  controller state -> InlinePolicy (quarantine / rewrite / QoS)
                              |  ACTIVE_IPS counter-frames -> FC transport

Design rules
------------
* The forwarding path never waits on the analyser: detection can be slow or stall without delaying a
  frame. The policy's dynamic rules lapse on their own when the analyser stops touching them
  (``InlinePolicy.dynamic_ttl_s``), so a stalled analyser means transparent forwarding.
* The detectors see the ORIGINAL frames (before any drop or rewrite), so an attack is still detected
  while it is being filtered.
* ``PASSIVE`` / ``ADVISORY`` forward every frame byte-identically; only ``ACTIVE_IPS`` enforces. ADVISORY
  sends nothing to the vehicle either; STATUSTEXT goes to the GCS side only.
* Unframeable bytes are dropped by the transports (counted there); no valid frame is altered unless a rule fires.
* A hook exception forwards the original frame (fail-open, counted in ``policy.hook_errors``).

What this does NOT give you: a process or power failure of the companion cuts the link, because both ports
terminate here. A real installation needs a hardware bypass (relay or splitter) for that; the software
watchdog above only covers a stalled analyser. Latency is measured per frame (``status()['latency_us']``)
on the host it runs on; nothing here has been measured on a companion computer or a flight controller.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any, Protocol

from ..config import AegisConfig, load_config
from ..mitigation.controller import MitigationController
from ..mitigation.inline_policy import InlinePolicy
from ..mitigation.types import DefenseMode
from ..pipeline import IDSPipeline
from ..proxy.hooks import FrameContext
from ..proxy.transport import split_frames
from ..sources.mavlink_live import LiveMavlinkSource


class BridgeTransport(Protocol):
    """A frame transport that can also write (``SerialMavlinkTransport`` satisfies it)."""

    def poll(self) -> list[tuple[int, bytes]]: ...

    def send(self, data: bytes) -> bool: ...

    def close(self) -> None: ...


class TapTransport:
    """``FrameTransport`` fed by the bridge: the analyser reads the original frames from here."""

    def __init__(self, maxlen: int = 65536) -> None:
        self._q: deque[tuple[int, bytes]] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self.dropped_overflow = 0

    def push(self, stamp_ns: int, data: bytes) -> None:
        with self._lock:
            if len(self._q) == self._q.maxlen:
                self.dropped_overflow += 1
            self._q.append((stamp_ns, data))

    def poll(self) -> list[tuple[int, bytes]]:
        with self._lock:
            out = list(self._q)
            self._q.clear()
        return out

    def close(self) -> None:
        return None


class InlineIpsBridge:
    def __init__(
        self,
        fc: BridgeTransport,
        gcs: BridgeTransport,
        *,
        cfg: AegisConfig | None = None,
        config_dir: str | None = None,
        mode: DefenseMode | str = DefenseMode.PASSIVE,
        trusted_sysids: tuple[int, ...] | None = None,
        vehicle_sysids: tuple[int, ...] | None = None,
        sample_rate_hz: float = 10.0,
        store: Any | None = None,
        run_id: str = "ips-bridge",
        secret_key: bytes | None = None,
        allow_unsigned_from_trusted: bool = False,
        signing_max_age_s: float | None = None,
        signing_state_path: str | None = None,
        idle_sleep_s: float = 0.0005,
        ekf_secondary: bool | None = None,
        clock_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.fc, self.gcs = fc, gcs
        self._secret_key = secret_key
        self.cfg = cfg or load_config(config_dir)
        proto = self.cfg.detector.get("protocol", {})
        self.pipeline = IDSPipeline(self.cfg, model_path=None, firmware_dir=None)  # ML is simulation-only
        self.controller = MitigationController(mode=DefenseMode(mode), secret_key=secret_key)
        self.controller.set_capabilities(ekf_secondary=ekf_secondary)
        self.policy = InlinePolicy(
            self.controller.sanitizer,
            trusted_sysids=trusted_sysids if trusted_sysids is not None else tuple(proto.get("expected_gcs_sysids", (255, 254))),
            vehicle_sysids=vehicle_sysids if vehicle_sysids is not None else tuple(proto.get("expected_sysids", (1,))),
            signing_key=secret_key, allow_unsigned_from_trusted=allow_unsigned_from_trusted,
            max_age_s=signing_max_age_s, state_path=signing_state_path,
        )
        self.policy.set_enforce(self.controller.mode == DefenseMode.ACTIVE_IPS)
        self.tap = TapTransport()
        self.rate_hz = sample_rate_hz
        self.store = store
        self.run_id = run_id
        self._clock_ns = clock_ns
        self._idle = idle_sleep_s
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._source: LiveMavlinkSource | None = None
        self._lat_us: deque[float] = deque(maxlen=20000)
        # counters
        self.frames_down = 0
        self.frames_up = 0
        self.forwarded_down = 0
        self.forwarded_up = 0
        self.dropped_down = 0
        self.dropped_up = 0
        self.send_failures = 0
        self.counter_frames_sent = 0
        self.decisions = 0
        self.alerts = 0
        self.analyser_errors = 0
        self.last_error: str | None = None
        self.last_summary: str = ""

    # -- lifecycle ----------------------------------------------------------- #

    def start(self) -> InlineIpsBridge:
        for name, target in (("ips-forward", self._forward_loop), ("ips-analyse", self._analyse_loop)):
            th = threading.Thread(target=target, name=name, daemon=True)
            th.start()
            self._threads.append(th)
        return self

    def close(self) -> None:
        self._stop.set()
        if self._source is not None:
            self._source.stop()
        for th in self._threads:
            if th is not threading.current_thread():
                th.join(timeout=2.0)
        self.policy.flush()
        for tr in (self.fc, self.gcs):
            with contextlib.suppress(Exception):
                tr.close()

    def __enter__(self) -> InlineIpsBridge:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def set_mode(self, mode: DefenseMode | str) -> None:
        """Operator posture change. Leaving ACTIVE_IPS clears every enforcement state at once."""
        self.controller.set_mode(mode)
        self.policy.set_enforce(self.controller.mode == DefenseMode.ACTIVE_IPS)

    # -- forwarding ---------------------------------------------------------- #

    def pump_once(self) -> int:
        """One non-blocking forwarding cycle (also driven directly by tests). Returns frames handled."""
        n = 0
        for stamp, data in self.fc.poll():
            n += self._handle(stamp, data, "down")
        for stamp, data in self.gcs.poll():
            n += self._handle(stamp, data, "up")
        return n

    def _handle(self, stamp: int, data: bytes, direction: str) -> int:
        frames, _bad = split_frames(data)
        if not frames:
            return 0
        n = 0
        hook = self.policy.down if direction == "down" else self.policy.up
        dest = self.gcs if direction == "down" else self.fc
        for fr in frames:
            t0 = time.perf_counter_ns()
            self.tap.push(stamp, fr.raw)  # the detectors always see the original
            ctx = FrameContext(direction=direction, raw=fr.raw, recv_ns=stamp, sysid=fr.sysid,  # type: ignore[arg-type]
                               compid=fr.compid, seq=fr.seq, msgid=fr.msgid, signed=fr.signed)
            try:
                out = hook(ctx)
            except Exception:  # noqa: BLE001 - never stop forwarding
                self.policy.hook_errors += 1
                out = [fr.raw]
            if direction == "down":
                self.frames_down += 1
            else:
                self.frames_up += 1
            if not out:
                if direction == "down":
                    self.dropped_down += 1
                else:
                    self.dropped_up += 1
            for raw in out:
                if dest.send(raw):
                    if direction == "down":
                        self.forwarded_down += 1
                    else:
                        self.forwarded_up += 1
                else:
                    self.send_failures += 1
            self._lat_us.append((time.perf_counter_ns() - t0) / 1000.0)
            n += 1
        return n

    def _forward_loop(self) -> None:
        while not self._stop.is_set():
            try:
                busy = self.pump_once()
            except Exception as exc:  # noqa: BLE001 - the loop outlives any single bad cycle
                self.last_error = repr(exc)
                busy = 0
            if not busy:
                self._stop.wait(self._idle)

    # -- analysis ------------------------------------------------------------ #

    def analyse_tick(self, tick: Any) -> None:
        """Process one tick: detect, run the controller, push its state into the policy, send counter-frames."""
        assessment = self.pipeline.process_tick(tick)
        if assessment is None or self.pipeline.last_frame is None:
            return
        self.decisions += 1
        act = self.controller.step(self.pipeline.last_frame, assessment)
        self.last_summary = act.summary
        self.policy.touch()
        if assessment.is_alert:
            self.alerts += 1
            if self.store is not None:
                with contextlib.suppress(Exception):
                    self.store.log_event(assessment, self.run_id)
        if self.controller.mode == DefenseMode.ACTIVE_IPS:
            for frame in act.counter_frames:
                if self.fc.send(frame):  # corrective commands go to the flight controller only
                    self.counter_frames_sent += 1
                else:
                    self.send_failures += 1

    def _analyse_loop(self) -> None:
        self._source = LiveMavlinkSource(self.tap, sample_rate_hz=self.rate_hz, origin="start",
                                         secret_key=self._secret_key)
        try:
            for tick in self._source.stream():
                if self._stop.is_set():
                    return
                try:
                    self.analyse_tick(tick)
                except Exception as exc:  # noqa: BLE001 - a detector bug must not stop the link
                    self.analyser_errors += 1
                    self.last_error = repr(exc)
        except Exception as exc:  # noqa: BLE001
            self.last_error = repr(exc)

    # -- observability ------------------------------------------------------- #

    def status(self) -> dict[str, Any]:
        lat = sorted(self._lat_us)

        def pct(q: float) -> float | None:
            return round(lat[min(len(lat) - 1, int(q * len(lat)))], 1) if lat else None

        return {
            "mode": self.controller.mode.value, "state": self.controller.state.value,
            "frames": {"down": self.frames_down, "up": self.frames_up,
                       "forwarded_down": self.forwarded_down, "forwarded_up": self.forwarded_up,
                       "dropped_down": self.dropped_down, "dropped_up": self.dropped_up,
                       "send_failures": self.send_failures, "tap_overflow": self.tap.dropped_overflow},
            "latency_us": {"p50": pct(0.50), "p95": pct(0.95), "max": round(lat[-1], 1) if lat else None,
                           "samples": len(lat)},
            "policy": self.policy.stats(),
            "analyser": {"decisions": self.decisions, "alerts": self.alerts, "errors": self.analyser_errors,
                         "counter_frames_sent": self.counter_frames_sent, "summary": self.last_summary,
                         "ekf_secondary": self.controller.ekf_secondary_available},
            "last_error": self.last_error,
        }
