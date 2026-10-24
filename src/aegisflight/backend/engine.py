"""Live IDS engine for the dashboard backend: one startup-selected telemetry source.

Drives the same pipeline as the benchmark, but in *real time*, and pushes an
update to every connected WebSocket subscriber. The source is chosen once at
startup (:class:`~aegisflight.backend.sources.SourceSpec`):

* ``SIM`` (default): the simulator encodes/decodes genuine MAVLink each tick;
  attacks can be injected and cleared at runtime by swapping the source's active
  attack (the source reads ``self.attack`` fresh each tick).
* ``REPLAY`` / ``SITL`` / ``BENCH``: the existing ingestion stack (tlog replay,
  loopback UDP, serial) runs in a background thread and its ticks enter the SAME
  ``IDSPipeline`` and the SAME ``EventStore`` path. These sources are read-only:
  no control or attack endpoint applies to them and nothing is ever transmitted.

Every update carries ``environment`` (and ``sim``, true only for SIM) plus the
link state, so the dashboard can never present simulated, replayed or stale data
as live physical telemetry.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import tempfile
import time
from collections import deque
from pathlib import Path

import numpy as np

from ..attacks import ATTACK_REGISTRY, build_attack
from ..attacks.base import NoAttack
from ..config import AegisConfig, load_config
from ..core.enums import IntegrityStatus
from ..core.geo import haversine_m
from ..logging import EventStore
from ..pipeline import IDSPipeline
from ..sources.stream import SimulatedTelemetrySource, TelemetryTick
from .sources import LiveFeed, SourceSpec

# Long "live" duration so the survey pattern flies continuously for a demo.
_LIVE_DURATION_S = 100_000.0

GPS_FIX_NAMES = {0: "NO_GPS", 1: "NO_FIX", 2: "2D_FIX", 3: "3D_FIX", 4: "DGPS", 5: "RTK_FLOAT",
                 6: "RTK_FIXED", 7: "STATIC", 8: "PPP"}


class LinkMonitor:
    """Application-level link health, computed from the ticks themselves (display only).

    Counts and ages are on the source's tick clock (``tick.t``), so a dead live link -- which keeps
    ticking (``origin="start"``) -- shows growing ages instead of frozen "fresh" values. Nothing here
    is fed back into the detectors: detector-facing presence lives in ``pipeline.last_frame``.
    """

    def __init__(self, stale_after_s: float, min_fix: int, min_sats: int) -> None:
        self.stale_after_s = stale_after_s
        self.min_fix, self.min_sats = min_fix, min_sats
        self.t: float | None = None
        self.frames = 0
        self.last_frame_t: float | None = None
        self.msgs: dict[str, list[float]] = {}  # name -> [count, last tick t]
        self.fix: int | None = None
        self.sats: int | None = None
        self.gps_raw_t: float | None = None
        self.gpi_t: float | None = None
        self.gpi_zero: bool | None = None

    def observe(self, tick: TelemetryTick) -> None:
        self.t = tick.t
        if tick.messages:
            self.last_frame_t = tick.t
        for m in tick.messages:
            self.frames += 1
            e = self.msgs.setdefault(m.msgname, [0, tick.t])
            e[0] += 1
            e[1] = tick.t
            f = m.fields
            if m.msgname == "GPS_RAW_INT":
                self.fix = int(f.get("fix_type", 0))
                self.sats = int(f.get("satellites_visible", 0))
                self.gps_raw_t = tick.t
            elif m.msgname == "GLOBAL_POSITION_INT":
                self.gpi_t = tick.t
                self.gpi_zero = int(f.get("lat", 0)) == 0 and int(f.get("lon", 0)) == 0

    def _age(self, last: float | None) -> float | None:
        return None if last is None or self.t is None else round(self.t - last, 2)

    def snapshot(self) -> dict:
        valid = None if self.fix is None else bool(self.fix >= self.min_fix and (self.sats or 0) >= self.min_sats)
        return {
            "frames": self.frames,
            "last_frame_age_s": self._age(self.last_frame_t),
            "stale_after_s": self.stale_after_s,
            "messages": {k: {"count": int(c), "age_s": self._age(t)} for k, (c, t) in sorted(self.msgs.items())},
            "gps": {"fix_type": self.fix, "fix_name": GPS_FIX_NAMES.get(self.fix) if self.fix is not None else None,
                    "satellites": self.sats, "valid_fix": valid,
                    "gps_raw_age_s": self._age(self.gps_raw_t),
                    "position_age_s": self._age(self.gpi_t), "position_zero": self.gpi_zero},
        }

# Rolling window (wall-clock seconds) used to report *current* live throughput.
# A window — rather than messages-since-boot / uptime — keeps the displayed rate
# honest across resets (counters restart but a boot-time denominator would not).
_THROUGHPUT_WINDOW_S = 5.0


class LiveEngine:
    def __init__(self, cfg: AegisConfig | None = None, db_path: str | None = None,
                 model_path: str = "models/isoforest.joblib", spec: SourceSpec | None = None) -> None:
        self.spec = spec or SourceSpec()
        self.is_sim = self.spec.kind == "sim"
        self.cfg = cfg or load_config(self.spec.config_dir)
        self.cfg.simulation["duration_s"] = _LIVE_DURATION_S
        # ML: Stage-1 behaviour for SIM; never for real/replayed telemetry (SourceSpec refuses it)
        self.model_path = model_path if self.spec.ml_enabled and Path(model_path).exists() else None
        self.db_path = db_path or "artifacts/aegisflight_live.sqlite"
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self.dt = 1.0 / float(self.cfg.simulation.get("sample_rate_hz", 10.0))
        # the firmware fixture is part of the simulation; a real source has no verifier (integrity UNKNOWN)
        self.fw_dir = tempfile.mkdtemp(prefix="aegis_live_fw_") if self.is_sim else None
        p = self.cfg.detector.get("protocol", {})
        self.link = LinkMonitor(float(p.get("heartbeat_timeout_s", 3.0)),
                                int(p.get("min_gnss_fix_type", 3)), int(p.get("min_gnss_satellites", 5)))
        self.feed: LiveFeed | None = None
        self._queue: asyncio.Queue | None = None
        self._feed_ended = False
        self._closed = False

        self._subscribers: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None
        self.running = False

        self._active_attack_name: str | None = None
        self._pending_attack: str | None = "__none__"  # sentinel: no change pending
        self._sim_t = 0.0
        self._t0_wall = time.time()
        self._n_messages = 0
        self._n_decisions = 0
        # Rolling (wall_time, cumulative_messages) samples for live throughput.
        self._msg_samples: deque[tuple[float, int]] = deque(maxlen=512)
        # Cumulative simulated flight-path length (metres), summed from reported
        # positions — the same methodology the benchmark uses (_distance_m).
        self._distance_m = 0.0
        self._last_pos: tuple[float, float] | None = None
        # Live time-to-detect: sim time an attack was injected, and the elapsed
        # time to the FIRST alert after that injection (this session only).
        self._attack_injected_t: float | None = None
        self._ttd_pending = False
        self._last_ttd_s: float | None = None
        self._latest_update: dict | None = None
        self._last_threat: dict = {}  # last DECISION's threat block (for status)
        self._run_seq = 0
        self._run_id = self._new_run_id()

        self._build()

    # -- lifecycle ---------------------------------------------------------- #

    def _new_run_id(self) -> str:
        """A unique run id per run, even across resets within the same second.

        A monotonic suffix keeps each run's hash chain independent (two resets
        in one wall-clock second would otherwise share a run_id and merge
        chains).
        """
        self._run_seq += 1
        prefix = "live" if self.is_sim else self.spec.environment.lower()
        return f"{time.strftime(prefix + '-%Y%m%d-%H%M%S')}-{self._run_seq}"

    def _start_run(self) -> None:
        # the source identity rides in the existing runs table (label + meta); the event schema is unchanged
        if self.is_sim:
            self.store.start_run(self._run_id, label="live-demo")
        else:
            self.store.start_run(self._run_id, label=f"{self.spec.environment.lower()}-{self.spec.kind}",
                                 meta=self.spec.run_meta())

    def _build(self) -> None:
        self.pipeline = IDSPipeline(self.cfg, model_path=self.model_path, firmware_dir=self.fw_dir)
        if self.is_sim:
            self.source = SimulatedTelemetrySource(self.cfg, NoAttack(), seed=42)
            self._gen = self.source.stream()
        else:
            self.source = None
            self.feed = LiveFeed(self.spec, 1.0 / self.dt)
        self.store = EventStore(self.db_path)
        self._start_run()

    async def start(self) -> None:
        """Start the live loop on the current event loop (idempotent).

        Must be awaited from the event loop — ``asyncio.create_task`` needs a
        running loop, so the REST endpoints that call it are ``async`` (a sync
        endpoint runs in a threadpool worker with no loop and would raise).
        """
        if self._closed:
            raise RuntimeError("engine is closed")
        if self.running:
            return
        self.running = True
        if self.is_sim:
            self._task = asyncio.create_task(self._loop())
            return
        if self.feed is None or self.feed.ended:
            self.feed = LiveFeed(self.spec, 1.0 / self.dt)
            self._feed_ended = False
        # Unbounded on purpose: a dropped tick would lose its frames and shift the tick-count decision
        # cadence. The producer thread hands each tick to this loop; nothing is ever dropped or reordered.
        self._queue = asyncio.Queue()
        loop, q = asyncio.get_running_loop(), self._queue

        def deliver(tick: TelemetryTick | None) -> None:
            try:
                loop.call_soon_threadsafe(q.put_nowait, tick)
            except RuntimeError:  # event loop already closed (shutdown)
                pass

        self.feed.start(deliver)
        self._task = asyncio.create_task(self._live_loop())

    async def stop(self) -> None:
        """Stop the live loop and await the task's cancellation.

        Safe to call when not running. Cancelling *and awaiting* the old task
        before any restart prevents two ``_loop`` coroutines from ever driving
        the same pipeline concurrently (a restart race).
        """
        self.running = False
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if self.feed is not None:
            # stop the producer, then close the transport (close alone would not stop the tick stream)
            await asyncio.to_thread(self.feed.close)

    async def close(self) -> None:
        """Final shutdown (app lifespan exit): stop the loop and the source (port released), close the event
        store and remove the simulated-firmware temp dir. Idempotent; a closed engine cannot be restarted."""
        if self._closed:
            return
        self._closed = True
        await self.stop()
        self.store.close()
        if self.fw_dir is not None:
            shutil.rmtree(self.fw_dir, ignore_errors=True)

    def reset(self) -> None:
        """Return the engine to a clean baseline (synchronous state reset).

        Task lifecycle is the caller's job: the REST reset endpoint awaits
        :meth:`stop` before this and :meth:`start` after, so this method does no
        async work and stays callable from tests / any thread. It reflashes the
        simulated firmware and clears all runtime state (see
        :meth:`IDSPipeline.reset`) and starts a fresh run id; historical event
        records from earlier runs are left untouched.

        SIM only: resetting the pipeline on a live link would erase detector memory (seen-flags, the
        "fix lost" history, the elapsed-time gates) -- see docs/THREAT_MODEL.md.
        """
        if not self.is_sim:
            raise RuntimeError("reset is simulation-only")
        self.running = False
        self._active_attack_name = None
        self._pending_attack = "__none__"
        self._sim_t = 0.0
        self._n_messages = 0
        self._n_decisions = 0
        self._msg_samples.clear()
        self._distance_m = 0.0
        self._last_pos = None
        self._attack_injected_t = None
        self._ttd_pending = False
        self._last_ttd_s = None
        self._latest_update = None
        self._last_threat = {}
        self.link = LinkMonitor(self.link.stale_after_s, self.link.min_fix, self.link.min_sats)
        # Restore the simulated vehicle to a clean baseline: this reflashes the
        # firmware fixture to known-good AND clears extractor/detector/fusion
        # state (see IDSPipeline.reset).
        self.pipeline.reset()
        self._run_id = self._new_run_id()
        self.source = SimulatedTelemetrySource(self.cfg, NoAttack(), seed=42)
        self._gen = self.source.stream()
        self._start_run()

    def set_attack(self, name: str | None) -> None:
        if not self.is_sim:
            raise RuntimeError("attacks are simulation-only")
        self._pending_attack = name or None

    # -- subscribers -------------------------------------------------------- #

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=32)
        self._subscribers.add(q)
        if self._latest_update:
            q.put_nowait(self._latest_update)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def _broadcast(self, msg: dict) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass  # slow client; drop this frame

    # -- attack swapping ---------------------------------------------------- #

    def _apply_pending_attack(self) -> None:
        if self._pending_attack == "__none__":
            return
        name = self._pending_attack
        self._pending_attack = "__none__"
        if not name or name in ("none", "benign"):
            self.source.attack = NoAttack()
            self._active_attack_name = None
            self._attack_injected_t = None
            self._ttd_pending = False
            return
        if name not in ATTACK_REGISTRY:
            return
        rng = np.random.default_rng(int(self._sim_t * 1000) & 0xFFFF)
        kwargs = {"firmware_dir": self.fw_dir} if name == "firmware_integrity" else {}
        atk = build_attack(name, self.cfg.attacks, rng, **kwargs)
        # Activate from *now* for a long window (until cleared).
        atk.start_s = self._sim_t
        atk.duration_s = _LIVE_DURATION_S
        self.source.attack = atk
        self._active_attack_name = name
        # Arm the live time-to-detect measurement: record the injection instant;
        # the first alert after this stamps the elapsed onset->detection time.
        self._attack_injected_t = self._sim_t
        self._ttd_pending = True

    # -- main loop ---------------------------------------------------------- #

    async def _loop(self) -> None:
        while self.running:
            t0 = time.perf_counter()
            self._apply_pending_attack()
            try:
                tick = next(self._gen)
            except StopIteration:
                self.source = SimulatedTelemetrySource(self.cfg, self.source.attack, seed=42)
                self._gen = self.source.stream()
                continue

            await self._process(tick)
            await asyncio.sleep(max(0.0, self.dt - (time.perf_counter() - t0)))

    async def _live_loop(self) -> None:
        """Consume ticks from the background feed (REPLAY / SITL / BENCH); the feed paces itself."""
        assert self._queue is not None
        while self.running:
            tick = await self._queue.get()
            if tick is None:  # finite source finished (replay) or the producer failed
                self._feed_ended = True
                # also when no tick ever arrived (e.g. the port never opened): subscribers must see the end state
                last = self._latest_update or self._make_update(self._sim_t, None)
                self._latest_update = {**last, "link": self.link_status()}
                await self._broadcast(self._latest_update)
                return
            await self._process(tick)

    async def _process(self, tick: TelemetryTick) -> None:
        """One tick through the shared pipeline -> event store -> subscribers (every source)."""
        self._sim_t = tick.t
        self._n_messages += len(tick.messages)
        self._msg_samples.append((time.time(), self._n_messages))
        self.link.observe(tick)
        assessment = self.pipeline.process_tick(tick)
        self._accumulate_distance()
        update = self._make_update(tick.t, assessment)
        self._latest_update = update
        if assessment is not None:
            self._n_decisions += 1
            self._last_threat = update.get("threat", {})
            if assessment.is_alert:
                # persisted only: /api/events reads the run back from the store (no in-memory copy)
                self.store.log_event(assessment, self._run_id)
                # First alert after an injection -> stamp live time-to-detect.
                if self._ttd_pending and self._attack_injected_t is not None:
                    self._last_ttd_s = round(assessment.t - self._attack_injected_t, 2)
                    self._ttd_pending = False
        await self._broadcast(update)

    # -- link state --------------------------------------------------------- #

    def link_status(self) -> dict:
        """Honest connection / freshness state (see LinkMonitor). SIM is always ``simulated``."""
        snap = self.link.snapshot()
        transport = self.feed.transport_stats() if self.feed is not None else None
        if self.is_sim:
            state = "simulated"
        elif self.feed is not None and self.feed.error:
            state = "error"  # the producer raised (or a port could not be opened with reconnect off)
        elif self._feed_ended or (self.feed is not None and self.feed.ended):
            state = "ended"
        elif transport is not None and transport.get("connected") is False:
            state = "disconnected"
        elif self.link.last_frame_t is None:
            state = "waiting"
        elif (snap["last_frame_age_s"] or 0.0) > self.link.stale_after_s:
            state = "stale"
        else:
            state = "live"
        return {"state": state, **snap, "transport": transport,
                "error": self.feed.error if self.feed is not None else None}

    # -- runtime metrics ---------------------------------------------------- #

    def _accumulate_distance(self) -> None:
        """Add the current leg to the cumulative simulated flight-path length.

        Uses the reported (telemetry) position, matching the benchmark's
        ``_distance_m`` methodology — this is simulated *path length*, not
        geographic range or straight-line displacement.
        """
        s = self.pipeline.extractor.snapshot
        if s.lat is None or s.lon is None:
            return
        pos = (s.lat, s.lon)
        if self._last_pos is not None:
            self._distance_m += haversine_m(
                self._last_pos[0], self._last_pos[1], pos[0], pos[1]
            )
        self._last_pos = pos

    def _throughput(self) -> float:
        """Current live throughput (msg/s) over a rolling wall-clock window.

        Falls back to the full available sample span when the window has not yet
        filled, and to 0.0 only when there is genuinely no interval to divide by.
        """
        samples = self._msg_samples
        if len(samples) < 2:
            return 0.0
        now = time.time()
        windowed = [(t, n) for (t, n) in samples if now - t <= _THROUGHPUT_WINDOW_S]
        span = windowed if len(windowed) >= 2 else list(samples)
        (t0, n0), (t1, n1) = span[0], span[-1]
        dt = t1 - t0
        return round((n1 - n0) / dt, 1) if dt > 0 else 0.0

    # -- serialisation ------------------------------------------------------ #

    def _make_update(self, t: float, assessment) -> dict:
        msg = {
            "type": "update",
            "sim": self.is_sim,
            "environment": self.spec.environment,
            "source": self.spec.describe(),
            "link": self.link_status(),
            "run_id": self._run_id,
            "t": round(t, 2),
            "telemetry": self.pipeline._telemetry_dict(),
            "attack_active": self._active_attack_name,
            "distance_m": round(self._distance_m, 1),
        }
        if assessment is not None:
            msg["threat"] = {
                "threat": assessment.threat,
                "threat_score": assessment.threat_score,
                "severity": assessment.severity.value,
                "attack_type": assessment.attack_type.value,
                "confidence": assessment.confidence,
                "evidence": assessment.evidence,
                "detector_scores": assessment.detector_scores,
                "contributing_detectors": assessment.contributing_detectors,
                "integrity_status": assessment.integrity_status.value,
                "latency_ms": round(assessment.latency_ms, 3),
                "is_alert": assessment.is_alert,
            }
        return msg

    # -- status snapshots --------------------------------------------------- #

    def status(self) -> dict:
        thr = self._last_threat
        return {
            "running": self.running,
            "sim": self.is_sim,
            "environment": self.spec.environment,
            "source": self.spec.describe(),
            "link": self.link_status(),
            "sim_time_s": round(self._sim_t, 1),
            "uptime_s": round(time.time() - self._t0_wall, 1),
            "active_attack": self._active_attack_name,
            "ml_available": self.pipeline.ml_available,
            "threat": thr.get("threat", False),
            "severity": thr.get("severity", "NORMAL"),
            "attack_type": thr.get("attack_type", "BENIGN"),
            "threat_score": thr.get("threat_score", 0.0),
            # before the first decision: a real / replayed source has no firmware verifier
            "integrity_status": thr.get("integrity_status",
                                        (IntegrityStatus.VALID if self.is_sim else IntegrityStatus.UNKNOWN).value),
            "distance_m": round(self._distance_m, 1),
            "run_id": self._run_id,
        }

    def metrics(self) -> dict:
        cs = self.store.verify_chain(self._run_id)
        return {
            "messages_processed": self._n_messages,
            "decisions": self._n_decisions,
            "alerts": cs.length,  # persisted alerts of the current run (== event_log.count)
            "throughput_msgs_per_s": self._throughput(),
            # Compute cost of one fused decision (NOT attack-onset latency).
            "decision_compute_ms": self._last_threat.get("latency_ms"),
            "last_latency_ms": self._last_threat.get("latency_ms"),  # legacy alias
            # Attack-onset -> first-detection for the current session (or null).
            "time_to_detect_s": self._last_ttd_s,
            "distance_m": round(self._distance_m, 1),
            "event_log": {"count": cs.length, "chain_ok": cs.ok},
            "ml_available": self.pipeline.ml_available,
            "environment": self.spec.environment,
        }

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        """The current run's alerts, newest first, read back from the EventStore (no in-memory copy): each
        stored row (id, hash-chain fields, evidence, ...) plus the run's source ``environment``."""
        env = self.spec.environment
        return [{**row, "environment": env} for row in self.store.get_events(run_id=self._run_id, limit=limit)]
