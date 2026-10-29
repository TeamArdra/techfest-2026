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
import math
import shutil
import tempfile
import time
from collections import deque
from pathlib import Path
from typing import Any

import numpy as np

from ..attacks import ATTACK_REGISTRY, build_attack
from ..attacks.base import NoAttack
from ..config import AegisConfig, load_config
from ..core.enums import AttackType, IntegrityStatus
from ..core.geo import haversine_m, offset_latlon
from ..core.gps_health import GpsHealthObserver
from ..logging import EventStore
from ..mitigation import DefenseMode, MitigationController, MitigationState
from ..mitigation.types import AttackSubMode
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

    _UPLINK_MSGS = frozenset({"COMMAND_LONG", "COMMAND_INT", "SET_MODE"})

    def __init__(self, stale_after_s: float, min_fix: int, min_sats: int,
                 gcs_sysids: tuple[int, ...] = (255, 254)) -> None:
        self.stale_after_s = stale_after_s
        self.gcs_sysids = tuple(int(x) for x in gcs_sysids)
        self.uplink_frames = 0  # frames sent BY a ground station or carrying COMMAND / SET_MODE (uplink evidence)
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
        # vehicle-stated estimator / GPS-health conditions: status only, never an alert (core/gps_health.py)
        self.health = GpsHealthObserver(stale_after_s=2.0)

    def observe(self, tick: TelemetryTick) -> None:
        self.t = tick.t
        if tick.messages:
            self.last_frame_t = tick.t
        for m in tick.messages:
            self.frames += 1
            if m.sysid in self.gcs_sysids or m.msgname in self._UPLINK_MSGS:
                self.uplink_frames += 1
            e = self.msgs.setdefault(m.msgname, [0, tick.t])
            e[0] += 1
            e[1] = tick.t
            f = m.fields
            self.health.observe(m.msgname, f, tick.t)
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
        h = self.health.snapshot(self.t if self.t is not None else 0.0)
        return {
            "frames": self.frames,
            "last_frame_age_s": self._age(self.last_frame_t),
            "stale_after_s": self.stale_after_s,
            "messages": {k: {"count": int(c), "age_s": self._age(t)} for k, (c, t) in sorted(self.msgs.items())},
            "gps": {"fix_type": self.fix, "fix_name": GPS_FIX_NAMES.get(self.fix) if self.fix is not None else None,
                    "satellites": self.sats, "valid_fix": valid,
                    "gps_raw_age_s": self._age(self.gps_raw_t),
                    "position_age_s": self._age(self.gpi_t), "position_zero": self.gpi_zero,
                    # additive: what the vehicle itself says about this position (not an authenticity check)
                    "hdop": h["hdop"], "ekf_flags": h["ekf_flags"], "ekf_age_s": h["ekf_age_s"],
                    "horizontal_solution": h["horizontal_solution"], "gps_healthy": h["gps_healthy"],
                    "quality_flags": h["quality_flags"]},
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
        if not self.is_sim:  # real / recorded link: learn its own normal message rate (SIM unchanged)
            if p.get("auto_rate_baseline") is None:
                p["auto_rate_baseline"] = True
        self.link = LinkMonitor(float(p.get("heartbeat_timeout_s", 3.0)),
                                int(p.get("min_gnss_fix_type", 3)), int(p.get("min_gnss_satellites", 5)),
                                tuple(p.get("expected_gcs_sysids", (255, 254))))
        self.feed: LiveFeed | None = None
        self._queue: asyncio.Queue | None = None
        self._feed_ended = False
        self._closed = False

        self._subscribers: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None
        self.running = False

        self._active_attack_name: str | None = None
        self._pending_attack: str | None = "__none__"  # sentinel: no change pending
        self._pending_attack_mode: str | None = None
        self._pending_drift_rate: float | None = None
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
        self._last_assessment = None
        self._last_mitigation_action = None
        self.mitigation = MitigationController(mode=DefenseMode(self.spec.defense_mode))
        self._run_seq = 0
        self._run_id = self._new_run_id()

        # Closed-loop cyber-physical state twin (simulates real drone dynamics under attack)
        self._cp_lat: float | None = None
        self._cp_lon: float | None = None
        self._cp_alt: float | None = None
        self._cp_mode: str | None = None
        self._cp_armed: bool | None = None
        self._cp_speed: float | None = None
        self._ips_lat: float | None = None
        self._ips_lon: float | None = None
        self._ips_alt: float | None = None
        self._ips_mode: str | None = None
        self._ips_armed: bool | None = None
        self._ips_speed: float | None = None
        self._last_cp_t: float | None = None
        self._top_a_detour_t: float = 0.0

        # The SIM twin models an inline (hybrid) deployment; the real topology is detected (topology_info()).
        self.topology: str = "a+b"
        self.topology_reasons: list[str] = [
            "Simulation twin models an inline deployment; nothing is transmitted to a vehicle",
        ]

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
        crossend = None
        if not self.is_sim:  # inert until a bridge summary is seen; never used for SIM
            from ..detectors.crossend import CrossEndMonitor, load_signing_key
            crossend = CrossEndMonitor(load_signing_key(self.spec.signing_key_file) if self.spec.signing_key_file else None)
        self.pipeline = IDSPipeline(self.cfg, model_path=self.model_path, firmware_dir=self.fw_dir, crossend=crossend)
        if self.is_sim:
            self.source = SimulatedTelemetrySource(self.cfg, NoAttack(), seed=42)
            self._gen = self.source.stream()
        else:
            self.source = None
            self.feed = LiveFeed(self.spec, 1.0 / self.dt)
        self.store = EventStore(self.db_path)
        self.gcs_notifier = None
        if getattr(self.spec, "gcs_notify", False):
            from ..mavlink.gcs_notifier import GcsNotifier
            target = ((self.spec.gcs_notify_host, self.spec.gcs_notify_port)
                      if getattr(self.spec, "gcs_notify_port", None) else None)
            self.gcs_notifier = GcsNotifier(enabled=True, udp_target=target)
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
        # STATUSTEXT alerts may also go out over the vehicle link's transport (UDP target set separately)
        if self.gcs_notifier is not None and getattr(self.feed, "transport", None) is not None:
            self.gcs_notifier.transport = self.feed.transport
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
        if self.gcs_notifier is not None:
            self.gcs_notifier.close()
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
        self._pending_attack_mode = None
        self._pending_drift_rate = None
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
        self._last_assessment = None
        self._last_mitigation_action = None
        self.mitigation.reset()
        self._cp_lat = None
        self._cp_lon = None
        self._cp_alt = None
        self._cp_mode = None
        self._cp_armed = None
        self._cp_speed = None
        self._ips_lat = None
        self._ips_lon = None
        self._ips_alt = None
        self._ips_mode = None
        self._ips_armed = None
        self._ips_speed = None
        self._last_cp_t = None
        self._top_a_detour_t = 0.0
        self.link = LinkMonitor(self.link.stale_after_s, self.link.min_fix, self.link.min_sats, self.link.gcs_sysids)
        # Restore the simulated vehicle to a clean baseline: this reflashes the
        # firmware fixture to known-good AND clears extractor/detector/fusion
        # state (see IDSPipeline.reset).
        self.pipeline.reset()
        self._run_id = self._new_run_id()
        self.source = SimulatedTelemetrySource(self.cfg, NoAttack(), seed=42)
        self._gen = self.source.stream()
        self._start_run()

    def set_defense_mode(self, mode: str) -> dict:
        self.mitigation.set_mode(mode)
        if self.mitigation.mode == DefenseMode.ACTIVE_IPS and self._cp_lat is not None:
            # Seed recovery from current position: for GPS attacks, use trusted dead-reckoning;
            # for command hijacks, seed from current deviated position so the drone smoothly rejoins track
            is_gps = "gps" in str(self._active_attack_name or "").lower()
            if is_gps and self.mitigation.golden.dr_lat is not None:
                self._ips_lat = self.mitigation.golden.dr_lat
                self._ips_lon = self.mitigation.golden.dr_lon
            else:
                self._ips_lat = self._cp_lat
                self._ips_lon = self._cp_lon
            self._ips_alt = self._cp_alt
            self._ips_mode = "AUTO"
            self._ips_speed = 12.0
            self._ips_armed = True
        if self._last_mitigation_action is not None:
            self._last_mitigation_action.mode = self.mitigation.mode
            self._last_mitigation_action.actions = list(self.mitigation.action_history)
            if self.mitigation.mode != DefenseMode.ACTIVE_IPS:
                self._last_mitigation_action.sanitize_gps = False
                self._last_mitigation_action.sanitize_alt = False
                self._last_mitigation_action.ekf_switched = False
        return {"mode": self.mitigation.mode.value}

    def topology_info(self) -> dict:
        """Detected topology (read-only): derived from the source and what the link has actually shown."""
        from ..hal.topology_status import replay_topology, sidecar_topology, sim_topology
        posture = self.mitigation.mode
        if self.is_sim:
            return sim_topology(posture)
        if self.spec.kind == "replay":
            return replay_topology(posture)
        if self.spec.kind in ("serial", "udp"):
            st = self.feed.transport_stats() if self.feed is not None else None
            conn = st.get("connected") if st else None
            name = self.spec.port if self.spec.kind == "serial" else f"udp:{self.spec.udp_port}"
            writable = True  # serial / udp transports carry counter-commands; replay never reaches here
            return sidecar_topology(posture, connected=conn if isinstance(conn, bool) else None,
                                    name=str(name) if name else None,
                                    uplink_seen=self.link.uplink_frames > 0, writable=writable)
        from ..hal.topology_status import unknown_topology
        return unknown_topology(posture)

    def _transmit(self, frames: list[bytes]) -> None:
        """Send counter-actuation frames on the live transport. Only in ACTIVE_IPS; a no-op for SIM / replay
        (no transport) and for PASSIVE / ADVISORY, which never actuate."""
        if self.mitigation.mode != DefenseMode.ACTIVE_IPS or not frames:
            return
        transport = getattr(self.feed, "transport", None) if self.feed is not None else None
        if transport is None:
            return
        for f in frames:
            with contextlib.suppress(Exception):
                transport.send(f)

    def defense_override(self, action: str) -> dict:
        act = self.mitigation.manual_override(action)
        self._last_mitigation_action = act
        self._transmit(act.counter_frames)
        return act.to_dict()

    def set_attack(
        self,
        name: str | None,
        mode: str | None = None,
        drift_rate_ms: float | None = None,
    ) -> None:
        if not self.is_sim:
            raise RuntimeError("attacks are simulation-only")
        self._pending_attack = name or None
        self._pending_attack_mode = mode
        self._pending_drift_rate = drift_rate_ms

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
            self._pending_attack_mode = None
            self._pending_drift_rate = None
            self._attack_injected_t = None
            self._ttd_pending = False
            self._top_a_detour_t = 0.0
            self.mitigation.reset()
            self._cp_lat = None
            self._cp_lon = None
            self._cp_alt = None
            self._cp_mode = None
            self._cp_speed = None
            self._ips_lat = None
            self._ips_lon = None
            self._ips_alt = None
            return
        if name not in ATTACK_REGISTRY:
            return

        self._top_a_detour_t = 0.0
        if self.mitigation.mode == DefenseMode.ACTIVE_IPS:
            self._cp_lat = None
            self._cp_lon = None
            self._cp_alt = None
            self._ips_lat = None
            self._ips_lon = None
            self._ips_alt = None

        # When switching to a non-GPS attack, unlatch any leftover GPS sanitizer flags
        if not name.startswith("gps"):
            self.mitigation._sanitize_gps_latched = False
            self.mitigation._ekf_switched = False
            self.mitigation.sanitizer.sanitize_gps = False
        rng = np.random.default_rng(int(self._sim_t * 1000) & 0xFFFF)
        kwargs = {"firmware_dir": self.fw_dir} if name == "firmware_integrity" else {}
        atk = build_attack(name, self.cfg.attacks, rng, **kwargs)
        if getattr(self, "_pending_attack_mode", None):
            atk.mode = self._pending_attack_mode
        if getattr(self, "_pending_drift_rate", None) is not None and hasattr(atk, "drift_rate"):
            atk.drift_rate = float(self._pending_drift_rate)
        # Activate from *now* for a long window (until cleared).
        atk.start_s = self._sim_t
        atk.duration_s = _LIVE_DURATION_S
        self.source.attack = atk
        submode_tag = f":{atk.mode}" if getattr(self, "_pending_attack_mode", None) else ""
        self._active_attack_name = f"{name}{submode_tag}"
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

        # Compact telemetry optimization:
        # During active mitigation (state != NOMINAL), skip intermediate non-decision ticks
        # to save companion compute and GCS network bandwidth.
        if self.is_sim and self.mitigation.state != MitigationState.NOMINAL and assessment is None:
            return

        if assessment is not None:
            self._last_assessment = assessment
            self._n_decisions += 1

            # Step autonomous mitigation controller BEFORE building update payload
            last_frame = self.pipeline.last_frame
            if last_frame is not None:
                act = self.mitigation.step(last_frame, assessment)
                self._last_mitigation_action = act

                # Topology B inline frame sanitization stats & filtering
                if self.mitigation.mode == DefenseMode.ACTIVE_IPS and self.is_sim:
                    for msg_env in tick.messages:
                        if msg_env.sysid in self.mitigation.sanitizer.quarantined_sysids:
                            self.mitigation.sanitizer.frames_dropped += 1
                        elif self.mitigation.sanitizer.sanitize_gps and msg_env.msgname == "GLOBAL_POSITION_INT":
                            self.mitigation.sanitizer.frames_sanitized += 1
                        elif self.mitigation.sanitizer.sanitize_alt and msg_env.msgname in ("GLOBAL_POSITION_INT", "VFR_HUD"):
                            self.mitigation.sanitizer.frames_sanitized += 1

                # Transmit counter-actuation frames if in ACTIVE_IPS mode
                self._transmit(act.counter_frames)

        if self.is_sim:  # simulated physics twin: never for a real / recorded vehicle
            self._step_cyber_physical_twin(tick.t, self.pipeline._telemetry_dict(), assessment)
        update = self._make_update(tick.t, assessment)
        if assessment is not None:
            self._last_threat = update.get("threat", {})
            if self._last_mitigation_action is not None:
                update["mitigation"] = self._last_mitigation_action.to_dict()

            if assessment.is_alert:
                # persisted only: /api/events reads the run back from the store (no in-memory copy)
                self.store.log_event(assessment, self._run_id)
                if self.gcs_notifier is not None:
                    self.gcs_notifier.notify(assessment)
                # First alert after an injection -> stamp live time-to-detect.
                if self._ttd_pending and self._attack_injected_t is not None:
                    self._last_ttd_s = round(assessment.t - self._attack_injected_t, 2)
                    self._ttd_pending = False
        elif self._last_mitigation_action is not None:
            update["mitigation"] = self._last_mitigation_action.to_dict()

        self._latest_update = update
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

    def _step_cyber_physical_twin(self, tick_t: float, raw_tele: dict, assessment: Any) -> None:
        """Closed-loop cyber-physical simulation twin.

        Simulates real vehicle physics and flight controller execution:
        - In PASSIVE / ADVISORY: The flight controller executes rogue commands (e.g. LAND,
          RTL, disarm, or veering off in GUIDED) and follows spoofed GPS positions.
        - In ACTIVE_IPS:
          - Topology B (Inline): Rogue frames are dropped before FC; 0.0 m detour.
          - Topology A (Sidecar): FC briefly reacts (0.4s reaction window) before
            counter-command (SET_MODE AUTO) recovers vehicle to survey track.
          - GPS Spoofing: EKF switch / Golden State dead reckoning maintains true position.
        """
        base_lat = raw_tele.get("lat")
        base_lon = raw_tele.get("lon")
        base_alt = raw_tele.get("rel_alt") if raw_tele.get("rel_alt") is not None else raw_tele.get("alt_msl", 60.0)
        base_mode = raw_tele.get("flight_mode") or "AUTO"
        base_armed = raw_tele.get("armed", True)
        base_speed = raw_tele.get("groundspeed") if raw_tele.get("groundspeed") is not None else 12.0

        if base_lat is None or base_lon is None:
            return

        has_threat = (
            self._active_attack_name is not None
            or (assessment is not None and assessment.threat)
        )

        if not has_threat:
            self._cp_lat = base_lat
            self._cp_lon = base_lon
            self._cp_alt = base_alt
            self._cp_mode = base_mode
            self._cp_armed = base_armed
            self._cp_speed = base_speed
            self._ips_lat = base_lat
            self._ips_lon = base_lon
            self._ips_alt = base_alt
            self._ips_mode = base_mode
            self._ips_armed = base_armed
            self._ips_speed = base_speed
            self._top_a_detour_t = 0.0
            self._last_cp_t = tick_t
            return

        dt = max(0.01, min(tick_t - (self._last_cp_t or tick_t), 0.5))
        self._last_cp_t = tick_t

        if self._cp_lat is None:
            self._cp_lat = base_lat
        if self._cp_lon is None:
            self._cp_lon = base_lon
        if self._cp_alt is None:
            self._cp_alt = base_alt
        if self._cp_mode is None:
            self._cp_mode = base_mode
        if self._cp_armed is None:
            self._cp_armed = base_armed
        if self._cp_speed is None:
            self._cp_speed = base_speed

        if self._ips_lat is None:
            self._ips_lat = base_lat
        if self._ips_lon is None:
            self._ips_lon = base_lon
        if self._ips_alt is None:
            self._ips_alt = base_alt
        if self._ips_mode is None:
            self._ips_mode = base_mode
        if self._ips_armed is None:
            self._ips_armed = base_armed
        if self._ips_speed is None:
            self._ips_speed = base_speed

        atk_tag = str(self._active_attack_name or "").lower()
        submode_tag = ""
        if assessment is not None and getattr(assessment, "sub_mode", None):
            submode_tag = str(assessment.sub_mode).lower()

        # 1. Unmitigated Drone Physics (_cp_*)
        if "mode_flip" in atk_tag or "mode_flip" in submode_tag:
            self._cp_mode = "LAND"
            self._cp_speed = max(0.0, self._cp_speed - 2.5 * dt)
            self._cp_alt = max(0.0, self._cp_alt - 3.0 * dt)
        elif "gcs_replay" in atk_tag or "gcs_replay" in submode_tag:
            self._cp_mode = "RTL"
            self._cp_speed = 11.0
            home_lat, home_lon = 19.1334, 72.9133
            dlat = home_lat - self._cp_lat
            dlon = home_lon - self._cp_lon
            brg = math.atan2(dlon, dlat)
            vn = 11.0 * math.cos(brg)
            ve = 11.0 * math.sin(brg)
            self._cp_lat, self._cp_lon = offset_latlon(self._cp_lat, self._cp_lon, vn * dt, ve * dt)
        elif "arm_disarm" in atk_tag or "arm_disarm" in submode_tag:
            self._cp_armed = False
            self._cp_speed = max(0.0, self._cp_speed - 5.0 * dt)
            self._cp_alt = max(0.0, self._cp_alt - 7.5 * dt)
        elif "rogue_command" in atk_tag or "rogue_command" in submode_tag:
            self._cp_mode = "GUIDED"
            self._cp_speed = 10.5
            vn = 10.5 * math.cos(math.radians(225.0))
            ve = 10.5 * math.sin(math.radians(225.0))
            self._cp_lat, self._cp_lon = offset_latlon(self._cp_lat, self._cp_lon, vn * dt, ve * dt)
        elif "replay_freeze" in atk_tag or "replay_freeze" in submode_tag:
            self._cp_speed = 0.0
            self._cp_lat = base_lat
            self._cp_lon = base_lon
        elif "rogue_sysid" in atk_tag or "rogue_sysid" in submode_tag:
            vn = 4.0
            ve = -4.0
            self._cp_lat, self._cp_lon = offset_latlon(self._cp_lat, self._cp_lon, vn * dt, ve * dt)
            self._cp_mode = base_mode
            self._cp_speed = base_speed
        else:
            self._cp_lat = base_lat
            self._cp_lon = base_lon
            self._cp_alt = base_alt
            self._cp_mode = base_mode
            self._cp_speed = base_speed

        # Determine if current attack alters GPS position
        is_gps = "gps" in atk_tag or "drift" in atk_tag or "offset" in atk_tag or (
            assessment is not None and assessment.attack_type == AttackType.GPS_SPOOFING
        )
        if is_gps and self.mitigation.golden.dr_lat is not None and self.mitigation.golden.dr_lon is not None:
            target_lat = self.mitigation.golden.dr_lat
            target_lon = self.mitigation.golden.dr_lon
        else:
            target_lat = base_lat
            target_lon = base_lon

        # Altitude handling:
        # If under altitude bias attack, maintain trusted barometric altitude;
        # otherwise follow the vehicle's nominal climb/cruise/descent profile (base_alt).
        is_alt_attack = "altitude" in atk_tag or "alt_bias" in atk_tag or (
            assessment is not None and getattr(assessment, "sub_mode", None) == "alt_bias"
        )
        if is_alt_attack:
            target_alt = self.mitigation.golden.trusted_rel_alt_m if self.mitigation.golden.trusted_rel_alt_m is not None else max(0.0, base_alt - 35.0)
        else:
            target_alt = base_alt

        # 2. Protected Drone Physics (_ips_*)
        if self.mitigation.mode == DefenseMode.ACTIVE_IPS:
            is_cmd = any(k in atk_tag or k in submode_tag for k in ("mode_flip", "gcs_replay", "arm_disarm", "rogue_command"))
            if is_cmd and self.topology == "a":
                # Topology A (Sidecar): FC obeys rogue command for ~0.4s before counter-command takes effect
                self._top_a_detour_t += dt
                if self._top_a_detour_t <= 0.4:
                    self._ips_lat = self._cp_lat
                    self._ips_lon = self._cp_lon
                    self._ips_alt = self._cp_alt
                    self._ips_speed = self._cp_speed
                    self._ips_mode = self._cp_mode
                else:
                    self._ips_mode = "AUTO"
                    self._ips_speed = 12.0
                    self._ips_alt = target_alt
                    self._ips_armed = True
                    dist_deg = math.hypot(target_lat - self._ips_lat, target_lon - self._ips_lon)
                    if dist_deg > 0.00002:
                        self._ips_lat += 0.35 * (target_lat - self._ips_lat)
                        self._ips_lon += 0.35 * (target_lon - self._ips_lon)
                    else:
                        self._ips_lat = target_lat
                        self._ips_lon = target_lon
            else:
                # Topology B (Inline): Dropped before FC, 0.0 m detour
                # Also handles GPS attacks under both topologies cleanly without oscillation
                self._top_a_detour_t = 0.0
                self._ips_mode = "AUTO"
                self._ips_speed = 12.0
                self._ips_alt = target_alt
                self._ips_armed = True
                dist_deg = math.hypot(target_lat - self._ips_lat, target_lon - self._ips_lon)
                if dist_deg > 0.0005:  # ~55m threshold: smooth return only if recovering from prior passive hijack
                    self._ips_lat += 0.35 * (target_lat - self._ips_lat)
                    self._ips_lon += 0.35 * (target_lon - self._ips_lon)
                else:
                    self._ips_lat = target_lat
                    self._ips_lon = target_lon
        else:
            # PASSIVE / ADVISORY: Drone follows unmitigated hijacked state
            self._ips_lat = self._cp_lat
            self._ips_lon = self._cp_lon
            self._ips_alt = self._cp_alt
            self._ips_mode = self._cp_mode
            self._ips_armed = self._cp_armed
            self._ips_speed = self._cp_speed
            self._top_a_detour_t = 0.0

    def _initial_mitigation_dict(self) -> dict:
        from ..mitigation.types import AttackParameters, AttackSubMode, MitigationAction

        summary = (
            "Autonomous IPS standby (passive)"
            if self.mitigation.mode == DefenseMode.PASSIVE
            else f"Autonomous IPS active ({self.mitigation.mode.value})"
        )
        return MitigationAction(
            t=round(self._sim_t, 3),
            mode=self.mitigation.mode,
            state=self.mitigation.state,
            sub_mode=AttackSubMode.NONE,
            params=AttackParameters(
                trusted_lat=self.mitigation.golden.trusted_lat,
                trusted_lon=self.mitigation.golden.trusted_lon,
                trusted_alt_m=self.mitigation.golden.trusted_alt_m,
                trusted_mode=self.mitigation.golden.trusted_mode,
            ),
            recovery_target_ticks=self.mitigation.recovery_clean_ticks,
            actions=list(self.mitigation.action_history),
            summary=summary,
        ).to_dict()

    def checks(self) -> dict | None:
        """Live-source integrity checks (mission path, cross-end, receiver); None for SIM."""
        if self.is_sim:
            return None
        f = self.pipeline.last_frame

        def g(name: str):
            return getattr(f, name, None) if f is not None else None

        def r(v, n):
            return None if v is None else round(float(v), n)

        ce = getattr(self.pipeline, "crossend", None)
        st = ce.stats() if ce is not None else None
        sat = g("gps_sat_jump")
        return {
            "mission": {"known": bool(g("mission_known")), "xtrack_m": r(g("mission_xtrack_m"), 2),
                        "wp_seq": g("mission_wp_seq")},
            "crossend": {"active": bool(st and st["summaries"] > 0), "matched": st["matched"] if st else 0,
                         "mismatches": st["mismatches"] if st else 0,
                         "last_summary_age_s": r(st["last_summary_age_s"], 2) if st else None},
            "receiver": {"ekf_vel_var": r(g("ekf_vel_var"), 4), "ekf_pos_var": r(g("ekf_pos_var"), 4),
                         "sat_jump": None if sat is None else int(sat), "snr_spread": r(g("gps_snr_spread_db"), 2)},
        }

    def _make_update(self, t: float, assessment) -> dict:
        source_desc = dict(self.spec.describe())
        source_desc["defense_mode"] = self.mitigation.mode.value
        raw_tele = self.pipeline._telemetry_dict()
        sanitized_tele = dict(raw_tele)

        if self.is_sim and self._cp_lat is not None:
            if self.mitigation.mode != DefenseMode.ACTIVE_IPS:
                raw_tele["lat"] = self._cp_lat
                raw_tele["lon"] = self._cp_lon
                raw_tele["rel_alt"] = self._cp_alt
                raw_tele["alt_msl"] = self._cp_alt
                raw_tele["flight_mode"] = self._cp_mode
                raw_tele["armed"] = self._cp_armed
                raw_tele["groundspeed"] = self._cp_speed
                sanitized_tele = dict(raw_tele)
            else:
                sanitized_tele["lat"] = round(self._ips_lat, 7) if self._ips_lat is not None else raw_tele.get("lat")
                sanitized_tele["lon"] = round(self._ips_lon, 7) if self._ips_lon is not None else raw_tele.get("lon")
                sanitized_tele["rel_alt"] = round(self._ips_alt, 2) if self._ips_alt is not None else raw_tele.get("rel_alt")
                sanitized_tele["alt_msl"] = round(self._ips_alt, 2) if self._ips_alt is not None else raw_tele.get("alt_msl")
                sanitized_tele["flight_mode"] = self._ips_mode or "AUTO"
                sanitized_tele["armed"] = self._ips_armed if self._ips_armed is not None else True
                sanitized_tele["groundspeed"] = round(self._ips_speed, 2) if self._ips_speed is not None else 12.0

        if self.is_sim and self._last_mitigation_action is not None and self.mitigation.mode == DefenseMode.ACTIVE_IPS:
            act = self._last_mitigation_action
            if act.sub_mode == AttackSubMode.TELEM_SPEED_MISMATCH:
                gs = math.hypot(self.mitigation.golden.vx_ms, self.mitigation.golden.vy_ms)
                sanitized_tele["groundspeed"] = round(gs, 2)
            if act.sub_mode == AttackSubMode.TELEM_BATTERY_JUMP and self.mitigation.golden.trusted_battery_v is not None:
                sanitized_tele["battery_voltage"] = round(self.mitigation.golden.trusted_battery_v, 2)

        msg = {
            "type": "update",
            "sim": self.is_sim,
            "environment": self.spec.environment,
            "source": source_desc,
            "defense_mode": self.mitigation.mode.value,
            "topology": self.topology,
            "topology_reasons": self.topology_reasons,
            "topology_info": self.topology_info(),
            "link": self.link_status(),
            "run_id": self._run_id,
            "t": round(t, 2),
            "telemetry": raw_tele,
            "sanitized_telemetry": sanitized_tele,
            "attack_active": self._active_attack_name,
            "distance_m": round(self._distance_m, 1),
            "checks": self.checks(),
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
        if self._last_mitigation_action is not None:
            msg["mitigation"] = self._last_mitigation_action.to_dict()
        else:
            msg["mitigation"] = self._initial_mitigation_dict()
        return msg

    # -- status snapshots --------------------------------------------------- #

    def status(self) -> dict:
        thr = self._last_threat
        source_desc = dict(self.spec.describe())
        source_desc["defense_mode"] = self.mitigation.mode.value
        return {
            "running": self.running,
            "sim": self.is_sim,
            "environment": self.spec.environment,
            "source": source_desc,
            "defense_mode": self.mitigation.mode.value,
            "topology": self.topology,
            "topology_reasons": self.topology_reasons,
            "topology_info": self.topology_info(),
            "mitigation": self._last_mitigation_action.to_dict() if self._last_mitigation_action else self._initial_mitigation_dict(),
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
            "checks": self.checks(),
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

    def forensic_bundle(self, limit: int = 200) -> dict:
        """Build a tamper-evident forensic audit bundle for the current run."""
        cs = self.store.verify_chain(self._run_id)
        rows = self.recent_alerts(limit=limit)
        head_hash = rows[0].get("hash") if rows else ("0" * 64)
        return {
            "run_id": self._run_id,
            "environment": self.spec.environment,
            "defense_mode": self.mitigation.mode.value,
            "chain_verification": {
                "ok": cs.ok,
                "length": cs.length,
                "broken_at": cs.broken_at,
                "detail": cs.detail,
                "genesis_hash": "0" * 64,
                "head_hash": head_hash,
            },
            "mitigation_actions": list(self.mitigation.action_history),
            "events": rows,
        }
