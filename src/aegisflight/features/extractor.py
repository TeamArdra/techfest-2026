"""Online feature extraction.

Consumes decoded :class:`MessageEnvelope` objects, reconstructs the observed
:class:`TelemetrySnapshot`, and — at each decision tick — emits a
:class:`FeatureFrame` of network, navigation, sensor-consistency and command
features. The extractor is **policy-free**: it computes physical quantities and
raw aggregates; the detectors apply thresholds and the "expected source" policy.

The signature cyber-physical feature is ``pos_residual_m``: a leaky-integrated
divergence between the reported position track and the track implied by the
reported velocity. Under GPS spoofing the two disagree and the residual grows;
under benign flight it stays near the GPS noise floor.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field

from ..core.geo import EARTH_RADIUS_M, wrap_deg_180
from ..core.types import MessageEnvelope, TelemetrySnapshot
from ..mavlink.codec import MODE_NAMES

# Position-residual sliding window (in position fixes; GPS ≈ 5 Hz => ~3 s).
# A bounded window (rather than an infinite leaky integrator) accumulates the
# sub-GPS-noise gradual-drift signal past the 12 m threshold while keeping the
# benign residual at a few metres (see the sim reference in
# artifacts/external/*/summary.md) AND recovering within the window length once an
# attack stops (no long post-attack detector tail). Per-fix increments are
# magnitude-clamped so a single position snap-back can't dominate the window.
_RESID_WINDOW = 15
_RESID_CLAMP_M = 30.0
# Link-gap guard. Both position-vs-velocity checks assume a short, continuous fix interval
# (constant velocity over dt) and a fresh velocity. After a transport outage longer than this
# (matches the 2 s GPS-dropout rule, which reports the outage itself) the first fix would be
# compared against 8+ s of manoeuvre, and a fresh ATTITUDE against a stale GPS velocity, so both
# are skipped until GPS is fresh again. Gap-free streams are unaffected (benchmark-identical).
_LINK_GAP_S = 2.0
# ML feature vector order (policy-free continuous signals, benign-stable).
# NB: battery_v_rate is deliberately excluded — it is ~0 in steady flight
# (tiny variance), so throttle transitions read as extreme outliers and cause
# benign false positives. Battery attacks are covered by the physics detector's
# transition-robust 0.4 V rise threshold instead.
ML_FEATURES = (
    "msg_rate_hz",
    "interarrival_jitter_ms",
    "max_seq_gap",
    "pos_residual_m",
    "gps_vfr_speed_diff_ms",
    "gps_baro_alt_diff_m",
    "alt_rate_ms",
    "accel_ms2",
    "yaw_course_diff_deg",
    "cmd_rate_hz",
    "loss_ratio",
)


@dataclass
class CommandEvent:
    recv_time: float
    sysid: int
    compid: int
    command: int
    params: tuple[float, ...] = ()


@dataclass
class FeatureFrame:
    t: float
    snapshot: TelemetrySnapshot
    # --- network ---
    msg_rate_hz: float = 0.0
    interarrival_mean_ms: float = 0.0
    interarrival_jitter_ms: float = 0.0
    max_seq_gap: int = 0
    n_sources: int = 0
    heartbeat_age_s: float = 0.0
    gps_age_s: float = 0.0
    loss_ratio: float = 0.0
    signed_ratio: float = 0.0
    # ADDITIVE (P4): signing-policy violations (bad/missing MAVLink-2 signature) accumulated
    # since the last decision window, from the live source's ``TelemetryTick.sig_invalid``
    # (see ``sources.mavlink_live``). Always 0 for the simulated source / any source without
    # a signing key configured. NOT in ML_FEATURES -- rule-only, read by ProtocolDetector.
    sig_invalid_count: int = 0
    sources: dict[tuple[int, int], int] = field(default_factory=dict)
    # --- navigation / cyber-physical ---
    pos_residual_m: float = 0.0
    gps_vfr_speed_diff_ms: float = 0.0
    gps_baro_alt_diff_m: float = 0.0
    alt_rate_ms: float = 0.0
    accel_ms2: float = 0.0
    jerk_ms3: float = 0.0
    battery_v_rate: float = 0.0
    battery_v_rise: float = 0.0
    yaw_course_diff_deg: float = 0.0
    # --- command ---
    cmd_rate_hz: float = 0.0
    commands_recent: list[CommandEvent] = field(default_factory=list)

    @property
    def battery_v_rate_abs(self) -> float:
        return abs(self.battery_v_rate)

    def to_vector(self) -> list[float]:
        return [float(getattr(self, name)) for name in ML_FEATURES]

    def signals(self) -> dict[str, float]:
        return {name: float(getattr(self, name)) for name in ML_FEATURES}


class FeatureExtractor:
    """Stateful, online telemetry reconstruction + feature computation."""

    def __init__(self, rate_window_s: float = 1.0, cmd_window_s: float = 2.0) -> None:
        self.rate_window_s = rate_window_s
        self.cmd_window_s = cmd_window_s
        self.reset()

    def reset(self) -> None:
        """Clear all online state so the extractor behaves like a fresh instance.

        Called by :meth:`IDSPipeline.reset`; without this, a live reset leaves
        stale receive-time / navigation / battery windows behind, which — once
        the sim clock restarts near t=0 — read as a message flood and phantom
        anomalies (false positives on a benign source).
        """
        self.snapshot = TelemetrySnapshot(t=0.0)

        # network bookkeeping
        self._recv_times: deque[float] = deque(maxlen=2000)
        self._seq_state: dict[tuple[int, int], int] = {}
        self._seq_gap: dict[tuple[int, int], int] = {}
        self._sources: dict[tuple[int, int], int] = {}
        self._signed = 0
        self._unsigned = 0
        self._last_heartbeat_t = -1e9
        self._last_gps_t = -1e9
        self._expected_msgs = 0.0  # for loss estimate

        # navigation bookkeeping
        self._resid_incs: deque[tuple[float, float]] = deque(maxlen=_RESID_WINDOW)
        self._last_fix: tuple[float, float, float] | None = None  # (t, lat, lon)
        self._vel_hist: deque[tuple[float, float, float]] = deque(maxlen=6)  # (t, vx, vy)
        self._accel_prev: tuple[float, float] | None = None  # (t, accel)
        self._batt_hist: deque[tuple[float, float]] = deque(maxlen=4)  # (t, voltage)
        self._alt_hist: deque[tuple[float, float]] = deque(maxlen=4)  # (t, baro_alt)

        # command log
        self._commands: deque[CommandEvent] = deque(maxlen=200)
        self._sig_invalid_window = 0  # P4: reset each decision, see note_sig_invalid()

    # -- ingestion ---------------------------------------------------------- #

    def note_sig_invalid(self, n: int) -> None:
        """Accumulate ``n`` signing-policy violations (see ``TelemetryTick.sig_invalid``)
        into the current decision window; always called with 0 by a caller that never
        configures a signing key, so this is a strict no-op for Stage-1 / any unsigned
        live source."""
        self._sig_invalid_window += n

    def update(self, msg: MessageEnvelope) -> None:
        t = msg.recv_time
        src = (msg.sysid, msg.compid)
        self._recv_times.append(t)
        self._sources[src] = self._sources.get(src, 0) + 1
        if msg.signed:
            self._signed += 1
        else:
            self._unsigned += 1

        # per-source sequence gap tracking (single link => +1 expected)
        prev = self._seq_state.get(src)
        if prev is not None:
            gap = (msg.seq - prev) % 256
            # gap of 1 is normal; larger => loss/scramble; 0 => duplicate
            if gap > 1:
                self._seq_gap[src] = max(self._seq_gap.get(src, 0), gap - 1)
        self._seq_state[src] = msg.seq

        name = msg.msgname
        f = msg.fields
        if name == "HEARTBEAT":
            self._last_heartbeat_t = t
            self.snapshot.armed = bool(f.get("base_mode", 0) & 128)
            self.snapshot.flight_mode = MODE_NAMES.get(int(f.get("custom_mode", 0)), "UNKNOWN")
        elif name == "GLOBAL_POSITION_INT":
            self._last_gps_t = t
            lat = f["lat"] / 1e7
            lon = f["lon"] / 1e7
            self.snapshot.lat = lat
            self.snapshot.lon = lon
            self.snapshot.alt_msl = f["alt"] / 1000.0
            self.snapshot.rel_alt = f["relative_alt"] / 1000.0
            self.snapshot.vx = f["vx"] / 100.0
            self.snapshot.vy = f["vy"] / 100.0
            self.snapshot.vz = f["vz"] / 100.0
            self._update_position_residual(t, lat, lon, self.snapshot.vx, self.snapshot.vy)
        elif name == "ATTITUDE":
            self.snapshot.roll = f["roll"]
            self.snapshot.pitch = f["pitch"]
            self.snapshot.yaw = f["yaw"]
            self.snapshot.rollspeed = f["rollspeed"]
            self.snapshot.pitchspeed = f["pitchspeed"]
            self.snapshot.yawspeed = f["yawspeed"]
        elif name == "VFR_HUD":
            self.snapshot.groundspeed = f["groundspeed"]
            self.snapshot.heading = float(f["heading"])
            self.snapshot.throttle = float(f["throttle"])
            self.snapshot.baro_alt = f["alt"]
            self.snapshot.vertical_speed = f["climb"]
        elif name == "SYS_STATUS":
            self.snapshot.battery_voltage = f["voltage_battery"] / 1000.0
            self.snapshot.battery_remaining = float(f["battery_remaining"])
            self._batt_hist.append((t, self.snapshot.battery_voltage))
        elif name == "GPS_RAW_INT":
            self.snapshot.satellites = int(f.get("satellites_visible", 0))
            self.snapshot.gps_fix_type = int(f.get("fix_type", 0))
            self.snapshot.hdop = f.get("eph", 0) / 100.0
        elif name == "COMMAND_LONG":
            params = tuple(f.get(f"param{i}", 0.0) for i in range(1, 8))
            self._commands.append(
                CommandEvent(t, msg.sysid, msg.compid, int(f.get("command", 0)), params)
            )

    # -- navigation helpers ------------------------------------------------- #

    def _update_position_residual(self, t: float, lat: float, lon: float, vx: float, vy: float) -> None:
        if self._last_fix is not None:
            t0, lat0, lon0 = self._last_fix
            dt = t - t0
            if dt > _LINK_GAP_S:
                pass  # outage: constant-velocity assumption invalid; re-anchor on this fix
            elif dt > 1e-6:
                # measured displacement (local NE metres)
                dn = math.radians(lat - lat0) * EARTH_RADIUS_M
                de = math.radians(lon - lon0) * EARTH_RADIUS_M * math.cos(math.radians(lat))
                # velocity-implied displacement; residual increment is the gap
                inc_n = dn - vx * dt
                inc_e = de - vy * dt
                mag = math.hypot(inc_n, inc_e)
                if mag > _RESID_CLAMP_M:  # clamp so a snap-back can't dominate
                    scale = _RESID_CLAMP_M / mag
                    inc_n *= scale
                    inc_e *= scale
                self._resid_incs.append((inc_n, inc_e))
        self._last_fix = (t, lat, lon)
        self._vel_hist.append((t, vx, vy))

    def _position_residual(self) -> float:
        rn = sum(i[0] for i in self._resid_incs)
        re = sum(i[1] for i in self._resid_incs)
        return math.hypot(rn, re)

    # -- feature emission --------------------------------------------------- #

    def extract(self, t: float) -> FeatureFrame:
        snap = self.snapshot
        snap.t = t

        # ---- network ----
        window = [rt for rt in self._recv_times if rt >= t - self.rate_window_s]
        msg_rate = len(window) / self.rate_window_s if self.rate_window_s > 0 else 0.0
        deltas = [
            (b - a) * 1000.0
            for a, b in zip(sorted(window), sorted(window)[1:], strict=False)
            if b - a >= 0
        ]
        ia_mean = sum(deltas) / len(deltas) if deltas else 0.0
        ia_jit = (
            (sum((d - ia_mean) ** 2 for d in deltas) / len(deltas)) ** 0.5 if deltas else 0.0
        )
        max_gap = max(self._seq_gap.values(), default=0)
        total = self._signed + self._unsigned
        signed_ratio = self._signed / total if total else 0.0
        # loss estimate: fraction of expected +1 steps that were gaps
        loss_ratio = min(1.0, max_gap / 50.0)

        snap.gps_age = max(0.0, t - self._last_gps_t) if self._last_gps_t > -1e8 else 999.0
        hb_age = max(0.0, t - self._last_heartbeat_t) if self._last_heartbeat_t > -1e8 else 999.0

        # ---- navigation / physics ----
        pos_residual = self._position_residual()
        gps_speed = math.hypot(snap.vx or 0.0, snap.vy or 0.0)
        vfr_speed = snap.groundspeed or 0.0
        speed_diff = abs(gps_speed - vfr_speed)
        alt_diff = (
            abs((snap.alt_msl or 0.0) - (snap.baro_alt or 0.0))
            if snap.alt_msl is not None and snap.baro_alt is not None
            else 0.0
        )
        # altitude rate from baro history (sampled at decision cadence)
        if snap.baro_alt is not None:
            self._alt_hist.append((t, snap.baro_alt))
        alt_rate = self._rate(self._alt_hist)
        # horizontal acceleration & jerk from velocity history
        accel, jerk = self._accel_jerk(t)
        # battery rate / rise
        batt_rate = self._rate(self._batt_hist)
        batt_rise = max(0.0, batt_rate)  # V/s upward (implausible if large)
        # yaw vs course
        yaw_course = 0.0
        if gps_speed > 2.0 and snap.yaw is not None and snap.gps_age <= _LINK_GAP_S:
            course = math.degrees(math.atan2(snap.vy or 0.0, snap.vx or 0.0)) % 360.0
            yaw_deg = math.degrees(snap.yaw) % 360.0
            yaw_course = abs(wrap_deg_180(yaw_deg - course))

        # ---- command ----
        recent = [c for c in self._commands if c.recv_time >= t - self.cmd_window_s]
        cmd_rate = len(recent) / self.cmd_window_s if self.cmd_window_s > 0 else 0.0

        return FeatureFrame(
            t=t,
            snapshot=snap,
            msg_rate_hz=msg_rate,
            interarrival_mean_ms=ia_mean,
            interarrival_jitter_ms=ia_jit,
            max_seq_gap=max_gap,
            n_sources=len(self._sources),
            heartbeat_age_s=hb_age,
            gps_age_s=snap.gps_age,
            loss_ratio=loss_ratio,
            signed_ratio=signed_ratio,
            sig_invalid_count=self._sig_invalid_window,
            sources=dict(self._sources),
            pos_residual_m=pos_residual,
            gps_vfr_speed_diff_ms=speed_diff,
            gps_baro_alt_diff_m=alt_diff,
            alt_rate_ms=alt_rate,
            accel_ms2=accel,
            jerk_ms3=jerk,
            battery_v_rate=batt_rate,
            battery_v_rise=batt_rise,
            yaw_course_diff_deg=yaw_course,
            cmd_rate_hz=cmd_rate,
            commands_recent=recent,
        )

    # -- small numeric helpers --------------------------------------------- #

    @staticmethod
    def _rate(hist: deque[tuple[float, float]]) -> float:
        if len(hist) < 2:
            return 0.0
        (t0, v0), (t1, v1) = hist[-2], hist[-1]
        dt = t1 - t0
        return (v1 - v0) / dt if dt > 1e-6 else 0.0

    def _accel_jerk(self, t: float) -> tuple[float, float]:
        if len(self._vel_hist) < 2:
            return 0.0, 0.0
        (t0, vx0, vy0), (t1, vx1, vy1) = self._vel_hist[-2], self._vel_hist[-1]
        dt = t1 - t0
        if dt <= 1e-6:
            return 0.0, 0.0
        accel = math.hypot(vx1 - vx0, vy1 - vy0) / dt
        jerk = 0.0
        if self._accel_prev is not None:
            pt, pa = self._accel_prev
            if t1 - pt > 1e-6:
                jerk = abs(accel - pa) / (t1 - pt)
        self._accel_prev = (t1, accel)
        return accel, jerk

    # window reset between the rate window drops handled by deque + filtering
    def clear_window_counts(self) -> None:
        """Reset per-window source counts (called by the pipeline each decision)."""
        self._sources = {}
        self._seq_gap = {}
        self._sig_invalid_window = 0
