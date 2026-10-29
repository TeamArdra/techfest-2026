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

# The ardupilotmega dialect is imported only for its EKF_STATUS_FLAGS constants (EKF_POS_HORIZ_ABS,
# EKF_POS_HORIZ_REL, EKF_CONST_POS_MODE): the common dialect does not define them, and taking them
# from the installed dialect avoids hand-typed bit values.
from pymavlink.dialects.v20 import ardupilotmega as _apm

from ..core.geo import EARTH_RADIUS_M, wrap_deg_180
from ..core.types import MessageEnvelope, TelemetrySnapshot
from ..mavlink.codec import MODE_NAMES
from .mission import MissionTracker

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
# Estimator state (ADDITIVE, 2026-10-25; v2 2026-10-26). EKF_STATUS_REPORT (ardupilotmega id 193)
# says whether the autopilot's estimator has a horizontal position solution. In CONST_POS_MODE, or
# with neither the absolute nor the relative horizontal-position bit, its velocity output is not a
# measurement (it is pinned at ~0) while GLOBAL_POSITION_INT may carry the receiver's position, so
# position and velocity are not one navigation solution. Bits come from the installed dialect.
# A position fix is GATED only when (all three):
#   * the latest report is fresh (<= _LINK_GAP_S old at the fix) and says no horizontal solution;
#   * the reports have said no solution continuously for >= _LINK_GAP_S (first to latest report of
#     the run), so one forged report, flag flipping, or a stale / missing status never gates;
#   * the run restarts on any solution report and on any gap > _LINK_GAP_S between two reports.
# The first ungated fix after a gated one is the TRANSITION fix. Both tags are per increment in the
# existing _RESID_WINDOW; nothing restarts the window.
_EKF_HORIZ_POS_BITS = _apm.EKF_POS_HORIZ_ABS | _apm.EKF_POS_HORIZ_REL
_EKF_CONST_POS_MODE = _apm.EKF_CONST_POS_MODE
_INC_NORMAL, _INC_GATED, _INC_TRANSITION = 0, 1, 2


def ekf_has_horizontal_solution(flags: int) -> bool:
    """True when EKF_STATUS_REPORT ``flags`` report a usable horizontal position solution."""
    return bool(flags & _EKF_HORIZ_POS_BITS) and not flags & _EKF_CONST_POS_MODE


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
    # ADDITIVE: whether a HEARTBEAT / GLOBAL_POSITION_INT has EVER been received since the last
    # reset. ``heartbeat_age_s`` / ``gps_age_s`` report the 999 s sentinel for "never seen", which a
    # real outage longer than 999 s would also exceed; these flags remove that ambiguity. ``None``
    # (hand-built frames) means unknown: readers fall back to the sentinel. NOT in ML_FEATURES.
    # ``gps_seen`` is POSITION presence (GLOBAL_POSITION_INT); ``gps_raw_seen`` says whether any
    # GPS_RAW_INT (raw receiver fix report) has been received -- reported, not position presence.
    heartbeat_seen: bool | None = None
    gps_seen: bool | None = None
    gps_raw_seen: bool | None = None
    # ADDITIVE: 2D Page-Hinkley / CUSUM micro-drift residual magnitude (m) for catching
    # sub-noise-floor gradual GPS drift (< 0.3 m/s). NOT in ML_FEATURES.
    cusum_drift_m: float = 0.0
    # ADDITIVE (2026-10-25; v2 2026-10-26): estimator state from EKF_STATUS_REPORT. NOT in
    # ML_FEATURES. Gated / transition fixes: see the _EKF_* comment at the top of this module.
    # ``ekf_flags`` / ``ekf_age_s``: the last report and its age at ``t``; None = never received.
    # ``nav_solution``: the estimator state at the LATEST POSITION FIX (not at ``t``; before the
    # first fix, at ``t``): True = horizontal solution, False = none (CONST_POS_MODE or no
    # horizontal-position bit), None = unknown (no report, or older than _LINK_GAP_S at that fix).
    # ``nav_gated``: the latest fix was gated (debounced no-solution state).
    # ``pos_residual_nav_m``: ``pos_residual_m`` over the same window without the increments of
    # gated fixes and of the transition fix; EXACTLY ``pos_residual_m`` when the window holds
    # neither. None when no EKF_STATUS_REPORT was ever received (readers use ``pos_residual_m``).
    # ``pos_step_max_m``: the largest unclamped residual increment |dp - v*dt| of a gated or
    # transition fix in the window (not the raw displacement); 0.0 when there is none.
    # ``pos_vel_shortfall_gated_m``: over the gated fixes in the window, the velocity-implied
    # movement the position does NOT show. V = sum of v*dt, P = sum of the raw measured
    # displacements of the same fixes; shortfall = |V| - (P projected on V, clamped to [0, |V|]),
    # so 0 <= shortfall <= |V| (0 when |V| = 0, when P follows V, or when P overshoots along V).
    # Displacement perpendicular to V is not measured. 0.0 when no gated fix is in the window.
    ekf_flags: int | None = None
    ekf_age_s: float | None = None
    nav_solution: bool | None = None
    nav_gated: bool = False
    pos_residual_nav_m: float | None = None
    pos_step_max_m: float = 0.0
    pos_vel_shortfall_gated_m: float = 0.0
    # ADDITIVE (2026-10-28): EKF health and GPS receiver signature. NOT in ML_FEATURES. All are
    # None (``gps_sat_jump``: 0) unless the extended MAVLink messages are present, so the SIM stream
    # and any link without them is unchanged.
    # ``ekf_vel_var`` / ``ekf_pos_var`` / ``ekf_compass_var``: EKF_STATUS_REPORT velocity_variance,
    # pos_horiz_variance, compass_variance (ArduPilot normalised innovation ratios; >= 1.0 = the EKF
    # rejects its inputs, >= 0.5 warning); None if never received or older than 2 s.
    # ``gps_sat_jump``: |change| of GPS_RAW_INT.satellites_visible between consecutive reports, held
    # for 1 s after it happens. ``gps_snr_spread_db``: std of the non-zero GPS_STATUS satellite_snr
    # values (None without GPS_STATUS, older than 2 s, or fewer than 8 satellites);
    # ``gps_snr_sats``: how many were non-zero. ``gps_vel_disagree_ms``: |GPS_RAW_INT.vel -
    # hypot(GLOBAL_POSITION_INT vx, vy)|. The two receiver-signature fields that SIM also carries
    # (sat jump, vel disagreement) are reported only once EKF_STATUS_REPORT or GPS_STATUS has been
    # received, which keeps the SIM stream and the Stage-1 benchmark untouched.
    ekf_vel_var: float | None = None
    ekf_pos_var: float | None = None
    ekf_compass_var: float | None = None
    gps_sat_jump: int = 0
    gps_snr_spread_db: float | None = None
    gps_snr_sats: int = 0
    gps_vel_disagree_ms: float | None = None
    # ADDITIVE (2026-10-28): mission-path check. NOT in ML_FEATURES. ``mission_known``: a COMPLETE
    # mission was observed AND the check is active (MISSION_CURRENT seen <= 3 s ago, flight_mode
    # AUTO, armed, fresh position). ``mission_xtrack_m``: horizontal distance to the current mission
    # leg SEGMENT; ``mission_wp_dist_m``: distance to its target waypoint; ``mission_wp_seq``: that
    # waypoint's seq. All None / False when inactive (always so on the SIM stream).
    mission_known: bool = False
    mission_xtrack_m: float | None = None
    mission_wp_dist_m: float | None = None
    mission_wp_seq: int | None = None

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
        self._gps_raw_seen = False
        self._expected_msgs = 0.0  # for loss estimate
        self._last_ekf_t = -1e9
        self._ekf_flags: int | None = None
        self._nosol_since: float | None = None  # first report of the current no-solution run
        self._ekf_vars: tuple[float, float, float] | None = None  # (vel, pos_horiz, compass)
        self._ext_seen = False  # EKF_STATUS_REPORT or GPS_STATUS ever received
        self._prev_sats: int | None = None
        self._prev_valid = False
        self._sat_jump = 0
        self._sat_jump_t = -1e9
        self._raw_vel_ms: float | None = None
        self._raw_vel_t = -1e9
        self._snr: tuple[float, int] | None = None  # (spread dB, n satellites) or None
        self._snr_t = -1e9

        # navigation bookkeeping
        self._resid_incs: deque[tuple[float, float]] = deque(maxlen=_RESID_WINDOW)
        self._cusum_incs: deque[tuple[float, float, float]] = deque(maxlen=60)  # (inc_n, inc_e, dt)
        # per-increment estimator tags, aligned 1:1 with _resid_incs (appended together):
        # (tag, raw unclamped residual magnitude, v_n*dt, v_e*dt, measured d_n, measured d_e);
        # the last four are kept for gated increments only (0.0 otherwise)
        self._resid_tags: deque[tuple[int, float, float, float, float, float]] = deque(maxlen=_RESID_WINDOW)
        self._last_fix_gated = False
        self._last_fix_nav: bool | None = None
        self._last_fix: tuple[float, float, float] | None = None  # (t, lat, lon)
        self._vel_hist: deque[tuple[float, float, float]] = deque(maxlen=6)  # (t, vx, vy)
        self._accel_prev: tuple[float, float] | None = None  # (t, accel)
        self._batt_hist: deque[tuple[float, float]] = deque(maxlen=4)  # (t, voltage)
        self._alt_hist: deque[tuple[float, float]] = deque(maxlen=4)  # (t, baro_alt)

        self._mission = MissionTracker()

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
        if name.startswith("MISSION_"):
            self._mission.update(msg)
            return
        if name == "HEARTBEAT":
            m_type = f.get("type", 0)
            if m_type != 6:  # Ignore GCS heartbeats for vehicle state
                self._last_heartbeat_t = t
                self.snapshot.armed = bool(f.get("base_mode", 0) & 128)
                cm = int(f.get("custom_mode", 0))
                autopilot = f.get("autopilot", 0)
                if autopilot == 12 or cm >= 65536:
                    from ..sources.mavlink_live import decode_px4_mode
                    self.snapshot.flight_mode = decode_px4_mode(cm)
                else:
                    self.snapshot.flight_mode = MODE_NAMES.get(cm, "UNKNOWN")
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
            self._gps_raw_seen = True
            self.snapshot.satellites = int(f.get("satellites_visible", 0))
            self.snapshot.gps_fix_type = int(f.get("fix_type", 0))
            self.snapshot.hdop = f.get("eph", 0) / 100.0
            sats = self.snapshot.satellites
            # a jump counts only with a 3D fix on BOTH reports: satellites returning after a fix
            # loss (or leaving with it) is receiver recovery / jamming, handled by other rules
            valid = self.snapshot.gps_fix_type >= 3
            if self._prev_sats is not None and valid and self._prev_valid and sats != self._prev_sats:
                self._sat_jump = abs(sats - self._prev_sats)
                self._sat_jump_t = t
            self._prev_sats = sats
            self._prev_valid = valid
            vel = f.get("vel")
            if vel is not None and int(vel) != 65535:  # 65535 = unknown
                self._raw_vel_ms = int(vel) / 100.0
                self._raw_vel_t = t
        elif name == "GPS_STATUS" and "satellite_snr" in f:
            self._ext_seen = True
            vals = [float(x) for x in f["satellite_snr"] if x]
            self._snr_t = t
            if len(vals) >= 8:
                mean = sum(vals) / len(vals)
                self._snr = ((sum((x - mean) ** 2 for x in vals) / len(vals)) ** 0.5, len(vals))
            else:
                self._snr = None
        elif name == "EKF_STATUS_REPORT" and "flags" in f:
            flags = int(f["flags"])
            if ekf_has_horizontal_solution(flags):
                self._nosol_since = None
            elif self._nosol_since is None or t - self._last_ekf_t > _LINK_GAP_S:
                self._nosol_since = t  # a new no-solution run (first one, or after a report gap)
            self._last_ekf_t = t
            self._ekf_flags = flags
            self._ext_seen = True
            if all(k in f for k in ("velocity_variance", "pos_horiz_variance", "compass_variance")):
                self._ekf_vars = (
                    float(f["velocity_variance"]),
                    float(f["pos_horiz_variance"]),
                    float(f["compass_variance"]),
                )
        elif name == "COMMAND_LONG":
            params = tuple(f.get(f"param{i}", 0.0) for i in range(1, 8))
            self._commands.append(
                CommandEvent(t, msg.sysid, msg.compid, int(f.get("command", 0)), params)
            )
        elif name == "SET_MODE":
            # the older plain SET_MODE message (some ground stations still use it) is the same intent as
            # MAV_CMD_DO_SET_MODE (176): record it as that command so provenance and pilot-override logic see it
            self._commands.append(
                CommandEvent(t, msg.sysid, msg.compid, 176,
                             (float(f.get("base_mode", 0)), float(f.get("custom_mode", 0)), 0.0, 0.0, 0.0, 0.0, 0.0))
            )

    # -- navigation helpers ------------------------------------------------- #

    def _nav_state(self, t: float) -> bool | None:
        """Estimator horizontal-solution state at ``t`` (None = no report, or older than _LINK_GAP_S)."""
        if self._ekf_flags is None or t - self._last_ekf_t > _LINK_GAP_S:
            return None
        return ekf_has_horizontal_solution(self._ekf_flags)

    def _gated(self, t: float) -> bool:
        """Debounced no-solution state at ``t`` (see the _EKF_* comment at the top of this module).
        ``_nosol_since`` is set only while the latest report says no solution."""
        return (
            self._nosol_since is not None
            and t - self._last_ekf_t <= _LINK_GAP_S
            # 1e-9 s tolerance: reports meant to be exactly _LINK_GAP_S apart must not miss on float error
            and self._last_ekf_t - self._nosol_since >= _LINK_GAP_S - 1e-9
        )

    def _update_position_residual(self, t: float, lat: float, lon: float, vx: float, vy: float) -> None:
        gated = self._gated(t)
        # the first ungated fix after a gated one: its increment straddles the state change (an
        # estimator reset as the solution returns), so it is tagged rather than read as drift
        transition = self._last_fix_gated and not gated
        if self._last_fix is not None:
            t0, lat0, lon0 = self._last_fix
            dt = t - t0
            if dt > _LINK_GAP_S:
                self._cusum_incs.clear()  # outage: re-anchor long-horizon CUSUM buffer
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
                self._cusum_incs.append((inc_n, inc_e, dt))
                if gated:
                    self._resid_tags.append((_INC_GATED, mag, vx * dt, vy * dt, dn, de))
                else:
                    tag = _INC_TRANSITION if transition else _INC_NORMAL
                    self._resid_tags.append((tag, mag, 0.0, 0.0, 0.0, 0.0))
        self._last_fix = (t, lat, lon)
        self._last_fix_gated = gated
        self._last_fix_nav = self._nav_state(t)
        self._vel_hist.append((t, vx, vy))

    def _position_residual(self) -> float:
        rn = sum(i[0] for i in self._resid_incs)
        re = sum(i[1] for i in self._resid_incs)
        return math.hypot(rn, re)

    def _cusum_residual(self) -> float:
        """2D telescoping Page-Hinkley / CUSUM residual over the extended horizon."""
        if not self._cusum_incs:
            return 0.0
        rn = sum(i[0] for i in self._cusum_incs)
        re = sum(i[1] for i in self._cusum_incs)
        total_dt = sum(i[2] for i in self._cusum_incs)
        mag = math.hypot(rn, re)
        # Subtract telescoping GPS position endpoint jitter (~1.6m) + velocity slack (0.04 m/s)
        slack = 1.6 + 0.04 * total_dt
        return max(0.0, mag - slack)
    def _estimator_aware_residual(self, pos_residual: float) -> tuple[float, float, float]:
        """(pos_residual_nav_m, pos_step_max_m, pos_vel_shortfall_gated_m) over the current window."""
        if self._ekf_flags is None:
            return pos_residual, 0.0, 0.0  # no EKF_STATUS_REPORT ever: nothing below runs
        if not any(g[0] != _INC_NORMAL for g in self._resid_tags):
            return pos_residual, 0.0, 0.0  # nothing gated or transitional: exactly pos_residual_m
        keep = [inc for inc, g in zip(self._resid_incs, self._resid_tags, strict=True) if g[0] == _INC_NORMAL]
        nav = math.hypot(sum(i[0] for i in keep), sum(i[1] for i in keep))
        step = max((g[1] for g in self._resid_tags if g[0] != _INC_NORMAL), default=0.0)
        gated = [g[2:] for g in self._resid_tags if g[0] == _INC_GATED]
        v_n, v_e = sum(g[0] for g in gated), sum(g[1] for g in gated)
        p_n, p_e = sum(g[2] for g in gated), sum(g[3] for g in gated)
        v_mag = math.hypot(v_n, v_e)
        shortfall = 0.0
        if v_mag > 0.0:
            along = (p_n * v_n + p_e * v_e) / v_mag  # measured displacement along the velocity
            shortfall = v_mag - min(v_mag, max(0.0, along))
        return nav, step, shortfall

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
        ekf_seen = self._ekf_flags is not None
        pos_residual_nav, pos_step_max, pos_vel_shortfall_gated = self._estimator_aware_residual(pos_residual)
        # the state at the latest fix; before the first fix, the state at t
        nav_solution = self._last_fix_nav if self._last_fix is not None else self._nav_state(t)
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

        # ---- EKF health / GPS receiver signature (ADDITIVE 2026-10-28) ----
        ekf_vars = self._ekf_vars if ekf_seen and t - self._last_ekf_t <= _LINK_GAP_S else None
        sat_jump = 0
        vel_disagree: float | None = None
        if self._ext_seen:
            if t - self._sat_jump_t <= 1.0:
                sat_jump = self._sat_jump
            if (
                self._raw_vel_ms is not None
                and t - self._raw_vel_t <= _LINK_GAP_S
                and snap.gps_age <= _LINK_GAP_S
            ):
                vel_disagree = abs(self._raw_vel_ms - gps_speed)
        snr = self._snr if t - self._snr_t <= _LINK_GAP_S else None

        # ---- mission path (ADDITIVE 2026-10-28) ----
        m_known, m_xt, m_wd, m_seq = False, None, None, None
        mt = self._mission
        if (
            mt.complete
            and 0.0 <= t - mt.current_t <= 3.0
            and snap.flight_mode == "AUTO"
            and snap.armed is True
            and snap.lat is not None
            and snap.lon is not None
            and snap.gps_age <= _LINK_GAP_S
        ):
            mev = mt.evaluate(snap.lat, snap.lon)
            if mev is not None:
                m_known, m_xt, m_wd, m_seq = True, mev[0], mev[1], mev[2]

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
            heartbeat_seen=self._last_heartbeat_t > -1e8,
            gps_seen=self._last_gps_t > -1e8,
            gps_raw_seen=self._gps_raw_seen,
            cusum_drift_m=self._cusum_residual(),
            ekf_flags=self._ekf_flags,
            ekf_age_s=max(0.0, t - self._last_ekf_t) if ekf_seen else None,
            nav_solution=nav_solution,
            nav_gated=self._last_fix_gated,
            pos_residual_nav_m=pos_residual_nav if ekf_seen else None,
            pos_step_max_m=pos_step_max,
            pos_vel_shortfall_gated_m=pos_vel_shortfall_gated,
            ekf_vel_var=ekf_vars[0] if ekf_vars else None,
            ekf_pos_var=ekf_vars[1] if ekf_vars else None,
            ekf_compass_var=ekf_vars[2] if ekf_vars else None,
            gps_sat_jump=sat_jump,
            gps_snr_spread_db=snr[0] if snr else None,
            gps_snr_sats=snr[1] if snr else 0,
            gps_vel_disagree_ms=vel_disagree,
            mission_known=m_known,
            mission_xtrack_m=m_xt,
            mission_wp_dist_m=m_wd,
            mission_wp_seq=m_seq,
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
