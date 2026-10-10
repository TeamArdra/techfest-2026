"""P2 attack for the ArduPilot SITL path: downlink position drift, started by an attacker-observable gate.

Red side only (no detector imports, no detector state, no simulator ground truth). It wraps the
EXISTING, reviewed ``aegisflight.proxy.attacks_live.PositionDriftAttack`` unchanged -- same
modification (rewrite ``GLOBAL_POSITION_INT`` lat/lon with a closed-form drift, leave ``vx/vy/vz/
alt/relative_alt`` truthful, recompute the MAVLink 2 CRC) -- and adds one thing: a start gate.

Gate: the attack stays pass-through until the in-path attacker SEES, in the downlink it is
already carrying, a ``GLOBAL_POSITION_INT`` from the target with ``relative_alt >= airborne_m``.
The drift clock (``onset``/``duration``) then starts at that frame. This is information a real
man-in-the-middle on the link has; it is NOT simulator ground truth. Without the gate the window
would be placed by wall-clock offset from the first frame and could land on the ground whenever
arming takes longer than in the last run.

Claim class: **link-level detection (SITL)**. The modification is applied to frames travelling from
the simulator to the IDS; the simulator never receives a modified frame, so its estimator and
trajectory are untouched -- this is NOT GPS spoofing of the vehicle and NOT a physical deviation.

Spec (CLI ``--attack``): ``position_drift:onset=5,duration=25,rate=5,bearing=90,airborne_m=12``
(seconds after the gate, seconds, m/s, degrees clockwise from north, metres above home).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "src") not in sys.path:  # pragma: no cover - editable install normally covers this
    sys.path.insert(0, str(REPO / "src"))

from aegisflight.proxy.attacks_live import PositionDriftAttack, PositionDriftParams  # noqa: E402
from aegisflight.proxy.groundtruth import FrameLogWriter, compute_actual_effect  # noqa: E402
from aegisflight.proxy.hooks import FrameContext  # noqa: E402

GLOBAL_POSITION_INT_ID = 33
_GPI_SIZE = 28  # time_boot_ms u32, lat, lon, alt, relative_alt i32 x4, vx vy vz i16 x3, hdg u16


def relative_alt_m(frame: bytes) -> float | None:
    """relative_alt (m) of a v2 GLOBAL_POSITION_INT frame, tolerating MAVLink-2 trailing-zero truncation."""
    if len(frame) < 12 or frame[0] != 0xFD:
        return None
    payload = frame[10:10 + frame[1]].ljust(_GPI_SIZE, b"\x00")
    return struct.unpack_from("<i", payload, 16)[0] / 1000.0


class AirborneGatedDrift:
    """``FrameHook``: pass-through until the target is seen airborne, then ``PositionDriftAttack``."""

    def __init__(self, params: PositionDriftParams, *, target: tuple[int, int] = (1, 1),
                 airborne_m: float = 12.0, frame_log: FrameLogWriter | None = None) -> None:
        self.params = params
        self.target = target
        self.airborne_m = airborne_m
        # warmup 0: the gate IS the warmup; explicit target: never learned from an autopilot id
        self.inner = PositionDriftAttack(params, target_sysid=target[0], target_compid=target[1],
                                         warmup_s=0.0, frame_log=frame_log)
        self.gate_open_recv_ns: int | None = None
        self.gate_relative_alt_m: float | None = None
        self.frames_before_gate = 0

    def __call__(self, ctx: FrameContext) -> list[bytes]:
        if self.gate_open_recv_ns is None:
            if (ctx.direction == "down" and ctx.msgid == GLOBAL_POSITION_INT_ID
                    and (ctx.sysid, ctx.compid) == self.target and not ctx.signed):
                alt = relative_alt_m(ctx.raw)
                if alt is not None and alt >= self.airborne_m:
                    self.gate_open_recv_ns = ctx.recv_ns
                    self.gate_relative_alt_m = alt
            if self.gate_open_recv_ns is None:
                self.frames_before_gate += 1
                return [ctx.raw]
        return self.inner(ctx)


class AttackHandle:
    def __init__(self, hook: AirborneGatedDrift, frame_log_path: Path, writer: FrameLogWriter,
                 meta: dict[str, Any]) -> None:
        self.hook, self._path, self._writer, self.meta = hook, frame_log_path, writer, meta

    def finalize(self) -> dict[str, Any]:
        """Close the ground-truth log; counters + realised effect (computed from the log only)."""
        self._writer.close()
        h, inner = self.hook, self.hook.inner
        effect: dict[str, Any] = {}
        if self._path.exists() and inner.frames_modified:
            effect = compute_actual_effect(self._path, ref_lat_deg=-35.363261)
        return {"gate_opened": h.gate_open_recv_ns is not None, "gate_relative_alt_m": h.gate_relative_alt_m,
                "gate_open_recv_ns": h.gate_open_recv_ns, "frames_before_gate": h.frames_before_gate,
                "frames_seen_by_attack": inner.frames_seen, "frames_modified": inner.frames_modified,
                "frames_skipped_signed": inner.frames_skipped_signed, "actual_effect": effect}


def parse_spec(spec: str) -> dict[str, float]:
    name, _, rest = spec.partition(":")
    if name != "position_drift":
        raise ValueError(f"unknown attack {name!r} (only position_drift is implemented)")
    allowed = {"onset", "duration", "rate", "bearing", "airborne_m"}
    out: dict[str, float] = {}
    for part in filter(None, rest.split(",")):
        k, _, v = part.partition("=")
        if k not in allowed:
            raise ValueError(f"unknown attack parameter {k!r}; allowed: {sorted(allowed)}")
        out[k] = float(v)
    missing = {"onset", "duration", "rate", "bearing"} - out.keys()
    if missing:
        raise ValueError(f"attack spec is missing {sorted(missing)}")
    return out


def build_attack(spec: str, out_dir: Path) -> tuple[AirborneGatedDrift, AttackHandle]:
    p = parse_spec(spec)
    params = PositionDriftParams(trial_seed=0, trial_index=0, onset_s=p["onset"], duration_s=p["duration"],
                                 drift_rate_ms=p["rate"], bearing_deg=p["bearing"])
    log_path = out_dir / "attack_frames.jsonl"
    writer = FrameLogWriter(log_path)
    hook = AirborneGatedDrift(params, airborne_m=p.get("airborne_m", 12.0), frame_log=writer)
    meta = {"spec": spec, "attack": "position_drift (GLOBAL_POSITION_INT lat/lon, downlink)",
            "injection_point": "downlink, simulator -> IDS (in-path, Windows side of the pipe)",
            "claim_class": "link-level detection (SITL); estimator and flight unaffected",
            "params": {"onset_after_gate_s": params.onset_s, "duration_s": params.duration_s,
                       "drift_rate_ms": params.drift_rate_ms, "bearing_deg": params.bearing_deg,
                       "airborne_gate_m": hook.airborne_m, "target": list(hook.target)},
            "reused_unchanged": "aegisflight.proxy.attacks_live.PositionDriftAttack",
            "frame_log": str(log_path)}
    return hook, AttackHandle(hook, log_path, writer, meta)
