"""Interface between the proxy TRANSPORT (relay) and live attack LOGIC.

Owners: transport = ``aegis-px4-mavlink`` (``proxy/transport.py``); attack logic and ground
truth = ``aegis-security`` (``proxy/attacks_live.py``, ``proxy/groundtruth.py``). The two
sides meet only here. Additive: independent of Stage-1 ``attacks/base.py`` /
``AttackContext`` (which need the simulator's encoder and ground-truth FlightState).

A hook sees ONE real MAVLink frame (raw bytes + header fields parsed by the transport) and
returns the frames to forward (possibly the same, modified, none, or several). It must not
read detector state or PX4/Gazebo ground truth, and must not open sockets.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

Direction = Literal["down", "up"]  # down: PX4 -> clients (IDS, GCS); up: clients -> PX4


@dataclass(frozen=True)
class FrameContext:
    direction: Direction
    raw: bytes          # exactly one complete MAVLink frame (v1 or v2)
    recv_ns: int        # proxy receive time, ``time.monotonic_ns`` clock
    sysid: int
    compid: int
    seq: int
    msgid: int
    signed: bool


# frames to forward, in order; ``[]`` drops the frame. Pass-through = ``[ctx.raw]``.
FrameHook = Callable[[FrameContext], list[bytes]]


def passthrough(ctx: FrameContext) -> list[bytes]:
    return [ctx.raw]
