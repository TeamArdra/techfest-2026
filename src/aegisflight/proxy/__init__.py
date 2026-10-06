"""Live MAVLink attack proxy (Stage 2, P2). See docs/ATTACK_PROXY.md."""

from .attacks_live import (
    COMMAND_INJECTION_RANGES,
    RANGES,
    CommandInjectionAttack,
    CommandInjectionParams,
    PositionDriftAttack,
    PositionDriftParams,
    draw_command_injection_params,
    draw_params,
)
from .groundtruth import (
    FrameLogEntry,
    FrameLogWriter,
    Manifest,
    compute_actual_effect,
    compute_command_injection_effect,
    is_holdout,
    read_frame_log,
    read_manifest,
    write_manifest,
)
from .hooks import FrameContext, FrameHook, passthrough

__all__ = [
    "COMMAND_INJECTION_RANGES",
    "RANGES",
    "CommandInjectionAttack",
    "CommandInjectionParams",
    "FrameContext",
    "FrameHook",
    "FrameLogEntry",
    "FrameLogWriter",
    "Manifest",
    "PositionDriftAttack",
    "PositionDriftParams",
    "compute_actual_effect",
    "compute_command_injection_effect",
    "draw_command_injection_params",
    "draw_params",
    "is_holdout",
    "passthrough",
    "read_frame_log",
    "read_manifest",
    "write_manifest",
]
