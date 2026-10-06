"""Ground-truth manifest + frame-level log for the live attack proxy (P2).

Schema: ``docs/ATTACK_PROXY.md`` §4, implemented here exactly as specified there.
Written **only** by the proxy's attack logic itself, at modification time, frame
by frame -- never derived from, or written by, any detector output (red/blue
separation per ``.claude/CLAUDE.md`` "Security principles" / "Detectors read
only ``FeatureFrame``").

``Manifest.detector_decision`` / ``Manifest.time_to_detection_s`` are explicit,
nullable, reserved fields: this module never writes them. They are declared
``init=False`` with a fixed default of ``None`` -- there is no constructor
argument or setter that lets a caller of this module put a non-null value in
them, which enforces the "never written by this module" rule structurally, not
just by convention. Filling them in from a *separate* join against IDS
decisions is ``aegis-validation``'s job, done on its own copy of the data (e.g.
reading the manifest JSON directly with ``json.load`` and writing an augmented
copy elsewhere) -- not through this module's ``Manifest``/``read_manifest``,
which cannot represent a non-null value for either field.

Red/blue disclosure rule (``docs/ATTACK_PROXY.md`` §6): of the trial seeds run,
some may be held out -- their *exact* per-trial parameter draws must not be
used to calibrate P3 detector thresholds, only the disclosed parameter
*ranges* (``attacks_live.RANGES``) may inform calibration. ``Manifest
.holdout_seeds`` records which seeds are held out; :func:`is_holdout` is the
check a calibration step should call before using a trial's ``parameters``.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..core.geo import EARTH_RADIUS_M

SCHEMA_ID = "aegisflight.proxy.groundtruth"
SCHEMA_VERSION = "1.0.0"

#: Keys the caller's ``provenance`` dict must supply (docs/ATTACK_PROXY.md §1 /
#: task spec): PX4 ``git describe``, this repo's git commit, and the Python /
#: pymavlink versions in use. Extra keys (e.g. ``gazebo_version``) are allowed
#: and passed through unchanged. This module never shells out to git/wsl to
#: discover these itself -- the caller (an integration/runbook layer) supplies
#: them, so this module stays pure and unit-testable without PX4 or WSL.
REQUIRED_PROVENANCE_KEYS = (
    "px4_git_describe",
    "aegisflight_git_commit",
    "python_version",
    "pymavlink_version",
)

_VALID_INJECTION_POINTS = ("downlink", "uplink")
#: ``observed_ack`` is additive (beyond the task's literal 4-counter/action list) for the
#: command-injection attack (``attacks_live.CommandInjectionAttack``): it logs a downlink
#: ``COMMAND_ACK`` the attack hook matched, by command id, to a frame it injected. It is not
#: a modification/drop/injection of the ack frame itself (the ack always passes through
#: unchanged) -- it is a ground-truth observation, which is why it is a distinct action from
#: ``forwarded``.
_VALID_ACTIONS = frozenset(
    {"modified", "forwarded", "dropped", "injected", "delayed", "observed_ack"}
)


def _validate_provenance(provenance: Mapping[str, str]) -> None:
    missing = [k for k in REQUIRED_PROVENANCE_KEYS if not provenance.get(k)]
    if missing:
        raise ValueError(f"provenance missing required keys: {missing}")


@dataclass(frozen=True)
class Manifest:
    """Per-trial ground-truth manifest -- ``docs/ATTACK_PROXY.md`` §4.

    Construct and pass to :func:`write_manifest`. ``detector_decision`` and
    ``time_to_detection_s`` are always ``None`` here (see module docstring).
    """

    trial_id: str
    seed: int
    trial_index: int
    provenance: Mapping[str, str]
    attack_type: str  # Stage-1 AttackType.value, for continuity only (not reuse of Attack class)
    attack_mode: str
    message_type: str
    target_system: int
    target_component: int
    injection_point: str  # "downlink" | "uplink"
    claim_class: str
    environment: str
    attack_action: str
    parameters: Mapping[str, Any]
    attack_start_utc: str
    attack_end_utc: str
    frames_seen: int
    frames_modified: int
    frames_dropped: int
    frames_injected: int
    expected_effect: Mapping[str, Any]
    actual_effect: Mapping[str, Any] | None = None
    # Not in the task's literal 4-counter list but needed to account for the
    # documented "refuse to modify signed frames" behaviour (§3); additive.
    frames_skipped_signed: int = 0
    holdout_seeds: Sequence[int] = ()
    schema_id: str = field(default=SCHEMA_ID, init=False)
    schema_version: str = field(default=SCHEMA_VERSION, init=False)
    detector_decision: Any = field(default=None, init=False)
    time_to_detection_s: float | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        _validate_provenance(self.provenance)
        if self.injection_point not in _VALID_INJECTION_POINTS:
            raise ValueError(
                f"injection_point must be one of {_VALID_INJECTION_POINTS}, "
                f"got {self.injection_point!r}"
            )


def write_manifest(manifest: Manifest, path: Path) -> None:
    """Write ``manifest`` as pretty-printed JSON to ``path`` (parents created)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = asdict(manifest)
    data["holdout_seeds"] = list(manifest.holdout_seeds)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_manifest(path: Path) -> Manifest:
    """Read back a manifest written by :func:`write_manifest`.

    ``schema_id``/``schema_version``/``detector_decision``/``time_to_detection_s``
    are ``init=False`` fields on :class:`Manifest`: they are dropped from the
    loaded JSON before reconstruction (this round-trip is for this module's own
    tests/reuse; it intentionally cannot represent a non-null detector verdict).
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for key in ("schema_id", "schema_version", "detector_decision", "time_to_detection_s"):
        data.pop(key, None)
    data["holdout_seeds"] = tuple(data.get("holdout_seeds", ()))
    return Manifest(**data)


def is_holdout(seed: int, holdout_seeds: Iterable[int]) -> bool:
    """``True`` if ``seed`` is one of the disclosed-ranges-only holdout trials.

    Per ``docs/ATTACK_PROXY.md`` §6: holdout trials' exact parameter draws must
    not be used for P3 detector calibration -- only the parameter *ranges* are
    disclosed up front for those trials, never the specific drawn values.
    """
    return seed in set(holdout_seeds)


@dataclass(frozen=True)
class FrameLogEntry:
    """One line of the per-trial frame log -- ``docs/ATTACK_PROXY.md`` §4."""

    seq_no: int
    proxy_recv_time_utc: str
    recv_ns: int
    msgid: int
    sysid: int
    compid: int
    mavlink_seq: int
    action: str  # "modified" | "forwarded" | "dropped" | "injected" | "delayed"
    field_deltas: Mapping[str, int]
    crc_recomputed: bool
    original_len: int
    modified_len: int

    def __post_init__(self) -> None:
        if self.action not in _VALID_ACTIONS:
            raise ValueError(f"invalid action {self.action!r}, expected one of {_VALID_ACTIONS}")


class FrameLogWriter:
    """Append-only, per-frame-flushed JSONL writer -- ``docs/ATTACK_PROXY.md`` §4/§7.

    O(1) per frame: nothing is buffered in memory for a whole trial (resource
    bound in §7). By convention, call :meth:`append` only for *touched* frames
    (``action != "forwarded"`` for the common case) -- logging every one of
    hundreds of untouched messages per second would defeat the O(1)/no-unbounded
    -buffering intent without adding ground-truth value.
    """

    def __init__(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")

    def append(self, entry: FrameLogEntry) -> None:
        self._fh.write(json.dumps(asdict(entry)) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> FrameLogWriter:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def read_frame_log(path: Path) -> list[FrameLogEntry]:
    """Read back every entry written by :class:`FrameLogWriter`, in order."""
    entries: list[FrameLogEntry] = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entries.append(FrameLogEntry(**json.loads(line)))
    return entries


def compute_actual_effect(frame_log_path: Path, ref_lat_deg: float) -> dict[str, float]:
    """Measure the real lat/lon displacement actually written to the wire.

    Derived **only** from ``field_deltas`` of ``action == "modified"`` entries in
    the frame log -- never from detector output. Each entry's ``lat_1e7deg`` /
    ``lon_1e7deg`` delta is converted to metres using a flat-earth approximation
    (same convention as ``core.geo.offset_latlon``) and combined into a
    displacement magnitude.

    ``ref_lat_deg`` -- the one addition beyond the literal
    ``compute_actual_effect(frame_log_path)`` signature in
    ``docs/ATTACK_PROXY.md`` §4 -- is **required** because the frame-log schema
    (§4, deliberately followed exactly) stores only *deltas*, not absolute
    lat/lon, and converting a longitude delta to metres needs ``cos(lat)`` at
    the time of the frame. A fixed reference latitude (e.g. the SITL home
    latitude, roughly constant across one ~30-90 s trial for a hovering/slow
    vehicle) is accurate enough for this post-hoc, non-detector check; using
    ``ref_lat_deg=0`` would silently overstate east/west displacement by
    ``1/cos(lat)`` at non-equatorial latitudes (PX4 SITL's default lat is
    ~47 degrees => ~48% overstatement), which is worse than requiring the
    caller to pass it. See the handback report for why this was changed from
    the literal single-argument signature.

    Returns a dict with ``max_lat_lon_delta_m``, ``mean_lat_lon_delta_m``,
    ``position_residual_proxy_estimate_m`` (same as the mean -- an explicitly
    labelled proxy for the physics detector's residual feature, not the
    feature itself), and ``frames_counted``. Comparing this against the
    closed-form *prediction* (which needs ``drift_rate_ms``/timing from the
    trial's parameters, not present in the frame log) is left to the caller --
    e.g. the manifest's ``expected_effect`` alongside this function's output.
    """
    entries = [e for e in read_frame_log(frame_log_path) if e.action == "modified"]
    if not entries:
        return {
            "max_lat_lon_delta_m": 0.0,
            "mean_lat_lon_delta_m": 0.0,
            "position_residual_proxy_estimate_m": 0.0,
            "frames_counted": 0,
        }
    lat_rad = math.radians(ref_lat_deg)
    magnitudes_m: list[float] = []
    for entry in entries:
        dlat_deg = entry.field_deltas.get("lat_1e7deg", 0) / 1e7
        dlon_deg = entry.field_deltas.get("lon_1e7deg", 0) / 1e7
        north_m = math.radians(dlat_deg) * EARTH_RADIUS_M
        east_m = math.radians(dlon_deg) * EARTH_RADIUS_M * math.cos(lat_rad)
        magnitudes_m.append(math.hypot(north_m, east_m))
    mean_m = sum(magnitudes_m) / len(magnitudes_m)
    return {
        "max_lat_lon_delta_m": max(magnitudes_m),
        "mean_lat_lon_delta_m": mean_m,
        "position_residual_proxy_estimate_m": mean_m,
        "frames_counted": len(entries),
    }


def compute_command_injection_effect(frame_log_path: Path) -> dict[str, Any]:
    """Measure what the live command-injection attack actually put on the wire, and whether
    PX4 acknowledged it -- derived **only** from the frame log's ``"injected"`` and
    ``"observed_ack"`` entries, never from detector output (same red/blue separation rule as
    :func:`compute_actual_effect`).

    **Known limitation** (disclosed, not fixed here -- see the attack hook's own docstring
    and the handback report): MAVLink 2's ``COMMAND_LONG``/``COMMAND_ACK`` pair carries no
    request-id, so an ack is matched to an injected frame by ``command`` id alone. If a trial
    ever injects more than one distinct command type, or two acks for the same command id
    arrive in one trial, this function cannot disambiguate which injected frame a given ack
    answers; ``time_to_first_ack_s`` is computed from the *first* injected frame and the
    *first* observed ack in the log, which is only unambiguous for the single-command-type,
    single-outstanding-request case this attack currently implements (one command id per
    trial, repeated in a burst).

    Returns a dict with ``frames_injected``, ``acked`` (bool: at least one matching ack seen),
    ``ack_count``, ``first_ack_result`` (the ``MAV_RESULT_*`` int, or ``None``),
    ``first_ack_result_name`` (its name if known, e.g. ``"MAV_RESULT_ACCEPTED"``, or ``None``),
    and ``time_to_first_ack_s`` (seconds from the first injected frame's ``recv_ns`` to the
    first observed ack's ``recv_ns``, or ``None`` if no ack was observed).
    """
    entries = read_frame_log(frame_log_path)
    injected = [e for e in entries if e.action == "injected"]
    acks = [e for e in entries if e.action == "observed_ack"]
    result: dict[str, Any] = {
        "frames_injected": len(injected),
        "acked": bool(acks),
        "ack_count": len(acks),
        "first_ack_result": None,
        "first_ack_result_name": None,
        "time_to_first_ack_s": None,
    }
    if acks:
        result["first_ack_result"] = acks[0].field_deltas.get("result")
        result["first_ack_result_name"] = _MAV_RESULT_NAMES.get(result["first_ack_result"])
    if injected and acks:
        result["time_to_first_ack_s"] = (acks[0].recv_ns - injected[0].recv_ns) / 1e9
    return result


#: ``MAV_RESULT_*`` int -> name, for :func:`compute_command_injection_effect`'s
#: ``first_ack_result_name``. Built from the real dialect so it never drifts from the wire
#: enum; lazily avoids importing pymavlink at module scope in a file that otherwise has no
#: MAVLink dependency (``groundtruth.py`` is pure bookkeeping, deliberately socket- and
#: dialect-free everywhere else in this module).
def _mav_result_names() -> dict[int, str]:
    from pymavlink.dialects.v20 import common as _mav2

    return {
        getattr(_mav2, name): name
        for name in dir(_mav2)
        if name.startswith("MAV_RESULT_") and name != "MAV_RESULT_ENUM_END"
    }


_MAV_RESULT_NAMES: dict[int, str] = _mav_result_names()
