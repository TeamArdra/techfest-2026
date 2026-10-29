"""Detected deployment topology: pure builders, no I/O.

The operator never selects a topology; it follows from how the software is connected.

* ``A``      sidecar monitor on ONE port: sees only what the flight controller sends there; can detect and (in
             active-ips) send counter-commands on that port; can NOT block frames.
* ``A+B``    inline bridge between the flight controller and the GCS radio: sees both directions, can drop hostile
             uplink frames (active-ips) and send counter-commands.
* ``SIM``    modelled twin; ``REPLAY`` has no wiring; ``UNKNOWN`` when nothing is known.

Reasons only state what was observed.
"""
from __future__ import annotations

from typing import Any

POSTURES = ("passive", "advisory", "active-ips")


def _posture(p: Any) -> str:
    v = str(getattr(p, "value", p) or "passive").lower()
    return v if v in POSTURES else "passive"


def _flag(v: Any) -> bool | None:
    return v if isinstance(v, bool) else None


def _link(connected: bool | None = None, name: str | None = None) -> dict[str, Any]:
    return {"connected": connected, "name": name}


def _info(kind: str, label: str, source: str, posture: str, fc: dict, gcs: dict, uplink: bool | None,
          block: bool, counter: bool, reasons: list[str]) -> dict[str, Any]:
    return {"kind": kind, "label": label, "source": source, "posture": posture,
            "links": {"fc": fc, "gcs": gcs}, "uplink_visible": uplink,
            "can_block_frames": bool(block), "can_send_counter_commands": bool(counter), "reasons": reasons}


def unknown_topology(posture: Any = "passive") -> dict[str, Any]:
    return _info("UNKNOWN", "Unknown", "none", _posture(posture), _link(), _link(), None, False, False,
                 ["no connection information available"])


def sim_topology(posture: Any) -> dict[str, Any]:
    p = _posture(posture)
    return _info("SIM", "Simulation (modelled inline twin)", "modelled", p, _link(), _link(), None, False, False,
                 ["simulated vehicle: the twin models an inline deployment, nothing is wired or transmitted"])


def replay_topology(posture: Any) -> dict[str, Any]:
    return _info("REPLAY", "Replay (no wiring)", "none", _posture(posture), _link(), _link(), None, False, False,
                 ["recorded log: no live link, nothing can act on a vehicle"])


def sidecar_topology(posture: Any, *, connected: bool | None, name: str | None, uplink_seen: bool,
                     writable: bool = True) -> dict[str, Any]:
    """Live single link (serial or UDP) on one port."""
    p = _posture(posture)
    counter = p == "active-ips" and bool(writable)
    reasons = ["single port: sees only what the flight controller sends here"]
    if connected is True:
        reasons.append("link connected")
    elif connected is False:
        reasons.append("link not connected")
    else:
        reasons.append("link state not reported by this transport (UDP: judged by frame age)")
    reasons.append("ground-station frames or commands seen on this port: uplink partly visible" if uplink_seen
                   else "no ground-station frames seen: uplink not visible")
    reasons.append("cannot block frames from a single port")
    if p != "active-ips":
        reasons.append(f"posture {p}: no counter-commands are sent")
    elif not writable:
        reasons.append("source has no writable transport: no counter-commands")
    return _info("A", "Sidecar (single port)", "detected", p, _link(connected, name), _link(), bool(uplink_seen),
                 False, counter, reasons)


def bridge_topology(posture: Any, *, fc_connected: bool | None, gcs_connected: bool | None,
                    gcs_frames_seen: int, fc_name: str | None = None, gcs_name: str | None = None) -> dict[str, Any]:
    """Inline bridge between flight controller and GCS radio."""
    p = _posture(posture)
    fc_ok, gcs_ok = fc_connected is True, gcs_connected is True
    uplink = gcs_frames_seen > 0 or gcs_ok
    block = p == "active-ips" and fc_ok and gcs_ok
    counter = p == "active-ips" and fc_ok
    reasons = ["inline bridge: flight-controller link and GCS link are both handled by this process"]
    for nm, c in (("flight-controller", fc_connected), ("GCS", gcs_connected)):
        reasons.append(f"{nm} link {'connected' if c else 'DOWN' if c is False else 'state not reported'}")
    reasons.append(f"{int(gcs_frames_seen)} frame(s) seen from the GCS side")
    if p != "active-ips":
        reasons.append(f"posture {p}: frames are forwarded unchanged, no blocking, no counter-commands")
    else:
        if not fc_ok:
            reasons.append("flight-controller link down: cannot send counter-commands or block")
        elif not gcs_ok:
            reasons.append("GCS link not confirmed up: not claiming frame blocking")
    return _info("A+B", "Inline bridge (FC <-> GCS)", "detected", p, _link(_flag(fc_connected), fc_name),
                 _link(_flag(gcs_connected), gcs_name), uplink, block, counter, reasons)


def legacy_name(info: dict[str, Any]) -> str:
    return {"A": "a", "A+B": "a+b", "SIM": "sim", "REPLAY": "replay"}.get(info.get("kind"), "unknown")
