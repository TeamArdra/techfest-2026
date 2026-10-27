"""Autonomous topology planner and safety arbiter."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .discovery import CompanionInfo
from .identify import HardwareFingerprint
from .link_graph import LinkGraph, LinkTopologyType
from .profiles import get_firmware_profile


@dataclass
class TopologyDecision:
    """The planner's definitive topology decision and safety rationale."""

    topology: LinkTopologyType
    reasons: list[str] = field(default_factory=list)
    confidence: float = 0.95
    capabilities: dict[str, bool] = field(default_factory=dict)
    can_switch_in_flight: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["topology"] = self.topology.value
        return d


class TopologyPlanner:
    """Evaluates connected hardware, wiring graph, and platform headroom to select the safest topology."""

    @staticmethod
    def decide(
        fingerprint: HardwareFingerprint,
        companion: CompanionInfo,
        graph: LinkGraph,
        *,
        is_armed: bool = False,
        active_topology: LinkTopologyType = LinkTopologyType.TOPOLOGY_B_INLINE,
    ) -> TopologyDecision:
        """Resolve optimal topology with conservative fallback guarantees."""
        reasons: list[str] = []

        # Rule 1: In-Flight Lockout (Cannot escalate topology while armed)
        if is_armed:
            reasons.append("Vehicle is armed in flight: Autonomous topology changes locked to prevent link re-negotiation.")
            return TopologyDecision(
                topology=active_topology,
                reasons=reasons,
                confidence=0.99,
                capabilities={"inline_filtering": active_topology == LinkTopologyType.TOPOLOGY_B_INLINE},
                can_switch_in_flight=False,
            )

        # Rule 2: Firmware Support Validation
        profile = get_firmware_profile(fingerprint.autopilot, fingerprint.vehicle_class)
        if not profile.is_supported_for_ips:
            reasons.append(
                f"Autopilot firmware '{fingerprint.autopilot.value}' does not have verified closed-loop IPS control -> IDS Only"
            )
            return TopologyDecision(
                topology=LinkTopologyType.IDS_ONLY,
                reasons=reasons,
                confidence=0.99,
                capabilities={"monitoring_only": True},
                can_switch_in_flight=False,
            )

        # Rule 3: Flight Controller Command Acceptance
        if not fingerprint.accepts_companion_commands or not graph.fc_accepts_commands:
            reasons.append(
                "Flight controller rejected companion commands (SYSID_MYGCS or MAVLink signing guard) -> IDS Only"
            )
            return TopologyDecision(
                topology=LinkTopologyType.IDS_ONLY,
                reasons=reasons,
                confidence=0.98,
                capabilities={"monitoring_only": True},
                can_switch_in_flight=False,
            )

        # Rule 4: Headroom & Latency Budget Check
        if companion.cpu_headroom_pct < 25.0:
            graph.latency_budget_met = False
            reasons.append(f"Companion CPU headroom low ({companion.cpu_headroom_pct:.1f}% free) -> Stepping down B to A")

        # Rule 5: Graph-based Wiring Resolution
        top, graph_reasons = graph.resolve()
        reasons.extend(graph_reasons)

        caps = {
            "inline_filtering": top in (LinkTopologyType.TOPOLOGY_B_INLINE, LinkTopologyType.TOPOLOGY_AB_HYBRID),
            "sidecar_actuator": top in (LinkTopologyType.TOPOLOGY_A_SIDECAR, LinkTopologyType.TOPOLOGY_AB_HYBRID),
            "ekf_switch": fingerprint.has_optical_flow or fingerprint.has_secondary_gps or fingerprint.has_vision_nav,
            "zero_detour_command_drop": top in (LinkTopologyType.TOPOLOGY_B_INLINE, LinkTopologyType.TOPOLOGY_AB_HYBRID),
        }

        return TopologyDecision(
            topology=top,
            reasons=reasons,
            confidence=0.96,
            capabilities=caps,
            can_switch_in_flight=False,
        )
