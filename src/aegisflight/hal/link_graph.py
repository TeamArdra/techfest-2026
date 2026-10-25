"""Graph-based wiring topology resolver between GCS, Companion, and Flight Controller."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class LinkTopologyType(str, Enum):
    TOPOLOGY_B_INLINE = "b"
    TOPOLOGY_A_SIDECAR = "a"
    TOPOLOGY_AB_HYBRID = "a+b"
    IDS_ONLY = "ids"


@dataclass
class LinkGraph:
    """Represents physical & MAVLink connectivity across nodes."""

    # True if all GCS packets traverse the companion compute before reaching FC
    gcs_through_companion: bool = True
    # True if the companion computer has an active MAVLink routing bridge
    companion_bridge_active: bool = True
    # True if there is a secondary direct link from GCS to FC (e.g. ELRS or RC MAVLink)
    has_secondary_direct_link: bool = False
    # True if flight controller firmware allows companion override commands
    fc_accepts_commands: bool = True
    # True if companion computer meets CPU & latency headroom budgets
    latency_budget_met: bool = True

    def resolve(self) -> tuple[LinkTopologyType, list[str]]:
        """Resolve optimal, safest deployment topology and explicit rationale."""
        reasons: list[str] = []

        if not self.fc_accepts_commands:
            reasons.append("Flight controller rejects companion commands (SYSID/Signing mismatch) -> Falling back to IDS Only")
            return LinkTopologyType.IDS_ONLY, reasons

        if not self.latency_budget_met:
            reasons.append("Companion compute latency or CPU headroom budget exceeded -> Stepping down to Topology A (Sidecar)")
            return LinkTopologyType.TOPOLOGY_A_SIDECAR, reasons

        if self.gcs_through_companion and self.companion_bridge_active:
            if self.has_secondary_direct_link:
                reasons.append("Primary link routed inline via companion; secondary direct link detected -> Topology A+B Hybrid active")
                return LinkTopologyType.TOPOLOGY_AB_HYBRID, reasons

            reasons.append("Companion compute is the sole physical telemetry bridge between GCS and FC -> Topology B (Inline) active")
            return LinkTopologyType.TOPOLOGY_B_INLINE, reasons

        # Companion is connected to FC TELEM2/USB sidecar port while radio connects to TELEM1
        reasons.append("Radio connected directly to FC; companion connected as sidecar on auxiliary port -> Topology A active")
        return LinkTopologyType.TOPOLOGY_A_SIDECAR, reasons
