"""Hardware Abstraction Layer (HAL) for multi-autopilot, multi-compute deployment."""

from .discovery import CompanionInfo, HardwareDiscovery, PortInfo
from .identify import EndpointInfo, EndpointType, HardwareFingerprint
from .link_graph import LinkGraph, LinkTopologyType
from .profiles import AutopilotType, FirmwareProfile, get_firmware_profile
from .topology import TopologyDecision, TopologyPlanner

__all__ = [
    "AutopilotType",
    "CompanionInfo",
    "EndpointInfo",
    "EndpointType",
    "FirmwareProfile",
    "HardwareDiscovery",
    "HardwareFingerprint",
    "LinkGraph",
    "LinkTopologyType",
    "PortInfo",
    "TopologyDecision",
    "TopologyPlanner",
    "get_firmware_profile",
]
