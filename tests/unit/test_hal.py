"""Unit tests for the Hardware Abstraction Layer (HAL) and Topology Planner."""

from __future__ import annotations

import time

from aegisflight.hal.discovery import CompanionInfo, HardwareDiscovery
from aegisflight.hal.identify import EndpointIdentifier, HardwareFingerprint
from aegisflight.hal.inline_bridge import InlineBridge
from aegisflight.hal.link_graph import LinkGraph, LinkTopologyType
from aegisflight.hal.profiles import AutopilotType, get_firmware_profile
from aegisflight.hal.topology import TopologyPlanner
from aegisflight.mitigation.sanitizer import FrameSanitizer


def test_companion_discovery():
    comp = HardwareDiscovery.detect_companion()
    assert isinstance(comp, CompanionInfo)
    assert comp.cpu_count >= 1
    assert comp.cpu_headroom_pct > 0.0
    assert comp.latency_budget_ms >= 10.0


def test_serial_port_discovery():
    ports = HardwareDiscovery.scan_serial_ports()
    assert isinstance(ports, list)


def test_endpoint_identifier_heartbeat():
    ident = EndpointIdentifier()

    # 1. GCS Heartbeat (type=6)
    ident.observe_message("HEARTBEAT", {"type": 6, "autopilot": 0}, sysid=255, compid=190)
    assert 255 in ident.fingerprint.gcs_sysids

    # 2. ArduPilot Copter Heartbeat (autopilot=3, type=2)
    ident.observe_message("HEARTBEAT", {"type": 2, "autopilot": 3}, sysid=1, compid=1)
    assert ident.fingerprint.autopilot == AutopilotType.ARDUPILOT
    assert ident.fingerprint.vehicle_class == "COPTER"

    # 3. Secondary sensors
    ident.observe_message("OPTICAL_FLOW", {}, sysid=1, compid=1)
    assert ident.fingerprint.has_optical_flow is True

    ident.observe_message("RADIO_STATUS", {"rssi": 180}, sysid=1, compid=1)
    assert ident.fingerprint.has_radio_status is True
    assert ident.fingerprint.radio_rssi == 180


def test_firmware_profiles():
    # ArduCopter profile
    prof_ap = get_firmware_profile(AutopilotType.ARDUPILOT, "COPTER")
    assert prof_ap.is_supported_for_ips is True
    assert prof_ap.resolve_mode_number("AUTO") == 3
    assert prof_ap.resolve_mode_number("LAND") == 9

    cmd_auto = prof_ap.encode_restore_mode("AUTO")
    assert cmd_auto.custom_mode == 3
    assert cmd_auto.command_name == "MAV_CMD_DO_SET_MODE"

    ekf_ap = prof_ap.encode_ekf_switch(secondary_available=True)
    assert ekf_ap["command_id"] == 42007

    # ArduPlane profile
    prof_plane = get_firmware_profile(AutopilotType.ARDUPILOT, "PLANE")
    assert prof_plane.resolve_mode_number("AUTO") == 10

    # PX4 profile
    prof_px4 = get_firmware_profile(AutopilotType.PX4, "COPTER")
    assert prof_px4.is_supported_for_ips is True
    px4_auto = prof_px4.resolve_mode_number("AUTO")
    assert (px4_auto >> 16) & 0xFF == 4  # MAIN_AUTO
    assert (px4_auto >> 24) & 0xFF == 4  # SUB_MISSION

    # Generic / unsupported autopilot
    prof_gen = get_firmware_profile(AutopilotType.GENERIC, "COPTER")
    assert prof_gen.is_supported_for_ips is False


def test_link_graph_resolution():
    # Case 1: Sole inline path -> Topology B
    g_inline = LinkGraph(gcs_through_companion=True, companion_bridge_active=True, has_secondary_direct_link=False)
    top1, reasons1 = g_inline.resolve()
    assert top1 == LinkTopologyType.TOPOLOGY_B_INLINE
    assert any("Topology B" in r for r in reasons1)

    # Case 2: Inline + secondary direct link -> Topology A+B Hybrid
    g_hybrid = LinkGraph(gcs_through_companion=True, companion_bridge_active=True, has_secondary_direct_link=True)
    top2, reasons2 = g_hybrid.resolve()
    assert top2 == LinkTopologyType.TOPOLOGY_AB_HYBRID

    # Case 3: Sidecar auxiliary port -> Topology A
    g_side = LinkGraph(gcs_through_companion=False, companion_bridge_active=False)
    top3, reasons3 = g_side.resolve()
    assert top3 == LinkTopologyType.TOPOLOGY_A_SIDECAR

    # Case 4: FC rejects commands -> IDS Only
    g_ids = LinkGraph(fc_accepts_commands=False)
    top4, _ = g_ids.resolve()
    assert top4 == LinkTopologyType.IDS_ONLY


def test_topology_planner_decisions():
    comp = CompanionInfo(
        system="Linux",
        machine="aarch64",
        model="Raspberry Pi 4 Model B",
        cpu_count=4,
        is_raspberry_pi=True,
        cpu_headroom_pct=78.0,
    )
    fp = HardwareFingerprint(
        autopilot=AutopilotType.ARDUPILOT,
        vehicle_class="COPTER",
        has_optical_flow=True,
    )
    graph = LinkGraph(gcs_through_companion=True, companion_bridge_active=True)

    # 1. Normal disarmed check -> Topology B
    dec = TopologyPlanner.decide(fp, comp, graph, is_armed=False)
    assert dec.topology == LinkTopologyType.TOPOLOGY_B_INLINE
    assert dec.capabilities["inline_filtering"] is True
    assert dec.capabilities["ekf_switch"] is True

    # 2. Armed in flight: locked from escalating
    dec_armed = TopologyPlanner.decide(fp, comp, graph, is_armed=True, active_topology=LinkTopologyType.TOPOLOGY_A_SIDECAR)
    assert dec_armed.topology == LinkTopologyType.TOPOLOGY_A_SIDECAR

    # 3. Unsupported firmware -> IDS Only
    fp_unsupported = HardwareFingerprint(autopilot=AutopilotType.UNKNOWN)
    dec_ids = TopologyPlanner.decide(fp_unsupported, comp, graph, is_armed=False)
    assert dec_ids.topology == LinkTopologyType.IDS_ONLY

    # 4. Low CPU headroom (< 25%) -> steps down to Topology A
    comp_stressed = CompanionInfo(
        system="Linux",
        machine="armv7l",
        model="Raspberry Pi Zero W",
        cpu_count=1,
        cpu_headroom_pct=15.0,
    )
    dec_stepdown = TopologyPlanner.decide(fp, comp_stressed, graph, is_armed=False)
    assert dec_stepdown.topology == LinkTopologyType.TOPOLOGY_A_SIDECAR


def test_inline_bridge_and_watchdog():
    sanitizer = FrameSanitizer()
    sanitizer.configure(active=True, quarantined_sysids={66})
    bridge = InlineBridge(sanitizer, watchdog_timeout_s=0.08)

    # 1. In PASSIVE: all packets pass through
    bridge.active_ips = False
    raw_packet = b"\xfd\x01\x00\x00\x00\x42\x01\x00\x00\x00\x00\x00"  # sysid 66 (0x42)
    res_pass = bridge.process_frame(raw_packet, "up")
    assert res_pass == raw_packet
    assert bridge.frames_forwarded == 1

    # 2. In ACTIVE_IPS: quarantined packets dropped
    bridge.active_ips = True
    res_ips = bridge.process_frame(raw_packet, "up")
    assert res_ips is None
    assert bridge.frames_dropped == 1

    # 3. Watchdog fail-open
    assert bridge.check_watchdog() is True
    # Simulate a 100ms pipeline hang
    time.sleep(0.09)
    assert bridge.check_watchdog() is False
    assert bridge.fail_open_triggered is True

    # After fail-open: even quarantined packet passes to preserve link
    res_failopen = bridge.process_frame(raw_packet, "up")
    assert res_failopen == raw_packet
