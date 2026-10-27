"""Hardware discovery for onboard companion computers and flight controllers."""

from __future__ import annotations

import glob
import os
import platform
from dataclasses import asdict, dataclass
from pathlib import Path

# Known USB Vendor IDs for Flight Controllers and Telemetry Radios
KNOWN_FC_VIDS = {
    0x2DAE: "CubePilot (Cube Orange / Black / Yellow)",
    0x26AC: "3DR / Pixhawk / Holybro",
    0x1209: "ArduPilot ChibiOS / Generic STM32",
    0x0483: "STMicroelectronics Virtual COM Port",
}

KNOWN_RADIO_VIDS = {
    0x0403: "FTDI USB-UART (SiK Radio / RFD900)",
    0x10C4: "Silicon Labs CP210x (Telemetry / ELRS)",
    0x1A86: "Winchiphead CH340 (Telemetry Adapter)",
}


@dataclass
class PortInfo:
    """Discovered physical or virtual communications link."""

    device: str
    description: str
    hwid: str = ""
    vid: int | None = None
    pid: int | None = None
    is_flight_controller: bool = False
    is_telemetry_radio: bool = False


@dataclass
class CompanionInfo:
    """Discovered host companion computer specifications."""

    system: str
    machine: str
    model: str
    cpu_count: int
    is_raspberry_pi: bool = False
    is_nvidia_jetson: bool = False
    cpu_headroom_pct: float = 85.0
    latency_budget_ms: float = 18.0

    def to_dict(self) -> dict:
        return asdict(self)


class HardwareDiscovery:
    """Discovers connected autopilot serial ports, radios, and host compute."""

    @staticmethod
    def detect_companion() -> CompanionInfo:
        """Inspect host platform and model."""
        sys_name = platform.system()
        mach = platform.machine()
        cpu_cnt = os.cpu_count() or 1
        model_str = f"{sys_name} {mach}"
        is_rpi = False
        is_jetson = False

        # 1. Check for Raspberry Pi device tree
        dt_model = Path("/proc/device-tree/model")
        if dt_model.exists():
            try:
                raw_model = dt_model.read_text(encoding="utf-8", errors="ignore").strip().rstrip("\x00")
                if raw_model:
                    model_str = raw_model
                    is_rpi = "raspberry pi" in raw_model.lower()
            except Exception:
                pass

        # 2. Check for NVIDIA Jetson release file
        nv_tegra = Path("/etc/nv_tegra_release")
        if nv_tegra.exists():
            is_jetson = True
            model_str = f"NVIDIA Jetson ({mach})"

        # Compute latency budget based on CPU capability
        # Pi 4 / 5 or x86 has plenty of headroom (< 18ms budget)
        # Pi Zero / 3 has tighter budget (< 24ms budget)
        latency_budget = 18.0
        if is_rpi and ("zero" in model_str.lower() or "pi 3" in model_str.lower()):
            latency_budget = 24.0

        return CompanionInfo(
            system=sys_name,
            machine=mach,
            model=model_str,
            cpu_count=cpu_cnt,
            is_raspberry_pi=is_rpi,
            is_nvidia_jetson=is_jetson,
            cpu_headroom_pct=85.0,
            latency_budget_ms=latency_budget,
        )

    @staticmethod
    def scan_serial_ports() -> list[PortInfo]:
        """Scan available serial ports using pyserial or dev-filesystem fallback."""
        discovered: list[PortInfo] = []

        try:
            import serial.tools.list_ports  # type: ignore

            for p in serial.tools.list_ports.comports():
                vid = p.vid
                pid = p.pid
                is_fc = bool(vid and vid in KNOWN_FC_VIDS)
                is_radio = bool(vid and vid in KNOWN_RADIO_VIDS)

                # Heuristic text check
                desc_lower = (p.description or "").lower()
                if any(k in desc_lower for k in ("cube", "pixhawk", "ardupilot", "px4", "autopilot")):
                    is_fc = True
                if any(k in desc_lower for k in ("sik", "rfd900", "telemetry", "elrs", "radio")):
                    is_radio = True

                discovered.append(
                    PortInfo(
                        device=p.device,
                        description=p.description or "",
                        hwid=p.hwid or "",
                        vid=vid,
                        pid=pid,
                        is_flight_controller=is_fc,
                        is_telemetry_radio=is_radio,
                    )
                )
        except Exception:
            # Fallback to dev globbing on Linux/Mac
            patterns = [
                "/dev/ttyAMA*",
                "/dev/ttyACM*",
                "/dev/ttyUSB*",
                "/dev/ttyS[0-9]*",
                "/dev/cu.usb*",
            ]
            seen = set()
            for pat in patterns:
                for path in glob.glob(pat):
                    if path not in seen:
                        seen.add(path)
                        discovered.append(
                            PortInfo(
                                device=path,
                                description=f"Serial Port ({os.path.basename(path)})",
                            )
                        )

        return discovered

    def scan(self) -> dict:
        """Complete system scan of ports and companion compute."""
        comp = self.detect_companion()
        ports = self.scan_serial_ports()
        return {
            "companion": comp.to_dict(),
            "ports": [asdict(p) for p in ports],
            "fc_count": sum(1 for p in ports if p.is_flight_controller),
            "radio_count": sum(1 for p in ports if p.is_telemetry_radio),
        }
