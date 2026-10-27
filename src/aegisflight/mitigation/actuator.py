"""Pre-allocated MAVLink v2 counter-command packet builder."""

from __future__ import annotations

from pymavlink.dialects.v20 import common as mav2

from ..mavlink.codec import COPTER_MODES
from ..mavlink.signing import MavlinkSignatureVerifier

MAV_CMD_DO_AUX_FUNCTION = getattr(mav2, "MAV_CMD_DO_AUX_FUNCTION", 218)


def x25_crc(data: bytes, initial: int = 0xFFFF) -> int:
    """Compute X.25 CRC-16 used by MAVLink frame checksums."""
    crc = initial
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


class MavlinkActuator:
    """Encodes corrective MAVLink v2 commands with zero object allocation churn."""

    def __init__(
        self,
        sysid: int = 1,
        compid: int = 191,
        secret_key: bytes | None = None,
        link_id: int = 0,
    ) -> None:
        self.sysid = sysid
        self.compid = compid
        self.link_id = link_id
        self._encoder = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
        self._encoder.robust_parsing = True
        self._seq = 0
        self._signer = MavlinkSignatureVerifier(secret_key) if secret_key is not None else None

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq = (self._seq + 1) % 256
        self._encoder.seq = seq
        return seq

    def _finalize(self, raw: bytes) -> bytes:
        if self._signer is not None:
            return self._signer.sign_frame(raw, link_id=self.link_id)
        return raw

    @staticmethod
    def knows_mode(custom_mode_name: str | None) -> bool:
        """True only for an ArduCopter mode name this actuator can encode (PX4 names and unknowns are not)."""
        return bool(custom_mode_name) and str(custom_mode_name).upper() in COPTER_MODES

    def encode_set_mode(self, custom_mode_name: str, target_sysid: int = 1) -> bytes:
        """Encode MAV_CMD_DO_SET_MODE (176) to restore trusted flight mode.

        Raises ValueError for a mode it cannot map: never falls back to another mode (an AUTO fallback
        would start a mission, and on PX4 the same number means a different mode)."""
        if not self.knows_mode(custom_mode_name):
            raise ValueError(f"unknown ArduCopter mode {custom_mode_name!r}; refusing to guess a mode number")
        mode_id = COPTER_MODES[custom_mode_name.upper()]
        self._next_seq()
        msg = self._encoder.command_long_encode(
            target_sysid,
            1,  # target_component (autopilot)
            mav2.MAV_CMD_DO_SET_MODE,
            0,  # confirmation
            float(mav2.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED),
            float(mode_id),
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        )
        return self._finalize(bytes(msg.pack(self._encoder)))

    def encode_ekf_source_switch(self, source_set: int = 2, target_sysid: int = 1) -> bytes:
        """Encode MAV_CMD_DO_AUX_FUNCTION (218) with Aux 90 (EKF Pos Source Switch).

        source_set: 1 = Primary GPS, 2 = Secondary GPS / Dead-Reckoning / OptFlow.
        """
        self._next_seq()
        msg = self._encoder.command_long_encode(
            target_sysid,
            1,
            MAV_CMD_DO_AUX_FUNCTION,
            0,
            90.0,  # Aux function 90: EKF Pos Source
            float(source_set),
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        )
        return self._finalize(bytes(msg.pack(self._encoder)))

    def encode_prearm_disarm(self, force: bool = False, target_sysid: int = 1) -> bytes:
        """Encode MAV_CMD_COMPONENT_ARM_DISARM (400). ``force`` adds ArduPilot's force-disarm code (21196),
        which bypasses the autopilot's own checks; it is off by default and the controller never sets it."""
        self._next_seq()
        force_magic = 21196.0 if force else 0.0
        msg = self._encoder.command_long_encode(
            target_sysid,
            1,
            mav2.MAV_CMD_COMPONENT_ARM_DISARM,
            0,
            0.0,  # disarm
            force_magic,  # force disarm magic number in ArduPilot
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        )
        return self._finalize(bytes(msg.pack(self._encoder)))

    def encode_param_set(
        self,
        param_id: str,
        param_value: float,
        target_sysid: int = 1,
    ) -> bytes:
        """Encode PARAM_SET (23) to revert unauthorized parameter tampering."""
        self._next_seq()
        msg = self._encoder.param_set_encode(
            target_sysid,
            1,
            param_id.encode("ascii")[:16].ljust(16, b"\x00"),
            float(param_value),
            mav2.MAV_PARAM_TYPE_REAL32,
        )
        return self._finalize(bytes(msg.pack(self._encoder)))

    def encode_statustext(self, text: str, severity: int = 2) -> bytes:
        """Encode STATUSTEXT (253) message for GCS / HUD display."""
        self._next_seq()
        raw_text = text.encode("utf-8")[:50]
        msg = self._encoder.statustext_encode(severity, raw_text)
        return self._finalize(bytes(msg.pack(self._encoder)))
