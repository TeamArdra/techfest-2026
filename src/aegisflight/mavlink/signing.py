"""MAVLink v2 cryptographic packet signing (MAVLINK_IFLAG_SIGNED = 0x01) & anti-replay verifier."""

from __future__ import annotations

import hashlib
import hmac
import struct
import time
from dataclasses import dataclass

from pymavlink.dialects.v20 import common as mav2

MAVLINK_V2_MAGIC = 0xFD
MAVLINK_IFLAG_SIGNED = 0x01
MAVLINK_V2_HEADER_LEN = 10
MAVLINK_CRC_LEN = 2
MAVLINK_SIGNATURE_LEN = 13
# MAVLink 2 signature epoch: 2015-01-01 00:00:00 UTC
MAVLINK_EPOCH_UNIX_S = 1_420_070_400


def _x25_crc(data: bytes, initial: int = 0xFFFF) -> int:
    """Compute X.25 CRC-16 used by MAVLink frame checksums."""
    crc = initial
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def _lookup_crc_extra(msgid: int) -> int | None:
    cls = mav2.mavlink_map.get(msgid)
    if cls is not None and hasattr(cls, "crc_extra"):
        return int(cls.crc_extra) & 0xFF
    return None


def compute_mavlink2_mac(
    secret_key: bytes,
    frame_without_sig: bytes,
    link_id: int,
    timestamp_10us: int,
) -> bytes:
    """Compute the 48-bit (6-byte) truncated SHA-256 MAVLink 2 signature MAC.

    Per the MAVLink 2 specification:
        signature = SHA256(secret_key + header + payload + CRC + link_id + timestamp)[0:6]
    """
    if len(secret_key) != 32:
        raise ValueError("MAVLink 2 secret_key must be exactly 32 bytes")
    ts_bytes = int(timestamp_10us & 0xFFFFFFFFFFFF).to_bytes(6, "little", signed=False)
    h = hashlib.sha256()
    h.update(secret_key)
    h.update(frame_without_sig)
    h.update(bytes([link_id & 0xFF]))
    h.update(ts_bytes)
    return h.digest()[:6]


def sign_mavlink2_frame(
    raw_frame: bytes,
    secret_key: bytes,
    link_id: int = 0,
    timestamp_10us: int | None = None,
    crc_extra: int | None = None,
) -> bytes:
    """Sign a MAVLink v2 frame with a 13-byte trailer and recompute X.25 CRC over incompat_flags."""
    if len(secret_key) != 32:
        raise ValueError("MAVLink 2 secret_key must be exactly 32 bytes")
    if len(raw_frame) < MAVLINK_V2_HEADER_LEN + MAVLINK_CRC_LEN or raw_frame[0] != MAVLINK_V2_MAGIC:
        raise ValueError("raw_frame must be a valid MAVLink v2 frame starting with 0xFD")

    plen = raw_frame[1]
    body_crc_end = MAVLINK_V2_HEADER_LEN + plen + MAVLINK_CRC_LEN
    if len(raw_frame) < body_crc_end:
        raise ValueError("Truncated MAVLink v2 frame")

    buf = bytearray(raw_frame[:body_crc_end])
    buf[2] |= MAVLINK_IFLAG_SIGNED
    msgid = buf[7] | (buf[8] << 8) | (buf[9] << 16)

    extra = crc_extra if crc_extra is not None else _lookup_crc_extra(msgid)
    if extra is not None:
        crc_input = bytes(buf[1 : MAVLINK_V2_HEADER_LEN + plen]) + bytes([extra & 0xFF])
        crc = _x25_crc(crc_input)
        struct.pack_into("<H", buf, MAVLINK_V2_HEADER_LEN + plen, crc)

    if timestamp_10us is None:
        now_s = max(0.0, time.time() - MAVLINK_EPOCH_UNIX_S)
        timestamp_10us = int(now_s * 100_000)

    ts_val = int(timestamp_10us) & 0xFFFFFFFFFFFF
    ts_bytes = ts_val.to_bytes(6, "little", signed=False)
    frame_no_sig = bytes(buf)
    mac_6b = compute_mavlink2_mac(secret_key, frame_no_sig, link_id, ts_val)
    return frame_no_sig + bytes([link_id & 0xFF]) + ts_bytes + mac_6b


@dataclass(slots=True)
class SignatureCheckResult:
    """Result of verifying a MAVLink v2 frame's cryptographic signature and timestamp."""

    valid: bool
    signed: bool
    replayed: bool
    reason: str
    sysid: int = 0
    compid: int = 0
    msgid: int = 0
    link_id: int = 0
    timestamp_10us: int = 0


class MavlinkSignatureVerifier:
    """Stateful MAVLink v2 signature and strict monotonic timestamp verifier."""

    def __init__(
        self,
        secret_key: bytes,
        unsigned_allowed_msgids: frozenset[int] = frozenset({0, 109, 246, 247}),
    ) -> None:
        if len(secret_key) != 32:
            raise ValueError("MAVLink 2 secret_key must be exactly 32 bytes")
        self.secret_key = secret_key
        self.unsigned_allowed_msgids = unsigned_allowed_msgids
        self._last_timestamps: dict[tuple[int, int, int], int] = {}
        self._tx_timestamp_10us: int = int(max(1.0, time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000)
        self.valid_count: int = 0
        self.invalid_count: int = 0
        self.replay_count: int = 0

    def reset(self) -> None:
        self._last_timestamps.clear()
        self.valid_count = 0
        self.invalid_count = 0
        self.replay_count = 0

    def sign_frame(
        self,
        raw_frame: bytes,
        link_id: int = 0,
        timestamp_10us: int | None = None,
    ) -> bytes:
        """Sign an outgoing frame with guaranteed strictly monotonic 10us timestamps."""
        if timestamp_10us is None:
            now_10us = int(max(1.0, time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000)
            self._tx_timestamp_10us = max(self._tx_timestamp_10us + 1, now_10us)
            timestamp_10us = self._tx_timestamp_10us
        else:
            self._tx_timestamp_10us = max(self._tx_timestamp_10us, timestamp_10us)
        return sign_mavlink2_frame(
            raw_frame,
            self.secret_key,
            link_id=link_id,
            timestamp_10us=timestamp_10us,
        )

    def verify_frame(self, raw_frame: bytes) -> SignatureCheckResult:
        """Verify 13-byte MAVLink 2 signature trailer and enforce tau_frame > tau_last."""
        if len(raw_frame) < MAVLINK_V2_HEADER_LEN + MAVLINK_CRC_LEN or raw_frame[0] != MAVLINK_V2_MAGIC:
            self.invalid_count += 1
            return SignatureCheckResult(
                valid=False,
                signed=False,
                replayed=False,
                reason="malformed_header",
            )

        plen = raw_frame[1]
        incompat = raw_frame[2]
        sysid = raw_frame[5]
        compid = raw_frame[6]
        msgid = raw_frame[7] | (raw_frame[8] << 8) | (raw_frame[9] << 16)
        is_signed = bool(incompat & MAVLINK_IFLAG_SIGNED)

        if not is_signed:
            if msgid in self.unsigned_allowed_msgids:
                return SignatureCheckResult(
                    valid=True,
                    signed=False,
                    replayed=False,
                    reason="unsigned_allowed",
                    sysid=sysid,
                    compid=compid,
                    msgid=msgid,
                )
            self.invalid_count += 1
            return SignatureCheckResult(
                valid=False,
                signed=False,
                replayed=False,
                reason="unsigned_frame",
                sysid=sysid,
                compid=compid,
                msgid=msgid,
            )

        expected_total = MAVLINK_V2_HEADER_LEN + plen + MAVLINK_CRC_LEN + MAVLINK_SIGNATURE_LEN
        if len(raw_frame) < expected_total:
            self.invalid_count += 1
            return SignatureCheckResult(
                valid=False,
                signed=True,
                replayed=False,
                reason="truncated_signature",
                sysid=sysid,
                compid=compid,
                msgid=msgid,
            )

        body_crc_end = MAVLINK_V2_HEADER_LEN + plen + MAVLINK_CRC_LEN
        frame_no_sig = raw_frame[:body_crc_end]
        trailer = raw_frame[body_crc_end:expected_total]
        link_id = trailer[0]
        timestamp_10us = int.from_bytes(trailer[1:7], "little", signed=False)
        mac_6b = trailer[7:13]

        # 1. Constant-time cryptographic SHA-256_48 MAC check
        expected_mac = compute_mavlink2_mac(self.secret_key, frame_no_sig, link_id, timestamp_10us)
        if not hmac.compare_digest(mac_6b, expected_mac):
            self.invalid_count += 1
            return SignatureCheckResult(
                valid=False,
                signed=True,
                replayed=False,
                reason="mac_mismatch",
                sysid=sysid,
                compid=compid,
                msgid=msgid,
                link_id=link_id,
                timestamp_10us=timestamp_10us,
            )

        # 2. Strict timestamp monotonicity (anti-replay: tau_frame > tau_last)
        stream_key = (link_id, sysid, compid)
        last_ts = self._last_timestamps.get(stream_key)
        if last_ts is not None and timestamp_10us <= last_ts:
            self.invalid_count += 1
            self.replay_count += 1
            return SignatureCheckResult(
                valid=False,
                signed=True,
                replayed=True,
                reason="replay_timestamp_non_monotonic",
                sysid=sysid,
                compid=compid,
                msgid=msgid,
                link_id=link_id,
                timestamp_10us=timestamp_10us,
            )

        self._last_timestamps[stream_key] = timestamp_10us
        self.valid_count += 1
        return SignatureCheckResult(
            valid=True,
            signed=True,
            replayed=False,
            reason="ok",
            sysid=sysid,
            compid=compid,
            msgid=msgid,
            link_id=link_id,
            timestamp_10us=timestamp_10us,
        )
