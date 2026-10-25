"""Inline FrameHook for MavlinkRelay and live stream sanitization."""

from __future__ import annotations

import struct

from pymavlink.dialects.v20 import common as mav2

from ..proxy.hooks import FrameContext
from .actuator import x25_crc

GLOBAL_POSITION_INT_ID = 33
_V2_MAGIC = 0xFD
CRITICAL_MSGIDS = frozenset({0, 30, 33, 76})  # HEARTBEAT, ATTITUDE, GLOBAL_POSITION_INT, COMMAND_LONG


class FrameSanitizer:
    """Sanitizes incoming/outgoing MAVLink frames inline with zero allocation on the fast path."""

    def __init__(self) -> None:
        self.active: bool = False
        self.quarantined_sysids: set[int] = set()
        self.sanitize_gps: bool = False
        self.sanitize_alt: bool = False
        self.lat_offset_deg: float = 0.0
        self.lon_offset_deg: float = 0.0
        self.alt_bias_m: float = 0.0

        # Token-bucket rate limiting
        self.rate_limit_active: bool = False
        self.max_critical_fps: int = 120
        self._window_sec: int = -1
        self._critical_count: int = 0

        # Counters
        self.frames_dropped: int = 0
        self.frames_sanitized: int = 0

        # Cached encoder / decoder
        self._decoder = mav2.MAVLink(None)
        self._decoder.robust_parsing = True
        self._encoder = mav2.MAVLink(None)
        self._encoder.robust_parsing = True

    def configure(
        self,
        *,
        active: bool,
        quarantined_sysids: set[int] | frozenset[int] | None = None,
        sanitize_gps: bool = False,
        sanitize_alt: bool = False,
        lat_offset_deg: float = 0.0,
        lon_offset_deg: float = 0.0,
        alt_bias_m: float = 0.0,
        rate_limit_active: bool = False,
    ) -> None:
        self.active = active
        self.quarantined_sysids = set(quarantined_sysids or ())
        self.sanitize_gps = sanitize_gps
        self.sanitize_alt = sanitize_alt
        self.lat_offset_deg = lat_offset_deg
        self.lon_offset_deg = lon_offset_deg
        self.alt_bias_m = alt_bias_m
        self.rate_limit_active = rate_limit_active

    def __call__(self, ctx: FrameContext) -> list[bytes]:
        """Conforms to FrameHook (Callable[[FrameContext], list[bytes]])."""
        if not self.active:
            return [ctx.raw]

        # 1. Drop both uplink and downlink frames from quarantined sysids
        if ctx.sysid in self.quarantined_sysids:
            self.frames_dropped += 1
            return []

        # 2. Token-bucket QoS shedding during DoS flood
        if self.rate_limit_active:
            if ctx.msgid not in CRITICAL_MSGIDS:
                self.frames_dropped += 1
                return []
            sec_bucket = int(ctx.recv_ns // 1_000_000_000) if ctx.recv_ns > 0 else -1
            if sec_bucket != -1:
                if sec_bucket != self._window_sec:
                    self._window_sec = sec_bucket
                    self._critical_count = 0
                self._critical_count += 1
                if self._critical_count > self.max_critical_fps:
                    self.frames_dropped += 1
                    return []

        # 3. Downlink position and altitude sanitization (GLOBAL_POSITION_INT, msgid 33)
        if ctx.direction == "down" and ctx.msgid == GLOBAL_POSITION_INT_ID:
            if not (self.sanitize_gps or self.sanitize_alt):
                return [ctx.raw]

            if ctx.signed or not ctx.raw or ctx.raw[0] != _V2_MAGIC or len(ctx.raw) < 40:
                return [ctx.raw]

            try:
                buf = bytearray(ctx.raw)
                # lat @ 14..18, lon @ 18..22, alt @ 22..26, relative_alt @ 26..30
                if self.sanitize_gps and (self.lat_offset_deg != 0.0 or self.lon_offset_deg != 0.0):
                    lat_val = struct.unpack_from("<i", buf, 14)[0]
                    lon_val = struct.unpack_from("<i", buf, 18)[0]
                    lat_val -= int(round(self.lat_offset_deg * 1e7))
                    lon_val -= int(round(self.lon_offset_deg * 1e7))
                    struct.pack_into("<i", buf, 14, lat_val)
                    struct.pack_into("<i", buf, 18, lon_val)

                if self.sanitize_alt and self.alt_bias_m != 0.0:
                    bias_mm = int(round(self.alt_bias_m * 1000.0))
                    alt_val = struct.unpack_from("<i", buf, 22)[0]
                    rel_alt_val = struct.unpack_from("<i", buf, 26)[0]
                    struct.pack_into("<i", buf, 22, alt_val - bias_mm)
                    struct.pack_into("<i", buf, 26, rel_alt_val - bias_mm)

                payload_len = buf[1]
                header_len = 10
                crc = x25_crc(buf[1:header_len + payload_len] + bytes([104]))
                struct.pack_into("<H", buf, header_len + payload_len, crc)
                self.frames_sanitized += 1
                return [bytes(buf)]
            except Exception:
                return [ctx.raw]

        return [ctx.raw]

    def sanitize_frame(
        self,
        raw: bytes,
        direction: str = "down",
        sysid: int = 1,
        compid: int = 1,
        msgid: int = 33,
        seq: int = 0,
        signed: bool = False,
    ) -> bytes | None:
        """Convenience single-frame sanitizer."""
        ctx = FrameContext(
            direction=direction,  # type: ignore
            raw=raw,
            recv_ns=0,
            sysid=sysid,
            compid=compid,
            seq=seq,
            msgid=msgid,
            signed=signed,
        )
        res = self(ctx)
        return res[0] if res else None
