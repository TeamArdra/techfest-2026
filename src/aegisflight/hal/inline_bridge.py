"""Bidirectional inline MAVLink bridge with fail-open safety watchdog."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from ..mitigation.sanitizer import FrameSanitizer


class InlineBridge:
    """Passes packets between GCS and FC with inline sanitization and fail-open watchdog."""

    def __init__(
        self,
        sanitizer: FrameSanitizer,
        *,
        watchdog_timeout_s: float = 0.150,  # 150 ms fail-open limit
    ) -> None:
        self.sanitizer = sanitizer
        self.watchdog_timeout_s = watchdog_timeout_s
        self.active_ips: bool = False
        self.fail_open_triggered: bool = False
        self.last_healthy_t: float = time.time()
        self.lock = threading.Lock()
        self.frames_forwarded: int = 0
        self.frames_dropped: int = 0

    def process_frame(
        self,
        frame_bytes: bytes,
        direction: str = "up",  # "up" (GCS -> FC) or "down" (FC -> GCS)
        send_fn: Callable[[bytes], Any] | None = None,
    ) -> bytes | None:
        """Process frame inline. If pipeline is stalled or fail-open triggered, passes unaltered."""
        with self.lock:
            self.last_healthy_t = time.time()

            # If fail-open was triggered or not in ACTIVE_IPS: pass through untouched
            if self.fail_open_triggered or not self.active_ips:
                self.frames_forwarded += 1
                if send_fn:
                    send_fn(frame_bytes)
                return frame_bytes

            # Run through FrameSanitizer
            try:
                sysid = 1
                compid = 1
                msgid = 0
                seq = 0
                if len(frame_bytes) >= 10 and frame_bytes[0] == 0xFD:
                    seq = frame_bytes[4]
                    sysid = frame_bytes[5]
                    compid = frame_bytes[6]
                    msgid = frame_bytes[7] | (frame_bytes[8] << 8) | (frame_bytes[9] << 16)

                sanitized = self.sanitizer.sanitize_frame(
                    frame_bytes,
                    direction=direction,
                    sysid=sysid,
                    compid=compid,
                    msgid=msgid,
                    seq=seq,
                )
                if sanitized is not None:
                    self.frames_forwarded += 1
                    if send_fn:
                        send_fn(sanitized)
                    return sanitized
                else:
                    self.frames_dropped += 1
                    return None
            except Exception:
                # On unexpected exception: trigger fail-open immediately to protect airframe link
                self.fail_open_triggered = True
                self.frames_forwarded += 1
                if send_fn:
                    send_fn(frame_bytes)
                return frame_bytes

    def check_watchdog(self) -> bool:
        """Called by watchdog thread. Returns True if link is healthy, False if fail-open tripped."""
        with self.lock:
            dt = time.time() - self.last_healthy_t
            if dt > self.watchdog_timeout_s and not self.fail_open_triggered:
                self.fail_open_triggered = True
            return not self.fail_open_triggered

    def reset_fail_open(self) -> None:
        with self.lock:
            self.fail_open_triggered = False
            self.last_healthy_t = time.time()
