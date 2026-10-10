"""``FrameTransport`` decorator: tee the clean downlink, optionally rewrite it with a ``FrameHook``,
tee what the IDS then sees (Stage-2: ArduPilot SITL, and the in-path attack scenario).

::

    inner transport --(clean frames)--> [clean tlog] --> down_hook --> [observed tlog] --> IDS

* With no hook this is byte-identical, order-preserving pass-through (tested), plus two tlogs.
* A hook is the SAME ``FrameHook`` interface the UDP attack proxy uses (``aegisflight.proxy.hooks``):
  it sees one real frame (``FrameContext``, direction ``"down"``) and returns the frames to
  forward (same, modified, none, several). A hook that rewrites a frame must recompute its CRC.
  A hook that raises, or returns something that is not ``list[bytes]``, fails OPEN for the
  evidence (the original frame is forwarded) and is counted in ``hook_errors`` -- an attack that
  silently stops being applied must be visible in the manifest, so callers gate on that counter.
* Hooks run on the polling thread, once per frame. They get the receive stamp of the inner
  transport and must not read detector state or simulator ground truth (red/blue split).

Both tlogs use the repo's tlog framing (``>Q`` unix microseconds + one frame). The unix time is the
inner transport's monotonic stamp shifted by the wall/monotonic offset taken at construction.
"""

from __future__ import annotations

import struct
import time
from pathlib import Path
from typing import Any

from ..proxy.hooks import FrameContext, FrameHook


def frame_header(frame: bytes) -> tuple[int, int, int, int, bool]:
    """(sysid, compid, seq, msgid, signed) from the raw header of ONE complete frame."""
    if frame[0] == 0xFD:
        return frame[5], frame[6], frame[4], frame[7] | frame[8] << 8 | frame[9] << 16, bool(frame[2] & 1)
    return frame[3], frame[4], frame[2], frame[5], False


class TapTransport:
    def __init__(self, inner: Any, *, clean_tlog: str | Path | None = None,
                 observed_tlog: str | Path | None = None, down_hook: FrameHook | None = None) -> None:
        self.inner = inner
        self._hook = down_hook
        self._clean = open(clean_tlog, "wb") if clean_tlog else None  # noqa: SIM115 - closed in close()
        self._obs = open(observed_tlog, "wb") if observed_tlog else None  # noqa: SIM115
        self._off_us = int((time.time() - time.monotonic()) * 1e6)
        self.origin_ns: int | None = None  # stamp of the first clean frame
        self.last_ns: int | None = None  # stamp of the latest clean frame
        self.frames_in = 0
        self.frames_out = 0
        self.hook_errors = 0
        self.first_hook_error: str | None = None
        self._closed = False

    # delegate health counters LiveMavlinkSource reads via getattr
    def __getattr__(self, name: str) -> Any:
        if name == "inner":  # pragma: no cover - only before __init__ finished
            raise AttributeError(name)
        return getattr(self.inner, name)

    def start(self) -> None:
        start = getattr(self.inner, "start", None)
        if callable(start):
            start()

    def _write(self, fh: Any, stamp_ns: int, frame: bytes) -> None:
        if fh is not None:
            fh.write(struct.pack(">Q", self._off_us + stamp_ns // 1000) + frame)

    def poll(self) -> list[tuple[int, bytes]]:
        out: list[tuple[int, bytes]] = []
        for stamp_ns, frame in self.inner.poll():
            if self.origin_ns is None:
                self.origin_ns = stamp_ns
            self.last_ns = stamp_ns
            self.frames_in += 1
            self._write(self._clean, stamp_ns, frame)
            forwarded = [frame]
            if self._hook is not None:
                try:
                    sysid, compid, seq, msgid, signed = frame_header(frame)  # may raise on a torn/short frame
                    ctx = FrameContext("down", frame, stamp_ns, sysid, compid, seq, msgid, signed)
                    res = self._hook(ctx)
                    if not isinstance(res, list) or not all(isinstance(f, (bytes, bytearray)) for f in res):
                        raise TypeError(f"hook returned {type(res).__name__}, expected list[bytes]")
                    forwarded = [bytes(f) for f in res]
                except Exception as exc:  # noqa: BLE001 - fail open for the stream, loud in the counter
                    self.hook_errors += 1
                    self.first_hook_error = self.first_hook_error or repr(exc)
                    forwarded = [frame]
            for f in forwarded:
                self.frames_out += 1
                self._write(self._obs, stamp_ns, f)
                out.append((stamp_ns, f))
        return out

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.inner.close()
        finally:  # the evidence files are flushed and closed even if the inner transport fails to close
            for fh in (self._clean, self._obs):
                if fh is not None:
                    fh.close()

    @property
    def tap_stats(self) -> dict[str, object]:
        return {"frames_in": self.frames_in, "frames_out": self.frames_out,
                "hook_errors": self.hook_errors, "first_hook_error": self.first_hook_error}
