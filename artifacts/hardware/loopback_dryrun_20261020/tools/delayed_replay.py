"""SCRATCH ONLY. Loopback TCP replay of a repo-format tlog at original pace, starting DELAY s after the
monitor connects (repo virtual_serial_replay.py starts immediately and has no delay option).
Binds 127.0.0.1 only. Sends nothing but the recorded frames. Logs wall-clock of accept / first / last send.
Usage: delayed_replay.py TLOG PORT DELAY_S READY_FILE LOG_JSON [HOLD_S]
DELAY_S < 0 with an empty tlog arg "-" => silent listener (accept, send nothing, hold HOLD_S).
"""
from __future__ import annotations

import json
import socket
import struct
import sys
import time
from pathlib import Path


def read_tlog(path: Path) -> list[tuple[float, bytes]]:  # same framing logic as scripts/hardware/virtual_serial_replay.py
    data, out, i = path.read_bytes(), [], 0
    while i + 10 <= len(data):
        ts = struct.unpack(">Q", data[i:i + 8])[0] / 1e6
        n = (12 + data[i + 9] + (13 if data[i + 10] & 1 else 0)) if data[i + 8] == 0xFD else 8 + data[i + 9]
        out.append((ts, data[i + 8:i + 8 + n]))
        i += 8 + n
    return out


def main() -> int:
    tlog, port, delay, ready, logp = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4], sys.argv[5]
    hold = float(sys.argv[6]) if len(sys.argv) > 6 else 0.0
    frames = [] if tlog == "-" else read_tlog(Path(tlog))
    if frames:
        t0 = frames[0][0]
        frames = [(t - t0, f) for t, f in frames]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(120.0)
    Path(ready).write_text(str(port), encoding="utf-8")
    conn, _ = srv.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    log = {"accept_unix": time.time(), "delay_s": delay, "frames_total": len(frames)}
    if not frames:
        time.sleep(hold)
        log["sent"] = 0
    else:
        start = time.monotonic() + delay
        sent = 0
        for t, f in frames:
            wait = start + t - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            try:
                conn.sendall(f)
            except OSError as exc:
                log["send_error"] = repr(exc)
                break
            if sent == 0:
                log["first_send_unix"] = time.time()
            sent += 1
            log["last_send_unix"] = time.time()
        log["sent"] = sent
        time.sleep(hold)
    conn.close()
    srv.close()
    Path(logp).write_text(json.dumps(log, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
