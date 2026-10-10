"""Loopback "virtual serial device": plays a recorded tlog as a byte stream at its original pace.

    .venv/Scripts/python.exe scripts/hardware/virtual_serial_replay.py data/ardupilot/raw/ap_benign_six_001.clean.tlog \
        --port 18760 [--speed 1.0] [--drop-at 40 --drop-for 8]

A monitor then connects with ``--port socket://127.0.0.1:18760 --allow-url`` (``SerialMavlinkTransport``'s only
allowed URL scheme: a raw TCP client that sends nothing on connect). This is a REPLAY over a virtual port:
it exercises the real serial transport/framer/pipeline path on real ArduPilot bytes, but it is NOT a
serial device -- no baud rate, no driver, no USB, no UART. Nothing the monitor writes is read.

Binds 127.0.0.1 only. ``--drop-at S --drop-for D``: at stream time S the client connection is closed AND the
listening socket is closed for D seconds (connection refused, like an unplugged cable), then the device
"reappears". The stream clock keeps running during the gap and frames scheduled before the monitor
reconnects are skipped, exactly as the frames of a real unplug are lost. Prints ``LISTENING <port>`` once
ready; ``--ready-file`` also writes the port number. The stream clock starts when the monitor first connects.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from pathlib import Path


def read_tlog(path: Path) -> list[tuple[float, bytes]]:
    data, out, i = path.read_bytes(), [], 0
    while i + 10 <= len(data):
        ts = struct.unpack(">Q", data[i:i + 8])[0] / 1e6
        n = (12 + data[i + 9] + (13 if data[i + 10] & 1 else 0)) if data[i + 8] == 0xFD else 8 + data[i + 9]
        out.append((ts, data[i + 8:i + 8 + n]))
        i += 8 + n
    return out


def listen(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    s.settimeout(120.0)
    return s


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tlog")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--speed", type=float, default=1.0)
    ap.add_argument("--start-s", type=float, default=0.0, help="skip this much of the capture first")
    ap.add_argument("--drop-at", type=float, default=None)
    ap.add_argument("--drop-for", type=float, default=0.0)
    ap.add_argument("--ready-file")
    a = ap.parse_args(argv)
    if a.speed <= 0:
        print("--speed must be > 0", file=sys.stderr)
        return 2
    frames = read_tlog(Path(a.tlog))
    if not frames:
        print("empty tlog", file=sys.stderr)
        return 2
    t0 = frames[0][0] + a.start_s
    frames = [(t - t0, f) for t, f in frames if t >= t0]
    srv = listen(a.port)
    port = srv.getsockname()[1]
    if a.ready_file:
        Path(a.ready_file).write_text(str(port), encoding="utf-8")
    print(f"LISTENING {port}", flush=True)
    conn, _ = srv.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    start = time.monotonic()  # stream clock: runs on through any gap
    sent = skipped = 0
    dropped = False
    resume_t = 0.0
    for t, f in frames:
        if t < resume_t:  # scheduled while the "cable was out"
            skipped += 1
            continue
        wait = start + t / a.speed - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        if a.drop_at is not None and not dropped and (time.monotonic() - start) * a.speed >= a.drop_at:
            dropped = True
            print(f"DROP at stream t={(time.monotonic() - start) * a.speed:.1f}s for {a.drop_for}s", flush=True)
            conn.close()
            srv.close()
            time.sleep(a.drop_for)
            srv = listen(port)
            print("REAPPEAR", flush=True)
            conn, _ = srv.accept()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            resume_t = (time.monotonic() - start) * a.speed
            print(f"RECONNECTED at stream t={resume_t:.1f}s", flush=True)
            skipped += 1
            continue
        try:
            conn.sendall(f)
            sent += 1
        except OSError:
            skipped += 1
    time.sleep(0.5)
    conn.close()
    srv.close()
    print(f"DONE sent={sent} skipped={skipped}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
