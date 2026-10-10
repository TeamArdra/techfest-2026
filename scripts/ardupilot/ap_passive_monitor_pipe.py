#!/usr/bin/env python3
"""STRICTLY receive-only MAVLink monitor client for the passive-monitor SITL experiment.

Runs inside the network namespace of ``ap_netns_run_passive.sh`` (python3 + pymavlink only). It connects
to the vehicle's SECOND serial port (SERIAL1, whose streams are set by persistent SR1_* parameters) with a
RAW socket and parses what arrives; it never calls ``send``/``sendall``/``write`` on that socket, so it
cannot transmit a heartbeat, a request, a command or anything else -- UNLESS the explicit ``--send-heartbeat``
variant is chosen, which sends a 1 Hz GCS HEARTBEAT and nothing else (counted in the events file; the report
then says "heartbeat-only", never "receive-only"). A separate GCS (``ap_gcs_pipe.py``, on SERIAL0) flies the
simulator; its traffic is not this script's business and never reaches stdout.

stdout : ``>H length`` + one raw MAVLink frame per frame received on SERIAL1 (``aegisflight.sources.frame_pipe`` format)
--tlog : the same frames as a tlog written inside the namespace (pipe-integrity cross-check)
--events: JSONL (start, first frame, per-message counts, end) including ``tx_calls`` which must be 0.
Environment tag: SITL. Never run against a physical flight controller.
"""

from __future__ import annotations

import argparse
import json
import signal
import socket
import struct
import sys
import time
from collections import Counter

from pymavlink.dialects.v20 import (
    all as mavlink2,  # ardupilotmega ids must CRC-verify here too, not parse as UNKNOWN_n
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--events", required=True)
    ap.add_argument("--tlog", required=True)
    ap.add_argument("--connect-timeout", type=float, default=30.0)
    ap.add_argument("--send-heartbeat", action="store_true",
                    help="VARIANT (not receive-only): transmit a 1 Hz GCS HEARTBEAT and NOTHING else, to test whether "
                         "a heartbeat alone unlocks the SR1_*-configured streams; every sent frame is counted")
    a = ap.parse_args()

    stop = False

    def _term(*_a: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    ev = open(a.events, "w", encoding="utf-8")  # noqa: SIM115 - closed at exit
    tl = open(a.tlog, "wb")  # noqa: SIM115
    out = sys.stdout.buffer

    def event(name: str, **kw: object) -> None:
        ev.write(json.dumps({"t_unix": round(time.time(), 6), "event": name, **kw}) + "\n")
        ev.flush()

    deadline = time.monotonic() + a.connect_timeout
    sock = None
    while sock is None and time.monotonic() < deadline and not stop:
        try:
            sock = socket.create_connection(("127.0.0.1", a.port), timeout=2.0)
        except OSError:
            time.sleep(0.3)
    if sock is None:
        event("connect_failed", port=a.port)
        return 4
    sock.settimeout(0.5)
    event("connected", port=a.port)
    parser = mavlink2.MAVLink(None)
    parser.robust_parsing = True
    frames = 0
    bad = 0
    counts: Counter[str] = Counter()
    first = None
    tx_frames = 0
    tx_bytes = 0
    next_hb = time.monotonic()
    hb_enc = mavlink2.MAVLink(None, srcSystem=255, srcComponent=190)
    try:
        while not stop:
            if a.send_heartbeat and time.monotonic() >= next_hb:  # the ONLY transmit path in this file
                hb = bytes(hb_enc.heartbeat_encode(mavlink2.MAV_TYPE_GCS, mavlink2.MAV_AUTOPILOT_INVALID,
                                                   0, 0, 0).pack(hb_enc))
                sock.sendall(hb)
                tx_frames += 1
                tx_bytes += len(hb)
                next_hb += 1.0
            try:
                data = sock.recv(4096)
            except TimeoutError:
                continue
            except OSError as exc:
                event("recv_error", error=repr(exc))
                break
            if not data:
                event("peer_closed")
                break
            now = time.time()
            for msg in parser.parse_buffer(data) or []:
                if msg.get_type() == "BAD_DATA":
                    bad += 1
                    continue
                fr = bytes(msg.get_msgbuf())
                out.write(struct.pack(">H", len(fr)) + fr)
                out.flush()
                tl.write(struct.pack(">Q", int(now * 1e6)) + fr)
                frames += 1
                counts[msg.get_type()] += 1
                if first is None:
                    first = now
                    event("first_frame", msg=msg.get_type())
    except BrokenPipeError:
        event("stdout_closed")
    finally:
        event("end", frames=frames, bad_data=bad, tx_frames=tx_frames, tx_bytes=tx_bytes,
              tx_message_types=(["HEARTBEAT"] if tx_frames else []), receive_only=(tx_frames == 0),
              counts=dict(counts))
        tl.close()
        ev.close()
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
