"""Loopback 'radio' hub for the SITL test.

  bridge (client) --5800--> hub --5801--> GCS clients (read/write: the pilot script, an attacker script)
                                  --5802--> observers (read-only copy of the downlink: the dashboard)
Everything binds to 127.0.0.1 only.
"""
import selectors
import socket

sel = selectors.DefaultSelector()
bridge = None
gcs, obs = [], []


def listen(port, tag):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ, ("listen", tag))


def drop(sock):
    global bridge
    try:
        sel.unregister(sock)
    except Exception:
        pass
    sock.close()
    for lst in (gcs, obs):
        if sock in lst:
            lst.remove(sock)
    if sock is bridge:
        bridge = None


listen(5800, "bridge")
listen(5801, "gcs")
listen(5802, "obs")
print("hub up", flush=True)
while True:
    for key, _ in sel.select(timeout=1):
        kind, tag = key.data
        sock = key.fileobj
        if kind == "listen":
            c, _a = sock.accept()
            c.setblocking(False)
            sel.register(c, selectors.EVENT_READ, ("conn", tag))
            if tag == "bridge":
                bridge = c
            elif tag == "gcs":
                gcs.append(c)
            else:
                obs.append(c)
            print("accepted", tag, flush=True)
            continue
        try:
            data = sock.recv(65536)
        except OSError:
            data = b""
        if not data:
            drop(sock)
            continue
        if tag == "bridge":
            for c in list(gcs) + list(obs):
                try:
                    c.sendall(data)
                except OSError:
                    drop(c)
        elif tag == "gcs" and bridge is not None:
            try:
                bridge.sendall(data)
            except OSError:
                drop(bridge)
        # observers are read-only: anything they send is discarded
