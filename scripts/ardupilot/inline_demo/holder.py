import socket
import time

s = socket.create_connection(("127.0.0.1", 5760))
while True:
    s.recv(65536) or time.sleep(1)
