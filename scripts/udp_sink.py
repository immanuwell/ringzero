#!/usr/bin/env python3
"""Tiny UDP packet counter used as a stand-in "backend server" in the netns
demo. Prints a running total every second to /tmp/ringzero-backendN.log so
setup-netns.sh can prove packets are actually arriving DNAT'd, not just that
the LB's own counters moved."""
import socket
import sys
import time

addr = sys.argv[1]
port = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# A flood fills the default receive buffer in milliseconds, and drops there
# look exactly like the load balancer not forwarding. SO_RCVBUF is clamped to
# net.core.rmem_max; SO_RCVBUFFORCE is not, and this runs as root.
SO_RCVBUFFORCE = 33
try:
    sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 16 << 20)
except OSError:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
sock.bind((addr, port))
# Blocking with a timeout: a non-blocking drain plus a sleep loses everything
# that arrives during the sleep, which at these rates is most of it.
sock.settimeout(1.0)

count = 0
last_print = time.monotonic()
while True:
    try:
        sock.recv(4096)
        count += 1
    except TimeoutError:
        pass
    now = time.monotonic()
    if now - last_print >= 1.0:
        print(f"{addr}:{port} received {count} packets total", flush=True)
        last_print = now
