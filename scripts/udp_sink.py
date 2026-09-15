#!/usr/bin/env python3
"""Tiny UDP packet counter used as a stand-in "backend server" in the netns
demo. Prints a running total every second to /tmp/proxy-lb-backendN.log so
run-demo.sh can prove packets are actually arriving DNAT'd, not just that
the LB's own counters moved."""
import socket
import sys
import time

addr = sys.argv[1]
port = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((addr, port))
sock.setblocking(False)

count = 0
last_print = time.monotonic()
while True:
    try:
        while True:
            sock.recvfrom(4096)
            count += 1
    except BlockingIOError:
        pass
    now = time.monotonic()
    if now - last_print >= 1.0:
        print(f"{addr}:{port} received {count} packets total", flush=True)
        last_print = now
    time.sleep(0.05)
