#!/usr/bin/env python3
"""Verify the XDP program's packet rewriting in complete isolation from the
rest of the network stack, using BPF_PROG_TEST_RUN (via `bpftool prog run`).

This is a genuinely useful eBPF technique worth knowing on its own: you can
feed a loaded BPF program a raw packet buffer and inspect exactly what it
produces, without a NIC, a socket, routing, conntrack, or any of the other
machinery that can obscure *whether the packet-rewriting logic itself is
correct*. It's how this project's data plane was validated during
development, before the network-namespace demo delivered end to end.

Usage:
    verify_datapath.py --prog-id ID --vip IP --vip-port PORT [--client-ip IP]
                        [--proto udp|tcp] [--expect-dst IP]
                        [--expect-action drop|pass|tx|redirect|forward]
                        [--flows N]

Find --prog-id with: bpftool net show   (look for veth-c's attached prog id)
Set BPFTOOL=/path/to/bpftool if the one on PATH is a kernel-version wrapper.
"""
import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile

# Distros where bpftool is a wrapper that dispatches on kernel version can end
# up without a matching binary; point BPFTOOL at a real one.
BPFTOOL = os.environ.get("BPFTOOL", "bpftool")


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_packet(client_ip: str, vip: str, vip_port: int, proto: str, sport: int = 51000) -> bytes:
    eth = bytes.fromhex("020202020202") + bytes.fromhex("010101010101") + struct.pack("!H", 0x0800)
    src_ip = socket.inet_aton(client_ip)
    dst_ip = socket.inet_aton(vip)
    payload = b"verify-datapath-probe"

    if proto == "udp":
        l4_len = 8 + len(payload)
        hdr_nocsum = struct.pack("!HHHH", sport, vip_port, l4_len, 0)
        pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 17, l4_len)
        c = csum(pseudo + hdr_nocsum + payload) or 0xFFFF
        l4 = struct.pack("!HHHH", sport, vip_port, l4_len, c) + payload
        ip_proto = 17
    else:
        l4_len = 20 + len(payload)
        hdr_nocsum = struct.pack("!HHIIBBHHH", sport, vip_port, 1, 0, 0x50, 0x02, 65535, 0, 0)
        pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, l4_len)
        c = csum(pseudo + hdr_nocsum + payload) or 0xFFFF
        l4 = struct.pack("!HHIIBBHHH", sport, vip_port, 1, 0, 0x50, 0x02, 65535, c, 0) + payload
        ip_proto = 6

    tot_len = 20 + l4_len
    ip_nocsum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot_len, 0xABCD, 0x4000, 64, ip_proto, 0, src_ip, dst_ip)
    ip_c = csum(ip_nocsum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot_len, 0xABCD, 0x4000, 64, ip_proto, ip_c, src_ip, dst_ip)
    return eth + ip_hdr + l4


XDP_RETVAL_NAMES = {0: "XDP_ABORTED", 1: "XDP_DROP", 2: "XDP_PASS", 3: "XDP_TX", 4: "XDP_REDIRECT"}
EXPECTED_RETVALS = {"drop": (1,), "pass": (2,), "tx": (3,), "redirect": (4,), "forward": (3, 4)}


def run_prog(prog_id: int, pkt: bytes):
    """Feeds one packet through the loaded program, returns (retval, out)."""
    with tempfile.NamedTemporaryFile() as fin, tempfile.NamedTemporaryFile() as fout:
        fin.write(pkt)
        fin.flush()
        result = subprocess.run(
            [BPFTOOL, "-j", "prog", "run", "id", str(prog_id),
             "data_in", fin.name, "data_out", fout.name, "repeat", "1"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"FAIL: bpftool prog run failed: {result.stderr.strip()}", file=sys.stderr)
            return None, None
        return json.loads(result.stdout).get("retval"), fout.read()


def dst_of(out: bytes) -> str:
    return socket.inet_ntoa(out[30:34])


def check_flows(args) -> int:
    """Probes many source ports: every flow must land somewhere, the same flow
    must always land on the same backend, and the spread tells you whether the
    maglev table is actually distributing."""
    spread: dict[str, int] = {}
    for i in range(args.flows):
        sport = 20000 + i
        retval, out = run_prog(args.prog_id, build_packet(args.client_ip, args.vip, args.vip_port, args.proto, sport))
        if retval is None:
            return 1
        if retval not in EXPECTED_RETVALS[args.expect_action]:
            print(f"FAIL: sport {sport} returned {XDP_RETVAL_NAMES.get(retval, retval)}")
            return 1
        dst = dst_of(out)
        spread[dst] = spread.get(dst, 0) + 1

        retval2, out2 = run_prog(args.prog_id, build_packet(args.client_ip, args.vip, args.vip_port, args.proto, sport))
        if retval2 is None:
            return 1
        if dst_of(out2) != dst:
            print(f"FAIL: sport {sport} hashed to {dst} then {dst_of(out2)} -- not stable per flow")
            return 1

    print(f"{args.flows} flows -> {len(spread)} backend(s)")
    for dst, n in sorted(spread.items()):
        print(f"  {dst:<16} {n:>5} flows ({100.0 * n / args.flows:.1f}%)")
    print("PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prog-id", type=int, required=True)
    ap.add_argument("--client-ip", default="10.10.0.2")
    ap.add_argument("--vip", required=True)
    ap.add_argument("--vip-port", type=int, required=True)
    ap.add_argument("--proto", choices=["udp", "tcp"], default="udp")
    ap.add_argument("--expect-dst", help="fail if the rewritten dst IP isn't this")
    ap.add_argument("--expect-action", choices=list(EXPECTED_RETVALS), default="forward",
                    help="XDP action the program should return (default: tx or redirect)")
    ap.add_argument("--flows", type=int, default=1, metavar="N",
                    help="probe N distinct source ports and report the backend spread")
    args = ap.parse_args()

    if args.flows > 1:
        return check_flows(args)

    pkt = build_packet(args.client_ip, args.vip, args.vip_port, args.proto)
    retval, out = run_prog(args.prog_id, pkt)
    if retval is None:
        return 1

    print(f"input:  {len(pkt)} bytes, {args.client_ip} -> {args.vip}:{args.vip_port}/{args.proto}")
    print(f"return: {retval} ({XDP_RETVAL_NAMES.get(retval, 'unknown')})")

    ok = True
    expected = EXPECTED_RETVALS[args.expect_action]
    if retval not in expected:
        names = " or ".join(XDP_RETVAL_NAMES[r] for r in expected)
        print(f"FAIL: expected {names}, got {XDP_RETVAL_NAMES.get(retval, retval)}")
        ok = False

    # A dropped or passed packet is not rewritten, so there is nothing to check.
    if args.expect_action in ("drop", "pass"):
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1

    if len(out) < 34:
        print("FAIL: output packet too short to parse")
        return 1

    eth_dst, eth_src = out[0:6].hex(":"), out[6:12].hex(":")
    ip_hdr = out[14:34]
    ihl = (ip_hdr[0] & 0x0F) * 4
    ip_ok = csum(ip_hdr[:ihl]) == 0
    dst_ip = socket.inet_ntoa(ip_hdr[16:20])
    proto_num = ip_hdr[9]

    print(f"output: dst_mac={eth_dst} src_mac={eth_src} dst_ip={dst_ip} ip_csum_valid={ip_ok}")
    if not ip_ok:
        print("FAIL: rewritten IP header checksum does not validate")
        ok = False

    l4 = out[14 + ihl:]
    if proto_num in (6, 17) and len(l4) >= 8:
        pseudo = ip_hdr[12:16] + ip_hdr[16:20] + struct.pack("!BBH", 0, proto_num, len(l4))
        l4_ok = csum(pseudo + l4) == 0
        print(f"output: l4_csum_valid={l4_ok}")
        if not l4_ok:
            print("FAIL: rewritten L4 checksum does not validate")
            ok = False

    if args.expect_dst and dst_ip != args.expect_dst:
        print(f"FAIL: expected rewritten dst {args.expect_dst}, got {dst_ip}")
        ok = False

    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
