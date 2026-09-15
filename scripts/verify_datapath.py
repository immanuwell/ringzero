#!/usr/bin/env python3
"""Verify the XDP program's packet rewriting in complete isolation from the
rest of the network stack, using BPF_PROG_TEST_RUN (via `bpftool prog run`).

This is a genuinely useful eBPF technique worth knowing on its own: you can
feed a loaded BPF program a raw packet buffer and inspect exactly what it
produces, without a NIC, a socket, routing, conntrack, or any of the other
machinery that can obscure *whether the packet-rewriting logic itself is
correct*. It's how this project's data plane was validated during
development when the local network-namespace demo's end-to-end delivery hit
unrelated host-networking quirks (see the README).

Usage:
    verify_datapath.py --prog-id ID --client-ip IP --vip IP --vip-port PORT
                        [--proto udp|tcp] [--expect-dst IP]

Find --prog-id with: bpftool net show   (look for veth-c's attached prog id)
"""
import argparse
import json
import socket
import struct
import subprocess
import sys
import tempfile


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_packet(client_ip: str, vip: str, vip_port: int, proto: str) -> bytes:
    eth = bytes.fromhex("020202020202") + bytes.fromhex("010101010101") + struct.pack("!H", 0x0800)
    src_ip = socket.inet_aton(client_ip)
    dst_ip = socket.inet_aton(vip)
    payload = b"verify-datapath-probe"

    if proto == "udp":
        l4_len = 8 + len(payload)
        hdr_nocsum = struct.pack("!HHHH", 51000, vip_port, l4_len, 0)
        pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 17, l4_len)
        c = csum(pseudo + hdr_nocsum + payload) or 0xFFFF
        l4 = struct.pack("!HHHH", 51000, vip_port, l4_len, c) + payload
        ip_proto = 17
    else:
        l4_len = 20 + len(payload)
        hdr_nocsum = struct.pack("!HHIIBBHHH", 51000, vip_port, 1, 0, 0x50, 0x02, 65535, 0, 0)
        pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, l4_len)
        c = csum(pseudo + hdr_nocsum + payload) or 0xFFFF
        l4 = struct.pack("!HHIIBBHHH", 51000, vip_port, 1, 0, 0x50, 0x02, 65535, c, 0) + payload
        ip_proto = 6

    tot_len = 20 + l4_len
    ip_nocsum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot_len, 0xABCD, 0x4000, 64, ip_proto, 0, src_ip, dst_ip)
    ip_c = csum(ip_nocsum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot_len, 0xABCD, 0x4000, 64, ip_proto, ip_c, src_ip, dst_ip)
    return eth + ip_hdr + l4


XDP_RETVAL_NAMES = {0: "XDP_ABORTED", 1: "XDP_DROP", 2: "XDP_PASS", 3: "XDP_TX", 4: "XDP_REDIRECT"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prog-id", type=int, required=True)
    ap.add_argument("--client-ip", default="10.10.0.2")
    ap.add_argument("--vip", required=True)
    ap.add_argument("--vip-port", type=int, required=True)
    ap.add_argument("--proto", choices=["udp", "tcp"], default="udp")
    ap.add_argument("--expect-dst", help="fail if the rewritten dst IP isn't this")
    args = ap.parse_args()

    pkt = build_packet(args.client_ip, args.vip, args.vip_port, args.proto)

    with tempfile.NamedTemporaryFile() as fin, tempfile.NamedTemporaryFile() as fout:
        fin.write(pkt)
        fin.flush()
        result = subprocess.run(
            ["bpftool", "-j", "prog", "run", "id", str(args.prog_id),
             "data_in", fin.name, "data_out", fout.name, "repeat", "1"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"FAIL: bpftool prog run failed: {result.stderr.strip()}", file=sys.stderr)
            return 1
        info = json.loads(result.stdout)
        retval = info.get("retval")
        out = fout.read()

    print(f"input:  {len(pkt)} bytes, {args.client_ip} -> {args.vip}:{args.vip_port}/{args.proto}")
    print(f"return: {retval} ({XDP_RETVAL_NAMES.get(retval, 'unknown')})")

    ok = True
    if retval not in (3, 4):
        print(f"FAIL: expected XDP_TX or XDP_REDIRECT, got {retval}")
        ok = False

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
