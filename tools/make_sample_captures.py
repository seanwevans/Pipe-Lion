#!/usr/bin/env python3
"""Generate the sample captures served by the web UI.

The samples exist so the app has something to open on first visit, and so each
decoder in `core` (Ethernet, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, DNS, TLS) has a
packet that exercises it. They are generated rather than captured so they carry
no real traffic, stay tiny, and can be regenerated when a decoder changes.

Usage: python3 tools/make_sample_captures.py [output_dir]
Default output_dir is docs/public/samples.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58


# --- checksums ---------------------------------------------------------------


def ones_complement(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_pseudo_header(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return src + dst + struct.pack("!BBH", 0, proto, length)


def ipv6_pseudo_header(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return src + dst + struct.pack("!IBBBB", length, 0, 0, 0, proto)


# --- address helpers ---------------------------------------------------------


def mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def ipv4(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def ipv6(text: str) -> bytes:
    head, _, tail = text.partition("::")
    head_parts = [p for p in head.split(":") if p]
    tail_parts = [p for p in tail.split(":") if p]
    fill = 8 - len(head_parts) - len(tail_parts)
    groups = head_parts + ["0"] * fill + tail_parts
    return b"".join(int(g, 16).to_bytes(2, "big") for g in groups)


# --- layer builders ----------------------------------------------------------


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def ip4(src: bytes, dst: bytes, proto: int, payload: bytes, ident: int = 0) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, ident, 0x4000, 64, proto, 0, src, dst
    )
    checksum = ones_complement(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def ip6(src: bytes, dst: bytes, next_header: int, payload: bytes) -> bytes:
    header = struct.pack("!IHBB16s16s", 0x60000000, len(payload), next_header, 64, src, dst)
    return header + payload


def udp(src_port: int, dst_port: int, payload: bytes, pseudo: bytes | None = None) -> bytes:
    length = 8 + len(payload)
    datagram = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    if pseudo is not None:
        checksum = ones_complement(pseudo + datagram) or 0xFFFF
        datagram = datagram[:6] + struct.pack("!H", checksum) + datagram[8:]
    return datagram


def tcp(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    pseudo: bytes | None = None,
) -> bytes:
    segment = struct.pack(
        "!HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags, 64240, 0, 0
    ) + payload
    if pseudo is not None:
        checksum = ones_complement(pseudo + segment)
        segment = segment[:16] + struct.pack("!H", checksum) + segment[18:]
    return segment


def icmp_echo(kind: int, ident: int, seq: int, payload: bytes, pseudo: bytes | None = None) -> bytes:
    message = struct.pack("!BBHHH", kind, 0, 0, ident, seq) + payload
    base = message if pseudo is None else pseudo + message
    checksum = ones_complement(base)
    return message[:2] + struct.pack("!H", checksum) + message[4:]


# --- application payloads ----------------------------------------------------


def dns_name(name: str) -> bytes:
    out = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".") if label
    )
    return out + b"\x00"


def dns_query(ident: int, name: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    return header + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(ident: int, name: str, address: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0)
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    # 0xC00C is a compression pointer back to the question's name.
    answer = struct.pack("!HHHIH", 0xC00C, qtype, 1, 300, 4) + ipv4(address)
    return header + question + answer


def tls_client_hello(server_name: str, alpn: list[str]) -> bytes:
    sni_entry = struct.pack("!BH", 0, len(server_name)) + server_name.encode("ascii")
    sni_ext = struct.pack("!HHH", 0x0000, len(sni_entry) + 2, len(sni_entry)) + sni_entry

    alpn_list = b"".join(bytes([len(p)]) + p.encode("ascii") for p in alpn)
    alpn_ext = struct.pack("!HHH", 0x0010, len(alpn_list) + 2, len(alpn_list)) + alpn_list

    versions = struct.pack("!HH", 0x0304, 0x0303)
    versions_ext = struct.pack("!HHB", 0x002B, len(versions) + 1, len(versions)) + versions

    extensions = sni_ext + alpn_ext + versions_ext
    body = (
        struct.pack("!H", 0x0303)
        + bytes(range(32))                     # client random
        + b"\x00"                              # empty session id
        + struct.pack("!H", 4)                 # cipher suites
        + struct.pack("!HH", 0x1301, 0x1302)
        + b"\x01\x00"                          # one compression method: null
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = struct.pack("!BBH", 1, 0, len(body)) + body
    return struct.pack("!BBBH", 22, 3, 1, len(handshake)) + handshake


# --- container writers -------------------------------------------------------


def write_pcap(path: Path, packets: list[tuple[int, int, bytes]]) -> None:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET))
    for sec, usec, data in packets:
        out += struct.pack("<IIII", sec, usec, len(data), len(data))
        out += data
    path.write_bytes(bytes(out))


def _block(block_type: int, body: bytes) -> bytes:
    padding = (-len(body)) % 4
    total = 12 + len(body) + padding
    return struct.pack("<II", block_type, total) + body + b"\x00" * padding + struct.pack("<I", total)


def write_pcapng(path: Path, packets: list[tuple[int, int, bytes]]) -> None:
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _block(0x00000001, struct.pack("<HHI", LINKTYPE_ETHERNET, 0, 262144))
    out = bytearray(shb + idb)
    for sec, usec, data in packets:
        timestamp = sec * 1_000_000 + usec
        padding = (-len(data)) % 4
        body = struct.pack(
            "<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(data), len(data)
        ) + data + b"\x00" * padding
        out += _block(0x00000006, body)
    path.write_bytes(bytes(out))


# --- the samples themselves --------------------------------------------------

CLIENT_MAC = mac("02:00:00:00:00:01")
SERVER_MAC = mac("02:00:00:00:00:02")
CLIENT_IP = ipv4("192.0.2.10")
SERVER_IP = ipv4("198.51.100.20")
RESOLVER_IP = ipv4("192.0.2.53")
CLIENT_IP6 = ipv6("2001:db8::10")
SERVER_IP6 = ipv6("2001:db8::20")


def to_client(payload: bytes, ethertype: int = ETHERTYPE_IPV4) -> bytes:
    return ethernet(CLIENT_MAC, SERVER_MAC, ethertype, payload)


def to_server(payload: bytes, ethertype: int = ETHERTYPE_IPV4) -> bytes:
    return ethernet(SERVER_MAC, CLIENT_MAC, ethertype, payload)


def dns_packets() -> list[tuple[int, int, bytes]]:
    query = dns_query(0x1A2B, "example.com")
    reply = dns_response(0x1A2B, "example.com", "198.51.100.20")
    mdns = dns_query(0x0000, "_printer._tcp.local", qtype=12)
    return [
        (1, 0, to_server(ip4(CLIENT_IP, RESOLVER_IP, PROTO_UDP, udp(51234, 53, query), 1))),
        (1, 12000, to_client(ip4(RESOLVER_IP, CLIENT_IP, PROTO_UDP, udp(53, 51234, reply), 2))),
        (1, 30000, to_server(ip4(CLIENT_IP, ipv4("224.0.0.251"), PROTO_UDP, udp(5353, 5353, mdns), 3))),
    ]


def tcp_packets() -> list[tuple[int, int, bytes]]:
    def seg(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
        pseudo = ipv4_pseudo_header(src_ip, dst_ip, PROTO_TCP, 20 + len(payload))
        return ip4(src_ip, dst_ip, PROTO_TCP, tcp(sport, dport, seq, ack, flags, payload, pseudo))

    request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    return [
        (2, 0, to_server(seg(CLIENT_IP, SERVER_IP, 49152, 80, 1000, 0, 0x02))),
        (2, 8000, to_client(seg(SERVER_IP, CLIENT_IP, 80, 49152, 5000, 1001, 0x12))),
        (2, 8500, to_server(seg(CLIENT_IP, SERVER_IP, 49152, 80, 1001, 5001, 0x10))),
        (2, 9000, to_server(seg(CLIENT_IP, SERVER_IP, 49152, 80, 1001, 5001, 0x18, request))),
        (2, 20000, to_client(seg(SERVER_IP, CLIENT_IP, 80, 49152, 5001, 1001 + len(request), 0x18, response))),
        (2, 21000, to_server(seg(CLIENT_IP, SERVER_IP, 49152, 80, 1001 + len(request), 5001 + len(response), 0x11))),
    ]


def tls_packets() -> list[tuple[int, int, bytes]]:
    def seg(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
        pseudo = ipv4_pseudo_header(src_ip, dst_ip, PROTO_TCP, 20 + len(payload))
        return ip4(src_ip, dst_ip, PROTO_TCP, tcp(sport, dport, seq, ack, flags, payload, pseudo))

    hello = tls_client_hello("example.com", ["h2", "http/1.1"])
    return [
        (3, 0, to_server(seg(CLIENT_IP, SERVER_IP, 49234, 443, 7000, 0, 0x02))),
        (3, 9000, to_client(seg(SERVER_IP, CLIENT_IP, 443, 49234, 9000, 7001, 0x12))),
        (3, 9500, to_server(seg(CLIENT_IP, SERVER_IP, 49234, 443, 7001, 9001, 0x10))),
        (3, 10000, to_server(seg(CLIENT_IP, SERVER_IP, 49234, 443, 7001, 9001, 0x18, hello))),
    ]


def icmp_packets() -> list[tuple[int, int, bytes]]:
    payload = bytes(range(32))
    v6_request = icmp_echo(
        128, 0x3344, 1, payload,
        ipv6_pseudo_header(CLIENT_IP6, SERVER_IP6, PROTO_ICMPV6, 8 + len(payload)),
    )
    v6_reply = icmp_echo(
        129, 0x3344, 1, payload,
        ipv6_pseudo_header(SERVER_IP6, CLIENT_IP6, PROTO_ICMPV6, 8 + len(payload)),
    )
    return [
        (4, 0, to_server(ip4(CLIENT_IP, SERVER_IP, PROTO_ICMP, icmp_echo(8, 0x1234, 1, payload)))),
        (4, 15000, to_client(ip4(SERVER_IP, CLIENT_IP, PROTO_ICMP, icmp_echo(0, 0x1234, 1, payload)))),
        (4, 30000, to_server(ip6(CLIENT_IP6, SERVER_IP6, PROTO_ICMPV6, v6_request), ETHERTYPE_IPV6)),
        (4, 45000, to_client(ip6(SERVER_IP6, CLIENT_IP6, PROTO_ICMPV6, v6_reply), ETHERTYPE_IPV6)),
    ]


def main() -> None:
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/public/samples")
    out_dir.mkdir(parents=True, exist_ok=True)

    write_pcap(out_dir / "dns-lookup.pcap", dns_packets())
    write_pcap(out_dir / "tcp-http.pcap", tcp_packets())
    write_pcap(out_dir / "tls-client-hello.pcap", tls_packets())
    write_pcap(out_dir / "icmp-ping.pcap", icmp_packets())

    mixed = dns_packets() + tcp_packets() + tls_packets() + icmp_packets()
    write_pcapng(out_dir / "mixed-traffic.pcapng", mixed)

    for path in sorted(out_dir.iterdir()):
        print(f"{path.name:26} {path.stat().st_size:6} bytes")


if __name__ == "__main__":
    main()
