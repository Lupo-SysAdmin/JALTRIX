"""Bounded PCAP/PCAPNG reader. Never loads Lua, plugins or capture-file scripts."""

import hashlib
import ipaddress
from pathlib import Path
import struct

MAX_PACKET = 16 * 1024 * 1024
MAX_CAPTURE = 1024 * 1024 * 1024


def exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("Truncated capture")
    return data


def options(raw, endian):
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise ValueError("Invalid PCAPNG option")
        code, size = struct.unpack_from(endian + "HH", raw, offset)
        offset += 4
        if code == 0:
            if size:
                raise ValueError("Invalid option terminator")
            return
        if offset + size > len(raw):
            raise ValueError("Truncated PCAPNG option")
        yield code, raw[offset : offset + size]
        offset += (size + 3) & ~3
        if offset > len(raw):
            raise ValueError("Missing option padding")


def packets(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file() or path.stat().st_size > MAX_CAPTURE:
        raise ValueError("Capture must be a regular file up to 1 GiB")
    with path.open("rb") as stream:
        magic = exact(stream, 4)
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1e6),
            b"\xa1\xb2\xc3\xd4": (">", 1e6),
            b"\x4d\x3c\xb2\xa1": ("<", 1e9),
            b"\xa1\xb2\x3c\x4d": (">", 1e9),
        }
        if magic in formats:
            endian, scale = formats[magic]
            major, minor, _, _, snap, link = struct.unpack(
                endian + "HHIIII", exact(stream, 20)
            )
            if (major, minor) != (2, 4) or not 0 < snap <= MAX_PACKET:
                raise ValueError("Unsupported PCAP header")
            number = 0
            while header := stream.read(16):
                if len(header) != 16:
                    raise ValueError("Truncated packet header")
                sec, frac, length, original = struct.unpack(endian + "IIII", header)
                if length > snap or length > original or frac >= scale:
                    raise ValueError("Invalid packet length or timestamp")
                number += 1
                yield dict(
                    number=number,
                    timestamp=sec + frac / scale,
                    linktype=link,
                    original=original,
                    payload=exact(stream, length),
                    format="PCAP",
                    interface=0,
                )
            return
        if magic != b"\x0a\x0d\x0d\x0a":
            raise ValueError("Invalid capture header")
        stream.seek(0)
        endian = None
        interfaces = []
        number = 0
        while header := stream.read(8):
            if len(header) != 8:
                raise ValueError("Truncated block header")
            if header[:4] == b"\x0a\x0d\x0d\x0a":
                bom = exact(stream, 4)
                endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(bom)
                if endian is None:
                    raise ValueError("Invalid section byte order")
                length = struct.unpack(endian + "I", header[4:])[0]
                if not 28 <= length <= MAX_PACKET or length % 4:
                    raise ValueError("Invalid section length")
                rest = exact(stream, length - 12)
                if struct.unpack(endian + "I", rest[-4:])[0] != length:
                    raise ValueError("Block length mismatch")
                if struct.unpack(endian + "HH", rest[:4]) != (1, 0):
                    raise ValueError("Unsupported PCAPNG version")
                interfaces = []
                continue
            if endian is None:
                raise ValueError("Missing PCAPNG section")
            kind, length = struct.unpack(endian + "II", header)
            if not 12 <= length <= MAX_PACKET + 4096 or length % 4:
                raise ValueError("Invalid block length")
            body = exact(stream, length - 8)
            if struct.unpack(endian + "I", body[-4:])[0] != length:
                raise ValueError("Block length mismatch")
            body = body[:-4]
            if kind == 1:
                if len(body) < 8:
                    raise ValueError("Truncated interface block")
                link, _, snap = struct.unpack(endian + "HHI", body[:8])
                if snap > MAX_PACKET:
                    raise ValueError("Oversized snapshot")
                item = dict(link=link, snap=snap or MAX_PACKET, scale=1e6, offset=0)
                for code, value in options(body[8:], endian):
                    if code == 9:
                        if len(value) != 1:
                            raise ValueError("Invalid timestamp resolution")
                        item["scale"] = (2 if value[0] & 128 else 10) ** (
                            value[0] & 127
                        )
                    if code == 14:
                        if len(value) != 8:
                            raise ValueError("Invalid timestamp offset")
                        item["offset"] = struct.unpack(endian + "q", value)[0]
                interfaces.append(item)
            elif kind == 6:
                if len(body) < 20:
                    raise ValueError("Truncated enhanced packet")
                interface, high, low, captured, original = struct.unpack(
                    endian + "IIIII", body[:20]
                )
                if interface >= len(interfaces):
                    raise ValueError("Unknown capture interface")
                item = interfaces[interface]
                if captured > min(item["snap"], original, MAX_PACKET) or 20 + (
                    (captured + 3) & ~3
                ) > len(body):
                    raise ValueError("Invalid enhanced packet length")
                list(options(body[20 + ((captured + 3) & ~3) :], endian))
                number += 1
                yield dict(
                    number=number,
                    timestamp=((high << 32) | low) / item["scale"] + item["offset"],
                    linktype=item["link"],
                    original=original,
                    payload=body[20 : 20 + captured],
                    format="PCAPNG",
                    interface=interface,
                )
            elif kind == 3:
                if not interfaces or len(body) < 4:
                    raise ValueError("Invalid simple packet")
                item = interfaces[0]
                original = struct.unpack(endian + "I", body[:4])[0]
                captured = min(original, item["snap"])
                if 4 + ((captured + 3) & ~3) != len(body):
                    raise ValueError("Invalid simple packet size")
                number += 1
                yield dict(
                    number=number,
                    timestamp=None,
                    linktype=item["link"],
                    original=original,
                    payload=body[4 : 4 + captured],
                    format="PCAPNG",
                    interface=0,
                )
            elif kind == 2:
                raise ValueError(
                    "Legacy PCAPNG packet blocks require conversion with editcap"
                )


def inspect(path):
    path = Path(path).resolve(strict=True)
    count = 0
    first = last = None
    links = set()
    with path.open("rb") as stream:
        fmt = "PCAPNG" if stream.read(4) == b"\x0a\x0d\x0d\x0a" else "PCAP"
    for item in packets(path):
        count += 1
        links.add(item["linktype"])
        stamp = item["timestamp"]
        if stamp is not None:
            first = stamp if first is None else min(first, stamp)
            last = stamp if last is None else max(last, stamp)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return dict(
        path=str(path),
        sha256=digest,
        size=path.stat().st_size,
        packets=count,
        first_seconds=first,
        last_seconds=last,
        linktype=next(iter(links)) if len(links) == 1 else None,
        format=fmt,
    )


def convert_to_pcap(source, destination):
    """Reject missing timestamps/mixed linktypes rather than fabricate replay evidence."""
    link = None
    with Path(destination).open("wb") as out:
        for item in packets(source):
            if item["timestamp"] is None or not 0 <= item["timestamp"] < 2**32:
                raise ValueError("Packet timestamp cannot be represented in PCAP")
            if link is None:
                link = item["linktype"]
                out.write(
                    struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, MAX_PACKET, link)
                )
            if item["linktype"] != link:
                raise ValueError("Mixed linktypes cannot be replayed as one PCAP")
            sec = int(item["timestamp"])
            nano = min(999999999, round((item["timestamp"] - sec) * 1e9))
            out.write(
                struct.pack("<IIII", sec, nano, len(item["payload"]), item["original"])
            )
            out.write(item["payload"])
        if link is None:
            raise ValueError("Empty PCAPNG cannot be converted for replay")


def describe(item):
    payload = item["payload"]
    row = {k: v for k, v in item.items() if k != "payload"}
    row.update(
        captured=len(payload),
        src="—",
        dst="—",
        protocol="L2",
        src_port=None,
        dst_port=None,
    )
    offset = 0
    ether = None
    if item["linktype"] == 1 and len(payload) >= 14:
        ether = int.from_bytes(payload[12:14], "big")
        offset = 14
        for _ in range(2):
            if ether in (0x8100, 0x88A8) and len(payload) >= offset + 4:
                ether = int.from_bytes(payload[offset + 2 : offset + 4], "big")
                offset += 4
    elif item["linktype"] in (101, 228, 229) and payload:
        ether = {4: 0x800, 6: 0x86DD}.get(payload[0] >> 4)
    if ether == 0x800 and len(payload) >= offset + 20:
        ihl = (payload[offset] & 15) * 4
        if ihl < 20 or len(payload) < offset + ihl:
            return row
        row.update(
            src=str(ipaddress.ip_address(payload[offset + 12 : offset + 16])),
            dst=str(ipaddress.ip_address(payload[offset + 16 : offset + 20])),
        )
        proto = payload[offset + 9]
        fragmented = int.from_bytes(payload[offset + 6 : offset + 8], "big") & 0x1FFF
        offset += ihl
    elif ether == 0x86DD and len(payload) >= offset + 40:
        row.update(
            src=str(ipaddress.ip_address(payload[offset + 8 : offset + 24])),
            dst=str(ipaddress.ip_address(payload[offset + 24 : offset + 40])),
        )
        proto = payload[offset + 6]
        offset += 40
        fragmented = False
    else:
        return row
    row["protocol"] = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(
        proto, str(proto)
    )
    if not fragmented and proto in (6, 17) and len(payload) >= offset + 4:
        row["src_port"], row["dst_port"] = struct.unpack(
            "!HH", payload[offset : offset + 4]
        )
    return row


def page(path, offset=0, limit=200, query=""):
    if offset < 0 or not 1 <= limit <= 500:
        raise ValueError("Invalid packet page")
    rows = []
    matched = 0
    for item in packets(path):
        row = describe(item)
        if query.casefold() not in " ".join(str(v) for v in row.values()).casefold():
            continue
        if matched >= offset:
            rows.append(row)
        matched += 1
        if len(rows) >= limit:
            break
    return rows


def packet_bytes(path, number):
    if type(number) is not int or number < 1:
        raise ValueError("Invalid packet number")
    for item in packets(path):
        if item["number"] == number:
            data = item["payload"][:256]
            return dict(
                number=number,
                captured=len(item["payload"]),
                shown=len(data),
                hex=data.hex(" "),
                truncated=len(item["payload"]) > len(data),
            )
    raise ValueError("Packet not found")
