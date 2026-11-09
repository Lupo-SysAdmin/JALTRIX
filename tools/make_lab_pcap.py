"""Create benign offline traffic, never send packets to a network."""

from pathlib import Path
import socket
import struct


def checksum(data):
    values = struct.unpack("!10H", data)
    value = sum(values)
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def generate(target):
    packets = []
    for i, payload in enumerate(
        [b"SNORT_SOC_LAB one", b"ordinary benign payload", b"SNORT_SOC_LAB two"]
    ):
        udp = struct.pack("!HHHH", 45000 + i, 9999, 8 + len(payload), 0) + payload
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(udp),
            i,
            0,
            64,
            17,
            0,
            socket.inet_aton("192.0.2.10"),
            socket.inet_aton("198.51.100.20"),
        )
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        ethernet = bytes.fromhex("0200000000020200000000010800") + ip + udp
        packets.append(
            struct.pack("<IIII", 1794234000 + i, 123456, len(ethernet), len(ethernet))
            + ethernet
        )
    Path(target).write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"".join(packets)
    )


if __name__ == "__main__":
    generate(Path(__file__).parents[1] / "tests/fixtures/lab/benign.pcap")
