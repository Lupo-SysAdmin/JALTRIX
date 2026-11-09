"""Evidence-only graph and local interface counters; no inference of infrastructure."""

from collections import Counter
import ipaddress
from pathlib import Path
import re
import time


def topology(events):
    edges = Counter()
    for event in events:
        try:
            source = str(ipaddress.ip_address(event["src"]))
            destination = str(ipaddress.ip_address(event["dst"]))
        except (ValueError, KeyError):
            continue
        edges[(source, destination, event.get("protocol", "—"))] += 1
    return [
        dict(src=s, dst=d, protocol=p, alerts=n)
        for (s, d, p), n in edges.most_common(200)
    ]


class InterfaceSampler:
    def __init__(self, root=Path("/sys/class/net"), clock=time.monotonic):
        self.root, self.clock = Path(root), clock
        self.previous = {}

    def interfaces(self):
        return sorted(p.name for p in self.root.iterdir())

    def sample(self, name):
        if (
            not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", name)
            or name not in self.interfaces()
        ):
            raise ValueError("Unknown network interface")
        directory = self.root / name / "statistics"
        counters = {
            key: int((directory / key).read_text())
            for key in [
                "rx_bytes",
                "tx_bytes",
                "rx_packets",
                "tx_packets",
                "rx_dropped",
                "tx_dropped",
            ]
        }
        now = self.clock()
        previous = self.previous.get(name)
        self.previous[name] = (now, counters)
        result = dict(
            interface=name, counters=counters, ready=False, source=str(directory)
        )
        if previous:
            elapsed = now - previous[0]
            if elapsed > 0 and all(counters[k] >= previous[1][k] for k in counters):
                result.update(
                    ready=True,
                    seconds=elapsed,
                    rx_mbps=(counters["rx_bytes"] - previous[1]["rx_bytes"])
                    * 8
                    / elapsed
                    / 1e6,
                    tx_mbps=(counters["tx_bytes"] - previous[1]["tx_bytes"])
                    * 8
                    / elapsed
                    / 1e6,
                    rx_pps=(counters["rx_packets"] - previous[1]["rx_packets"])
                    / elapsed,
                    tx_pps=(counters["tx_packets"] - previous[1]["tx_packets"])
                    / elapsed,
                )
        return result
