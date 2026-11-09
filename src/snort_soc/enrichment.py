"""Versioned analyst ATT&CK mappings and explicitly imported offline GeoIP data."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
from pathlib import Path
import re
import sqlite3


class MappingStore:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path)
        path.chmod(0o600)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS mappings (revision INTEGER PRIMARY KEY, signature TEXT, technique TEXT, title TEXT, confidence TEXT, reason TEXT, created TEXT, actor TEXT)"
        )
        self.db.commit()

    def save(self, signature, technique, title, confidence, reason, actor):
        if not re.fullmatch(r"\d+:\d+:\d+", signature):
            raise ValueError("Invalid gid:sid:rev")
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            raise ValueError("Invalid ATT&CK technique identifier")
        if (
            confidence not in ("low", "medium", "high")
            or not title.strip()
            or not reason.strip()
        ):
            raise ValueError("Mapping requires title, confidence and rationale")
        if len(title) > 200 or len(reason) > 4000 or len(actor) > 200:
            raise ValueError("Mapping too large")
        with self.db:
            cursor = self.db.execute(
                "INSERT INTO mappings(signature,technique,title,confidence,reason,created,actor) VALUES (?,?,?,?,?,?,?)",
                (
                    signature,
                    technique,
                    title,
                    confidence,
                    reason,
                    datetime.now(timezone.utc).isoformat(),
                    actor,
                ),
            )
        return cursor.lastrowid

    def latest(self):
        rows = self.db.execute(
            "SELECT * FROM mappings WHERE revision IN (SELECT max(revision) FROM mappings GROUP BY signature)"
        )
        names = [
            "revision",
            "signature",
            "technique",
            "title",
            "confidence",
            "reason",
            "created",
            "actor",
        ]
        return {r[1]: dict(zip(names, r)) for r in rows}

    def summarize(self, events):
        mapping = self.latest()
        counts = Counter(e["sid"] for e in events if e.get("sid") in mapping)
        return [
            dict(
                mapping[sid],
                alerts=count,
                url="https://attack.mitre.org/techniques/"
                + mapping[sid]["technique"].replace(".", "/")
                + "/",
            )
            for sid, count in counts.items()
        ]

    def close(self):
        self.db.close()


class GeoDatabase:
    """Local CSV only. No IP, packet or identifier is transmitted to a service."""

    def __init__(self, path):
        import csv

        path = Path(path)
        if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("GeoIP CSV must be under 8 MiB")
        self.entries = []
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            if set(reader.fieldnames or []) != {
                "network",
                "country",
                "latitude",
                "longitude",
                "source",
            }:
                raise ValueError(
                    "GeoIP columns: network,country,latitude,longitude,source"
                )
            for item in reader:
                network = ipaddress.ip_network(item["network"], strict=True)
                latitude, longitude = float(item["latitude"]), float(item["longitude"])
                if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
                    raise ValueError("Invalid GeoIP coordinates")
                if (
                    not re.fullmatch("[A-Z]{2}", item["country"])
                    or not item["source"].strip()
                ):
                    raise ValueError("GeoIP requires country code and source")
                self.entries.append(
                    (
                        network,
                        dict(
                            country=item["country"],
                            latitude=latitude,
                            longitude=longitude,
                            source=item["source"][:500],
                        ),
                    )
                )
        self.entries.sort(key=lambda p: p[0].prefixlen, reverse=True)
        self.sha256 = hashlib.sha256(path.read_bytes()).hexdigest()

    def lookup(self, address):
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            return None
        for network, entry in self.entries:
            if ip.version == network.version and ip in network:
                return dict(
                    entry,
                    ip=str(ip),
                    network=str(network),
                    database_sha256=self.sha256,
                    approximate=True,
                )
        return None
