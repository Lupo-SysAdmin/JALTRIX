"""Offline, source-scoped geographic aggregation and paginated investigation.

Counts use the complete filtered query in one SQLite snapshot, not the UI page.
Only the demonstration fixture assigns synthetic locations to reserved IPs.
"""

from collections import defaultdict
from functools import lru_cache
import hashlib
import json

from .snort import AlertStore

DEMO_PLACES = (
    ("US", 40.7, -74.0),
    ("MX", 19.4, -99.1),
    ("CO", 4.7, -74.1),
    ("BR", -23.5, -46.6),
    ("ES", 40.4, -3.7),
    ("JP", 35.7, 139.7),
)
PAGE_SIZE = 100
MARKER_LIMIT = 1000


def demo_location(address):
    try:
        part = int(address.removeprefix("192.0.2."))
    except (ValueError, AttributeError):
        return None
    if not address.startswith("192.0.2.") or not 1 <= part <= 24:
        return None
    country, latitude, longitude = DEMO_PLACES[(part - 1) % len(DEMO_PLACES)]
    return dict(
        country=country,
        latitude=latitude,
        longitude=longitude,
        source="Ubicación sintética de demostración",
        ip=address,
        approximate=True,
    )


def marker_key(location):
    return hashlib.sha256(
        json.dumps([location[k] for k in ("country", "latitude", "longitude")]).encode()
    ).hexdigest()[:20]


def build_map(
    database=None,
    demo=None,
    path=None,
    mode="demo",
    source=None,
    query="",
    severity="Todas",
    minutes=1440,
    category="Todas",
    country="",
    marker="",
    offset=0,
):
    """Return bounded visuals and exact country counts; never send IPs externally."""
    store = None
    countries, points = {}, {}
    total = located = 0
    selected_count = 0
    selected_demo = []

    @lru_cache(maxsize=8192)
    def locate(address):
        try:
            return (
                demo_location(address)
                if mode == "demo"
                else database.lookup(address)
                if database
                else None
            )
        except ValueError:
            return None

    try:
        if mode == "demo":
            rows = demo or []
            counts = defaultdict(lambda: [0, 0])
            for event in rows:
                counts[event["src"]][0] += 1
                counts[event["src"]][1] += event["severity"] == "Crítica"
            groups = ((ip, *counts[ip]) for ip in counts)
        elif source:
            store = AlertStore(path)
            source_id = store.source_id(source, mode)
            clause, values = store._where(
                mode, source_id, query, severity, minutes, category
            )
            store.db.execute(
                "CREATE TEMP TABLE geo_selected (ip TEXT PRIMARY KEY) WITHOUT ROWID"
            )
            store.db.execute("BEGIN")
            groups = store.db.execute(
                "SELECT src,count(*),sum(severity='Crítica') FROM events WHERE "
                + clause
                + " GROUP BY src",
                values,
            )
        else:
            groups = []
        for address, count, critical in groups:
            total += count
            location = locate(address)
            if not location:
                continue
            located += count
            code, key = location["country"], marker_key(location)
            nation = countries.setdefault(
                code, dict(country=code, alerts=0, critical=0, sources=0)
            )
            nation["alerts"] += count
            nation["critical"] += critical
            nation["sources"] += 1
            point = points.setdefault(
                key, dict(location, key=key, alerts=0, critical=0, sources=0)
            )
            point["alerts"] += count
            point["critical"] += critical
            point["sources"] += 1
            if (not country or code == country) and (not marker or key == marker):
                selected_count += count
                if store:
                    store.db.execute(
                        "INSERT OR IGNORE INTO geo_selected VALUES (?)", (address,)
                    )
        if mode == "demo":
            for event in rows:
                location = locate(event["src"])
                if (
                    location
                    and (not country or location["country"] == country)
                    and (not marker or marker_key(location) == marker)
                ):
                    selected_demo.append(dict(event))
        offset = max(0, min(offset, ((selected_count - 1) // PAGE_SIZE) * PAGE_SIZE))
        if store:
            events = []
            size = 0
            for (raw,) in store.db.execute(
                "SELECT data FROM events WHERE "
                + clause
                + " AND src IN (SELECT ip FROM geo_selected) ORDER BY rowid DESC LIMIT ? OFFSET ?",
                values + [PAGE_SIZE, offset],
            ):
                size += len(raw.encode())
                if size > 8 * 1024 * 1024:
                    break
                events.append(json.loads(raw))
        else:
            events = selected_demo[offset : offset + PAGE_SIZE]
        for nation in countries.values():
            nation["percent"] = round(nation["alerts"] * 100 / max(1, located), 1)
        for point in points.values():
            point["x"] = (point["longitude"] + 180) / 360
            point["y"] = (90 - point["latitude"]) / 180
        visible = sorted(
            (p for p in points.values() if not country or p["country"] == country),
            key=lambda p: (-p["alerts"], p["key"]),
        )
        return dict(
            total=total,
            located=located,
            unlocated=total - located,
            countries=sorted(
                countries.values(), key=lambda c: (-c["alerts"], c["country"])
            ),
            markers=visible[:MARKER_LIMIT],
            hidden_markers=max(0, len(visible) - MARKER_LIMIT),
            events=events,
            matched=selected_count,
            offset=offset,
            next=offset + len(events),
            country=country,
            marker=marker,
            demo=mode == "demo",
            configured=mode == "demo" or database is not None,
            database_sha256=database.sha256 if database and mode != "demo" else "",
        )
    finally:
        if store:
            store.db.rollback()
            store.close()
