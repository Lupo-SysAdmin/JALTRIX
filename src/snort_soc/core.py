"""Datos demo deterministas y casos locales; sin operaciones de red."""

import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

CATEGORIES = ["Web", "SSH", "DNS", "Malware", "Escaneo"]
MESSAGES = [
    "Solicitud web de laboratorio",
    "Intentos SSH de laboratorio",
    "Consulta DNS de laboratorio",
    "Firma sintética de laboratorio",
    "Conexiones repetidas de laboratorio",
]
SEVERITIES = ["Crítica", "Alta", "Media", "Baja"]


def demo_events(count=240):
    anchor = datetime(2026, 11, 9, 14, 30, tzinfo=timezone.utc)
    events = []
    for i in range(count):
        category = i % 5
        timestamp = anchor - timedelta(seconds=i * 19)
        events.append(
            dict(
                event_id=f"demo-{i:06d}",
                timestamp=timestamp.isoformat(),
                time=timestamp.strftime("%H:%M:%S"),
                severity=SEVERITIES[i % 4],
                message=MESSAGES[category],
                category=CATEGORIES[category],
                sid=f"1:{1000001 + category}:1",
                src=f"192.0.2.{1 + i % 24}",
                dst=f"198.51.100.{1 + i % 6}",
                protocol=["HTTP", "TCP", "DNS", "TCP", "TCP"][category],
                action="Simulada",
                mode="demo",
                sensor="Laboratorio demo",
                source="fixture determinista v1; no procede de Snort",
                triage="Nuevo",
            )
        )
    return events


def filter_events(events, query="", severity="Todas", category="Todas", minutes=1440):
    # Demo anchored to fixture time, never to the system clock.
    anchor = max(
        (datetime.fromisoformat(e["timestamp"]) for e in events if e.get("timestamp")),
        default=None,
    )
    if events and events[0]["mode"] == "live":
        anchor = datetime.now(timezone.utc)
    needle = query.strip().casefold()
    return [
        e
        for e in events
        if (not needle or needle in " ".join(str(v) for v in e.values()).casefold())
        and (severity == "Todas" or e["severity"] == severity)
        and (category == "Todas" or e["category"] == category)
        and (
            anchor is None
            or not e.get("timestamp")
            or datetime.fromisoformat(e["timestamp"])
            >= anchor - timedelta(minutes=minutes)
        )
    ]


def summarize(events):
    buckets = Counter(e["timestamp"][:16] for e in events if e.get("timestamp"))
    ordered = sorted(buckets.items())
    series, stride = [], 1
    if ordered:
        start = datetime.fromisoformat(ordered[0][0]).replace(tzinfo=timezone.utc)
        end = datetime.fromisoformat(ordered[-1][0]).replace(tzinfo=timezone.utc)
        span = int((end - start).total_seconds() // 60) + 1
        stride = max(1, (span + 59) // 60)
        groups = Counter()
        for stamp, count in ordered:
            delta = int(
                (
                    datetime.fromisoformat(stamp).replace(tzinfo=timezone.utc) - start
                ).total_seconds()
                // 60
            )
            groups[delta // stride] += count
        series = [
            {
                "minute": (start + timedelta(minutes=i * stride)).strftime(
                    "%m-%d %H:%M"
                ),
                "count": groups[i],
            }
            for i in range((span + stride - 1) // stride)
        ]
    return dict(
        bin_minutes=stride,
        peak=max((v["count"] for v in series), default=1),
        total=len(events),
        critical=sum(e["severity"] == "Crítica" for e in events),
        sources=len({e["src"] for e in events}),
        series=series,
        top=[
            {"ip": ip, "count": count}
            for ip, count in Counter(e["src"] for e in events).most_common(5)
        ],
    )


class CaseStore:
    def __init__(self, path, mode="demo"):
        if mode not in ("demo", "replay", "live"):
            raise ValueError("invalid case mode")
        self.mode = mode
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.path)
        self.path.chmod(0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, event_id TEXT UNIQUE, title TEXT, created_at TEXT, mode TEXT CHECK(mode IN ("demo","replay","live")))'
        )
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(cases)")}
        if "notes" not in columns:
            self.db.execute(
                "ALTER TABLE cases ADD COLUMN notes TEXT NOT NULL DEFAULT ''"
            )
        if "status" not in columns:
            self.db.execute(
                "ALTER TABLE cases ADD COLUMN status TEXT NOT NULL DEFAULT 'new'"
            )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS case_history (id INTEGER PRIMARY KEY, case_id TEXT, timestamp TEXT, before_json TEXT, after_json TEXT)"
        )
        self.db.commit()

    def create(self, event):
        if event["mode"] != self.mode:
            raise ValueError("Este almacén está reservado a demostraciones")
        existing = self.db.execute(
            "SELECT id FROM cases WHERE event_id=?", (event["event_id"],)
        ).fetchone()
        if existing:
            return existing[0]
        case_id = ("DEMO-" if self.mode == "demo" else "CASE-") + uuid4().hex[
            :8
        ].upper()
        with self.db:
            self.db.execute(
                "INSERT INTO cases (id,event_id,title,created_at,mode) VALUES (?,?,?,?,?)",
                (
                    case_id,
                    event["event_id"],
                    event["message"],
                    datetime.now(timezone.utc).isoformat(),
                    self.mode,
                ),
            )
        return case_id

    def list(self):
        return [
            dict(
                zip(
                    [
                        "id",
                        "event_id",
                        "title",
                        "created_at",
                        "mode",
                        "notes",
                        "status",
                    ],
                    row,
                )
            )
            for row in self.db.execute("SELECT * FROM cases ORDER BY created_at DESC")
        ]

    def update(self, case_id, notes, status):
        if len(notes) > 100000 or status not in (
            "new",
            "investigating",
            "resolved",
            "closed",
        ):
            raise ValueError("Invalid case notes or status")
        before = next((c for c in self.list() if c["id"] == case_id), None)
        if before is None:
            raise ValueError("Unknown case")
        with self.db:
            self.db.execute(
                "UPDATE cases SET notes=?,status=? WHERE id=?", (notes, status, case_id)
            )
            self.db.execute(
                "INSERT INTO case_history(case_id,timestamp,before_json,after_json) VALUES (?,?,?,?)",
                (
                    case_id,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(before),
                    json.dumps(dict(before, notes=notes, status=status)),
                ),
            )

    def close(self):
        self.db.close()
