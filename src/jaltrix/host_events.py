"""Private, versioned store for local host observations; existing Snort stores stay intact.

One connection per thread. Events retain their provider identity and evidence.
Only collectors write observations; the GUI reads and explicitly pins case evidence.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import itertools
import json
import math
from pathlib import Path
import sqlite3

APPLICATION_ID = 0x4A485631
SCHEMA_VERSION = 1
MAX_BATCH = 5000
MAX_EVENT_BYTES = 131072
MAX_CHECKPOINT_BYTES = 65536
SOURCES = frozenset(("journal", "audit", "snort"))
KINDS = frozenset(
    (
        "auth_success",
        "auth_failure",
        "privilege_use",
        "file_change",
        "process_exec",
        "service_change",
        "network_alert",
        "system_event",
    )
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _json(value, maximum):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    if len(text.encode("utf-8")) > maximum:
        raise ValueError("JSON exceeds the configured record limit")
    return text


def _text(value, name, maximum=256, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise ValueError(f"Invalid {name}")
    if required and not value.strip():
        raise ValueError(f"Missing {name}")
    return value


def _time(value):
    """Do not assign a timezone or a year to ambiguous source timestamps."""
    if not isinstance(value, str):
        return None, None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None, None
        stamp = stamp.astimezone(timezone.utc)
        epoch = stamp.timestamp()
        if not math.isfinite(epoch):
            return None, None
        return stamp.isoformat(timespec="microseconds"), epoch
    except (ValueError, OverflowError, OSError):
        return None, None


def normalize_event(value):
    """Validate a provider observation without converting missing evidence to facts."""
    if not isinstance(value, dict):
        raise ValueError("Expected an event object")
    _json(value, MAX_EVENT_BYTES)
    event = dict(value)
    for key in ("event_id", "source", "host_id", "original_id"):
        _text(event.get(key), key, 2048 if key == "original_id" else 256, True)
    if event["source"] not in SOURCES:
        raise ValueError("Unsupported event source")
    if event.get("mode", "live") != "live":
        raise ValueError("Host observations are reserved for live mode")
    event["mode"] = "live"
    if event.get("kind") not in KINDS:
        raise ValueError("Unsupported event kind")
    event["hostname"] = event.get("hostname") or event["host_id"]
    for key in ("hostname", "user", "exe", "path", "home_dir", "service", "outcome"):
        event[key] = _text(
            event.get(key), key, 4096 if key in ("exe", "path", "home_dir") else 256
        )
    event["message"] = _text(event.get("message", ""), "message", 8192)
    if event.get("service") is None and isinstance(event.get("details"), dict):
        event["service"] = _text(event["details"].get("service"), "service", 256)
    if event.get("service") == "ssh":
        event["service"] = "sshd"
    for key in ("uid", "auid", "pid", "dst_port"):
        number = event.get(key)
        if number is not None and (type(number) is not int or number < 0):
            raise ValueError(f"Invalid {key}")
        if key == "dst_port" and number is not None and number > 65535:
            raise ValueError("Invalid destination port")
        event[key] = number
    for key in ("src_ip", "dst_ip"):
        address = event.get(key)
        if address is not None:
            if not isinstance(address, str):
                raise ValueError(f"Invalid {key}")
            event[key] = str(ipaddress.ip_address(address))
        else:
            event[key] = None
    if "host_bound" in event and type(event["host_bound"]) is not bool:
        raise ValueError("Invalid host binding")
    if not isinstance(event.get("raw_record", {}), (dict, list, str)):
        raise ValueError("Invalid original evidence")
    event.setdefault("raw_record", {})
    timestamp, epoch = _time(event.get("timestamp"))
    if event.get("timestamp_confidence") == "unknown":
        timestamp = epoch = None
    event.setdefault("original_timestamp", event.get("timestamp"))
    event["timestamp"] = timestamp
    event["timestamp_confidence"] = (
        event.get("timestamp_confidence") or "explicit_timezone"
        if timestamp is not None
        else "unknown"
    )
    event["ingested_at"] = utc_now()
    return event, epoch


class HostEventStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ValueError("Refusing a symbolic host database path")
        self.db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        try:
            application = self.db.execute("PRAGMA application_id").fetchone()[0]
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            tables = self.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            if application not in (0, APPLICATION_ID) or (application == 0 and tables):
                raise ValueError("This is not a JALTRIX host-event database")
            if version > SCHEMA_VERSION:
                raise ValueError("Host-event database requires a newer JALTRIX version")
            self.path.chmod(0o600)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA busy_timeout=15000")
            self.db.executescript(f"""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS host_events (
                    id TEXT PRIMARY KEY, source TEXT NOT NULL, host_id TEXT NOT NULL,
                    original_id TEXT NOT NULL, hostname TEXT NOT NULL,
                    timestamp TEXT, event_time REAL, ingested_at TEXT NOT NULL,
                    kind TEXT NOT NULL, service TEXT, user TEXT, src_ip TEXT,
                    outcome TEXT, path TEXT, data TEXT NOT NULL,
                    UNIQUE(source,host_id,original_id)
                );
                CREATE INDEX IF NOT EXISTS host_event_time ON host_events(host_id,event_time,id);
                CREATE INDEX IF NOT EXISTS host_event_match ON host_events(host_id,kind,user,src_ip,event_time);
                CREATE INDEX IF NOT EXISTS host_event_kind ON host_events(kind,event_time);
                CREATE INDEX IF NOT EXISTS host_event_src ON host_events(host_id,kind,src_ip,event_time);
                CREATE INDEX IF NOT EXISTS host_event_ingested ON host_events(ingested_at,id);
                CREATE TABLE IF NOT EXISTS host_checkpoints (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS host_quarantine (
                    id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, reason TEXT NOT NULL,
                    record_hash TEXT NOT NULL, preview TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS host_correlations (
                    id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, host_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL, data TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS host_correlation_time ON host_correlations(timestamp);
                CREATE TABLE IF NOT EXISTS host_correlation_events (
                    correlation_id TEXT NOT NULL REFERENCES host_correlations(id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL REFERENCES host_events(id) ON DELETE CASCADE,
                    PRIMARY KEY(correlation_id,event_id)
                );
                CREATE TABLE IF NOT EXISTS host_case_pins (
                    correlation_id TEXT NOT NULL REFERENCES host_correlations(id) ON DELETE CASCADE,
                    case_id TEXT NOT NULL, PRIMARY KEY(correlation_id,case_id)
                );
                CREATE TABLE IF NOT EXISTS host_correlation_work (
                    host_id TEXT NOT NULL, bucket INTEGER NOT NULL,
                    generation INTEGER NOT NULL DEFAULT 1, scan_generation INTEGER NOT NULL DEFAULT 1,
                    cursor_time REAL, cursor_id TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(host_id,bucket)
                );
                PRAGMA application_id={APPLICATION_ID};
                PRAGMA user_version={SCHEMA_VERSION};
                COMMIT;
            """)
        except Exception:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def checkpoint(self, key):
        _text(key, "checkpoint key", 512, True)
        row = self.db.execute(
            "SELECT value FROM host_checkpoints WHERE key=?", (key,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def _reject(self, value, reason):
        try:
            raw = json.dumps(value, ensure_ascii=True, default=str)
        except (TypeError, ValueError, RecursionError):
            raw = "<unserializable observation>"
        self.db.execute(
            "INSERT INTO host_quarantine(observed_at,reason,record_hash,preview) VALUES (?,?,?,?)",
            (
                utc_now(),
                str(reason)[:1024],
                hashlib.sha256(raw.encode()).hexdigest(),
                raw[:2048],
            ),
        )

    def ingest(self, events, checkpoint_key=None, checkpoint=None):
        values = list(itertools.islice(iter(events), MAX_BATCH + 1))
        if len(values) > MAX_BATCH:
            raise ValueError(f"An ingestion batch cannot exceed {MAX_BATCH} events")
        checkpoint_json = None
        if checkpoint_key is not None:
            _text(checkpoint_key, "checkpoint key", 512, True)
            checkpoint_json = _json(checkpoint, MAX_CHECKPOINT_BYTES)
        inserted = rejected = duplicates = 0
        self.db.execute("BEGIN IMMEDIATE")
        try:
            from .correlation import process_pending, schedule

            for value in values:
                try:
                    event, epoch = normalize_event(value)
                    data = _json(event, MAX_EVENT_BYTES)
                    existing = self.db.execute(
                        "SELECT id,source,host_id,original_id FROM host_events WHERE id=? OR (source=? AND host_id=? AND original_id=?)",
                        (
                            event["event_id"],
                            event["source"],
                            event["host_id"],
                            event["original_id"],
                        ),
                    ).fetchall()
                    if existing:
                        identity = (
                            event["source"],
                            event["host_id"],
                            event["original_id"],
                        )
                        if any(tuple(row[1:]) != identity for row in existing):
                            raise ValueError(
                                "Event ID collides with a different provider identity"
                            )
                        duplicates += 1
                        continue
                    self.db.execute(
                        "INSERT INTO host_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            event["event_id"],
                            event["source"],
                            event["host_id"],
                            event["original_id"],
                            event["hostname"],
                            event["timestamp"],
                            epoch,
                            event["ingested_at"],
                            event["kind"],
                            event["service"],
                            event["user"],
                            event["src_ip"],
                            event["outcome"],
                            event["path"],
                            data,
                        ),
                    )
                    inserted += 1
                    if epoch is not None and event["kind"] in (
                        "auth_failure",
                        "auth_success",
                        "file_change",
                        "privilege_use",
                        "network_alert",
                    ):
                        schedule(self.db, event["host_id"], epoch)
                except (ValueError, TypeError, RecursionError, OverflowError) as exc:
                    self._reject(value, exc)
                    rejected += 1
            created = process_pending(self.db)
            if checkpoint_key is not None:
                self.db.execute(
                    "INSERT INTO host_checkpoints VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (checkpoint_key, checkpoint_json),
                )
            self.db.execute(
                "DELETE FROM host_quarantine WHERE id NOT IN (SELECT id FROM host_quarantine ORDER BY id DESC LIMIT 1000)"
            )
            pending = self.db.execute(
                "SELECT count(*) FROM host_correlation_work"
            ).fetchone()[0]
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return dict(
            inserted=inserted,
            rejected=rejected,
            duplicates=duplicates,
            correlations_created=created,
            correlation_pending=pending,
        )

    @staticmethod
    def _where(query="", source="", kind="", host_id=""):
        predicates, parameters = [], []
        for key, value in (("source", source), ("kind", kind), ("host_id", host_id)):
            if value:
                _text(value, key, 256)
                predicates.append(key + "=?")
                parameters.append(value)
        if query:
            _text(query, "query", 4096)
            escaped = (
                query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            predicates.append("data LIKE ? ESCAPE '\\'")
            parameters.append("%" + escaped + "%")
        return " AND ".join(predicates) or "1", parameters

    @staticmethod
    def _page(limit, offset):
        if (
            type(limit) is not int
            or not 1 <= limit <= 1000
            or type(offset) is not int
            or offset < 0
        ):
            raise ValueError("Invalid page")

    def events(self, query="", source="", kind="", host_id="", limit=200, offset=0):
        self._page(limit, offset)
        clause, values = self._where(query, source, kind, host_id)
        return [
            json.loads(row[0])
            for row in self.db.execute(
                "SELECT data FROM host_events WHERE "
                + clause
                + " ORDER BY coalesce(timestamp,ingested_at) DESC,id LIMIT ? OFFSET ?",
                (*values, limit, offset),
            )
        ]

    def count(self, query="", source="", kind="", host_id=""):
        clause, values = self._where(query, source, kind, host_id)
        return self.db.execute(
            "SELECT count(*) FROM host_events WHERE " + clause, values
        ).fetchone()[0]

    def get_event(self, event_id):
        row = self.db.execute(
            "SELECT data FROM host_events WHERE id=?", (event_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def hosts(self, limit=1000):
        self._page(limit, 0)
        return [
            dict(
                host_id=row[0],
                hostname=row[1],
                event_count=row[2],
                first_seen=row[3],
                last_seen=row[4],
                sources=row[5].split(","),
            )
            for row in self.db.execute(
                "SELECT host_id,max(hostname),count(*),min(coalesce(timestamp,ingested_at)),max(coalesce(timestamp,ingested_at)),group_concat(DISTINCT source) FROM host_events GROUP BY host_id ORDER BY 5 DESC LIMIT ?",
                (limit,),
            )
        ]

    def _correlation_row(self, row):
        if row is None:
            return None
        result = json.loads(row[0])
        result["case_ids"] = [
            r[0]
            for r in self.db.execute(
                "SELECT case_id FROM host_case_pins WHERE correlation_id=? ORDER BY case_id",
                (result["id"],),
            )
        ]
        result["event_ids"] = [
            r[0]
            for r in self.db.execute(
                "SELECT e.id FROM host_events e JOIN host_correlation_events ce ON e.id=ce.event_id WHERE ce.correlation_id=? ORDER BY e.event_time,e.id",
                (result["id"],),
            )
        ]
        return result

    def correlations(self, limit=100, offset=0, host_id=""):
        self._page(limit, offset)
        rows = self.db.execute(
            "SELECT data FROM host_correlations WHERE (?='' OR host_id=?) ORDER BY timestamp DESC,id LIMIT ? OFFSET ?",
            (host_id, host_id, limit, offset),
        ).fetchall()
        return [self._correlation_row(row) for row in rows]

    def get_correlation(self, correlation_id):
        return self._correlation_row(
            self.db.execute(
                "SELECT data FROM host_correlations WHERE id=?", (correlation_id,)
            ).fetchone()
        )

    def correlation_events(self, correlation_id):
        return [
            json.loads(row[0])
            for row in self.db.execute(
                "SELECT e.data FROM host_events e JOIN host_correlation_events ce ON e.id=ce.event_id WHERE ce.correlation_id=? ORDER BY e.event_time,e.id",
                (correlation_id,),
            )
        ]

    def pin_correlation(self, correlation_id, case_id):
        _text(case_id, "case ID", 256, True)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self.get_correlation(correlation_id) is None:
                raise ValueError("Unknown correlation")
            self.db.execute(
                "INSERT OR IGNORE INTO host_case_pins VALUES (?,?)",
                (correlation_id, case_id),
            )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return self.get_correlation(correlation_id)

    def retain(self, days, max_events):
        if (
            type(days) is not int
            or not 0 <= days <= 3650
            or type(max_events) is not int
            or not 1 <= max_events <= 10000000
        ):
            raise ValueError("Invalid host-event retention policy")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute(
                "CREATE TEMP TABLE IF NOT EXISTS host_retained_ids(id TEXT PRIMARY KEY)"
            )
            self.db.execute("DELETE FROM host_retained_ids")
            self.db.execute(
                "INSERT OR IGNORE INTO host_retained_ids SELECT ce.event_id FROM host_correlation_events ce JOIN host_case_pins p ON p.correlation_id=ce.correlation_id"
            )
            self.db.execute(
                "CREATE TEMP TABLE IF NOT EXISTS host_remove_ids(id TEXT PRIMARY KEY)"
            )
            self.db.execute("DELETE FROM host_remove_ids")
            if days:
                cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(
                    timespec="microseconds"
                )
                self.db.execute(
                    "INSERT OR IGNORE INTO host_remove_ids SELECT id FROM host_events WHERE ingested_at<? AND id NOT IN (SELECT id FROM host_retained_ids)",
                    (cutoff,),
                )
            total = self.count()
            removed = self.db.execute(
                "SELECT count(*) FROM host_remove_ids"
            ).fetchone()[0]
            overflow = max(0, total - removed - max_events)
            if overflow:
                self.db.execute(
                    "INSERT OR IGNORE INTO host_remove_ids SELECT id FROM host_events WHERE id NOT IN (SELECT id FROM host_retained_ids) AND id NOT IN (SELECT id FROM host_remove_ids) ORDER BY ingested_at,id LIMIT ?",
                    (overflow,),
                )
            self.db.execute(
                "DELETE FROM host_correlations WHERE id IN (SELECT correlation_id FROM host_correlation_events WHERE event_id IN (SELECT id FROM host_remove_ids)) AND id NOT IN (SELECT correlation_id FROM host_case_pins)"
            )
            removed = self.db.execute(
                "DELETE FROM host_events WHERE id IN (SELECT id FROM host_remove_ids)"
            ).rowcount
            preserved = self.db.execute(
                "SELECT count(*) FROM host_retained_ids"
            ).fetchone()[0]
            stored = self.count()
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return dict(
            removed=removed,
            preserved=preserved,
            stored=stored,
            pinned_over_limit=preserved > max_events,
        )
