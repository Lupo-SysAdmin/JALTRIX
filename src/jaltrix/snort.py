"""Read-only Snort JSON ingestion with transactional checkpoints and provenance."""

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import uuid
from contextlib import nullcontext
import stat as stat_module

MAX_LINE = 1024 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def endpoint(record, direction):
    address = record.get(direction + "_addr")
    port = record.get(direction + "_port")
    if address is None:
        value = record.get(direction + "_ap")
        if value:
            # Snort's *_ap fields are address:port, including unbracketed IPv6.
            host, sep, tail = str(value).rpartition(":")
            if sep and tail.isdigit():
                try:
                    address = str(ipaddress.ip_address(host.strip("[]")))
                    port = int(tail)
                except ValueError:
                    address = str(ipaddress.ip_address(value))
            else:
                address = str(ipaddress.ip_address(value))
    if address is not None:
        address = str(ipaddress.ip_address(address))
    if port is not None:
        if (
            isinstance(port, bool)
            or not str(port).isdigit()
            or not 0 <= int(port) <= 65535
        ):
            raise ValueError("invalid port")
        port = int(port)
    return address, port


def normalize(raw, source_id, generation, offset, mode, source_path):
    if mode not in ("live", "replay"):
        raise ValueError("invalid mode")
    record = json.loads(raw)
    if not isinstance(record, dict):
        raise ValueError("event must be a JSON object")
    if not any(
        k in record for k in ("rule", "timestamp", "seconds", "src_ap", "src_addr")
    ):
        raise ValueError("not a Snort alert record")
    rule = record.get("rule")
    gid = sid = rev = None
    if rule is not None:
        if not isinstance(rule, str) or not re.fullmatch(r"\d+:\d+:\d+", rule):
            raise ValueError("invalid gid:sid:rev")
        gid, sid, rev = map(int, rule.split(":"))
    src, src_port = endpoint(record, "src")
    dst, dst_port = endpoint(record, "dst")
    timestamp, confidence = None, "unknown"
    if "seconds" in record:
        if isinstance(record["seconds"], bool):
            raise ValueError("invalid epoch")
        timestamp = datetime.fromtimestamp(
            float(record["seconds"]), timezone.utc
        ).isoformat()
        confidence = "epoch_seconds"
    elif isinstance(record.get("timestamp"), str):
        try:
            dt = datetime.fromisoformat(record["timestamp"])
            if dt.tzinfo is not None:
                timestamp = dt.astimezone(timezone.utc).isoformat()
                confidence = "explicit_timezone"
        except ValueError:
            pass  # Preserve yearless Snort timestamps; never silently guess a year/timezone.
    priority = record.get("priority")
    if priority is not None:
        if isinstance(priority, bool) or not str(priority).isdigit():
            raise ValueError("invalid priority")
        priority = int(priority)
    identity = f"{source_id}:{generation}:{offset}"
    observed = utc_now()
    return dict(
        event_id=hashlib.sha256(identity.encode()).hexdigest(),
        source_id=source_id,
        generation=generation,
        offset=offset,
        mode=mode,
        timestamp=timestamp,
        original_timestamp=record.get("timestamp"),
        timestamp_confidence=confidence,
        ingested_at=observed,
        observed_at=timestamp,
        gid=gid,
        rule_sid=sid,
        rev=rev,
        sid=rule or "—",
        src=src or "—",
        dst=dst or "—",
        src_port=src_port,
        dst_port=dst_port,
        priority=priority,
        severity={1: "Alta", 2: "Media", 3: "Baja"}.get(priority, "Sin información"),
        message=str(record.get("msg", "—")),
        classification=record.get("class"),
        category="Sin información",
        protocol=str(record.get("proto", "—")),
        action=str(record.get("action", "Sin información")),
        sensor=source_id[:12],
        source=str(source_path),
        raw_record=record,
        triage="Nuevo",
        time=datetime.fromisoformat(timestamp).strftime("%H:%M:%S")
        if timestamp
        else "—",
    )


class AlertStore:
    """One connection per thread. Source/checkpoint and records commit atomically."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.path)
        self.path.chmod(0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS sources (
                id TEXT PRIMARY KEY, path TEXT, mode TEXT, device INTEGER, inode INTEGER,
                generation TEXT, offset INTEGER, tail_digest TEXT);
            CREATE INDEX IF NOT EXISTS source_path_mode ON sources(path,mode);
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, source_id TEXT, mode TEXT, timestamp TEXT,
                src TEXT, dst TEXT, sid TEXT, severity TEXT, data TEXT);
            CREATE INDEX IF NOT EXISTS event_time ON events(timestamp);
            CREATE INDEX IF NOT EXISTS event_source_time ON events(mode,source_id,timestamp);
            CREATE INDEX IF NOT EXISTS event_src ON events(src);
            CREATE INDEX IF NOT EXISTS event_sid ON events(sid);
            CREATE INDEX IF NOT EXISTS event_rule_sid ON events(mode,json_extract(data,'$.rule_sid'));
            CREATE INDEX IF NOT EXISTS event_source_rule_sid ON events(mode,source_id,json_extract(data,'$.rule_sid'));
            CREATE TABLE IF NOT EXISTS quarantine (
                source_id TEXT, generation TEXT, offset INTEGER, reason TEXT, raw BLOB,
                PRIMARY KEY(source_id, generation, offset));
        """)

    @staticmethod
    def tail_digest(file, offset):
        file.seek(max(0, offset - 128))
        return hashlib.sha256(file.read(min(128, offset))).hexdigest()

    def source_id(self, path, mode):
        """Retain checkpoints/event IDs when a migrated path has a legacy alias."""
        path = Path(path).resolve()
        known = self.db.execute(
            "SELECT id FROM sources WHERE path=? AND mode=?", (str(path), mode)
        ).fetchone()
        if known:
            return known[0]
        matches = [
            identity
            for identity, previous in self.db.execute(
                "SELECT id,path FROM sources WHERE mode=?", (mode,)
            )
            if Path(previous).resolve() == path
        ]
        if len(matches) > 1:
            raise ValueError(
                "Multiple source histories resolve to this file; refusing ambiguous merge"
            )
        return (
            matches[0]
            if matches
            else hashlib.sha256(f"{mode}:{path}".encode()).hexdigest()
        )

    def ingest(self, path, mode="replay", limit=2000, stream=None):
        path = Path(path).resolve(strict=stream is None)
        if stream is None and not path.is_file():
            raise ValueError("source must be a regular file")
        source_id = self.source_id(path, mode)
        inserted = rejected = 0
        with (
            nullcontext(stream) if stream is not None else path.open("rb") as file,
            self.db,
        ):
            import os

            # Serialize all writers (GUI and independent collector) before reading the checkpoint.
            self.db.execute("BEGIN IMMEDIATE")
            stat = os.fstat(file.fileno())
            if not stat_module.S_ISREG(stat.st_mode):
                raise ValueError("Source must be a regular file")
            previous = self.db.execute(
                "SELECT device,inode,generation,offset,tail_digest FROM sources WHERE id=?",
                (source_id,),
            ).fetchone()
            generation, offset = uuid.uuid4().hex, 0
            if previous:
                device, inode, prior_generation, prior_offset, digest = previous
                if (
                    (device, inode) == (stat.st_dev, stat.st_ino)
                    and stat.st_size >= prior_offset
                    and self.tail_digest(file, prior_offset) == digest
                ):
                    generation, offset = prior_generation, prior_offset
            file.seek(offset)
            for _ in range(limit):
                start = file.tell()
                raw = file.readline(MAX_LINE + 1)
                if not raw:
                    break
                if len(raw) > MAX_LINE:
                    # Quarantine bounded sample, discard rest incrementally without unbounded allocation.
                    while raw and not raw.endswith(b"\n"):
                        raw = file.readline(MAX_LINE + 1)
                    end = file.tell()
                    self.db.execute(
                        "INSERT OR IGNORE INTO quarantine VALUES (?,?,?,?,?)",
                        (source_id, generation, start, "line exceeds 1 MiB", b""),
                    )
                    rejected += 1
                    offset = end
                    continue
                if not raw.endswith(b"\n"):
                    break  # Incomplete record: retry from same offset on append/restart.
                offset = file.tell()
                try:
                    data = normalize(
                        raw.decode("utf-8"), source_id, generation, start, mode, path
                    )
                    cursor = self.db.execute(
                        "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?)",
                        (
                            data["event_id"],
                            source_id,
                            mode,
                            data["timestamp"],
                            data["src"],
                            data["dst"],
                            data["sid"],
                            data["severity"],
                            json.dumps(data),
                        ),
                    )
                    inserted += cursor.rowcount
                except (
                    ValueError,
                    TypeError,
                    OverflowError,
                    UnicodeDecodeError,
                ) as exc:
                    self.db.execute(
                        "INSERT OR IGNORE INTO quarantine VALUES (?,?,?,?,?)",
                        (source_id, generation, start, str(exc), raw),
                    )
                    rejected += 1
            digest = self.tail_digest(file, offset)
            self.db.execute(
                "INSERT OR REPLACE INTO sources VALUES (?,?,?,?,?,?,?,?)",
                (
                    source_id,
                    str(path),
                    mode,
                    stat.st_dev,
                    stat.st_ino,
                    generation,
                    offset,
                    digest,
                ),
            )
        return dict(
            inserted=inserted,
            rejected=rejected,
            source_id=source_id,
            offset=offset,
            more=offset < stat.st_size,
            source=str(path),
        )

    def finish_rotated_fragment(self, source_id, stream):
        row = self.db.execute(
            "SELECT generation,offset FROM sources WHERE id=?", (source_id,)
        ).fetchone()
        if not row:
            return 0
        generation, offset = row
        stream.seek(offset)
        raw = stream.read(MAX_LINE + 1)
        if not raw or raw.endswith(b"\n") or len(raw) > MAX_LINE:
            return 0
        end = stream.tell()
        digest = self.tail_digest(stream, end)
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO quarantine VALUES (?,?,?,?,?)",
                (
                    source_id,
                    generation,
                    offset,
                    "Unterminated fragment in rotated source after grace period",
                    raw,
                ),
            )
            self.db.execute(
                "UPDATE sources SET offset=?,tail_digest=? WHERE id=?",
                (end, digest, source_id),
            )
        return end

    def events(self, mode, limit=10000, source_id=None):
        # Bound UI snapshot; the durable database retains all records.
        rows, size = [], 0
        for (raw,) in self.db.execute(
            "SELECT data FROM events WHERE mode=? AND (? IS NULL OR source_id=?) ORDER BY rowid DESC LIMIT ?",
            (mode, source_id, source_id, limit),
        ):
            size += len(raw.encode("utf-8"))
            if size > 16 * 1024 * 1024:
                break
            rows.append(json.loads(raw))
        return rows

    def count(self, mode, source_id=None):
        return self.db.execute(
            "SELECT COUNT(*) FROM events WHERE mode=? AND (? IS NULL OR source_id=?)",
            (mode, source_id, source_id),
        ).fetchone()[0]

    def close(self):
        self.db.close()

    def _where(
        self,
        mode,
        source_id=None,
        query="",
        severity="Todas",
        minutes=1440,
        category="Todas",
    ):
        """Bounded SQL page over the full source, including records outside the old snapshot."""
        import shlex
        from datetime import timedelta

        if mode not in ("live", "replay"):
            raise ValueError("Invalid query bounds")

        def contains_network(address, cidr):
            try:
                return int(
                    ipaddress.ip_address(address)
                    in ipaddress.ip_network(cidr, strict=False)
                )
            except ValueError:
                return 0

        self.db.create_function("in_network", 2, contains_network, deterministic=True)

        def fold(value):
            text = str(value or "")
            if text.startswith("{"):
                text = json.dumps(json.loads(text), ensure_ascii=False)
            return text.casefold()

        self.db.create_function("fold", 1, fold, deterministic=True)
        where, values = ["mode=?"], [mode]
        if source_id:
            where.append("source_id=?")
            values.append(source_id)
        if severity != "Todas":
            where.append("severity=?")
            values.append(severity)
        if category != "Todas":
            where.append(
                "coalesce(nullif(json_extract(data,'$.classification'),''),'Sin información')=?"
            )
            values.append(category)
        anchor = (
            utc_now()
            if mode == "live"
            else self.db.execute(
                "SELECT max(timestamp) FROM events WHERE mode=? AND (? IS NULL OR source_id=?)",
                (mode, source_id, source_id),
            ).fetchone()[0]
        )
        if anchor and minutes > 0:
            cutoff = (
                datetime.fromisoformat(anchor) - timedelta(minutes=minutes)
            ).isoformat()
            where.append("(timestamp IS NULL OR timestamp>=?)")
            values.append(cutoff)
        fields = {
            "src": "src",
            "dst": "dst",
            "sid": "sid",
            "gid": "json_extract(data,'$.gid')",
            "proto": "json_extract(data,'$.protocol')",
            "port": "json_extract(data,'$.src_port')",
        }
        for token in shlex.split(query):
            key, sep, value = token.partition(":")
            if sep and key in ("src", "dst"):
                network = str(ipaddress.ip_network(value, strict=False))
                where.append(f"in_network({key},?)")
                values.append(network)
            elif sep and key in fields:
                if key == "port":
                    if not value.isdigit() or not 0 <= int(value) <= 65535:
                        raise ValueError("Invalid port")
                    where.append(
                        "(json_extract(data,'$.src_port')=? OR json_extract(data,'$.dst_port')=?)"
                    )
                    values.extend([int(value), int(value)])
                elif key == "sid" and value.isdigit():
                    where.append("json_extract(data,'$.rule_sid')=?")
                    values.append(int(value))
                elif key == "gid":
                    if not value.isdigit():
                        raise ValueError("Invalid GID")
                    where.append(fields[key] + "=?")
                    values.append(int(value))
                else:
                    where.append(f"instr(fold({fields[key]}),?)>0")
                    values.append(value.casefold())
            elif "/" in token:
                network = str(ipaddress.ip_network(token, strict=False))
                where.append("(in_network(src,?) OR in_network(dst,?))")
                values.extend([network, network])
            else:
                where.append("instr(fold(data),?)>0")
                values.append(token.casefold())
        clause = " AND ".join(where)
        return clause, values

    def iter_query(
        self,
        mode,
        source_id=None,
        query="",
        severity="Todas",
        minutes=1440,
        category="Todas",
    ):
        clause, values = self._where(
            mode, source_id, query, severity, minutes, category
        )
        self.db.execute("BEGIN")
        try:
            for (raw,) in self.db.execute(
                "SELECT data FROM events WHERE " + clause + " ORDER BY rowid DESC",
                values,
            ):
                yield json.loads(raw)
        finally:
            self.db.rollback()

    def query(
        self,
        mode,
        source_id=None,
        query="",
        severity="Todas",
        minutes=1440,
        offset=0,
        limit=500,
        category="Todas",
    ):
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("Invalid query bounds")
        clause, values = self._where(
            mode, source_id, query, severity, minutes, category
        )
        # A read transaction gives count and rows a consistent snapshot while the collector writes.
        self.db.execute("BEGIN")
        try:
            count = self.db.execute(
                "SELECT count(*) FROM events WHERE " + clause, values
            ).fetchone()[0]
            rows, size = [], 0
            for (raw,) in self.db.execute(
                "SELECT data FROM events WHERE "
                + clause
                + " ORDER BY rowid DESC LIMIT ? OFFSET ?",
                values + [limit, offset],
            ):
                size += len(raw.encode())
                if size > 16 * 1024 * 1024:
                    break
                rows.append(json.loads(raw))
            return dict(
                events=rows,
                matched=count,
                offset=offset,
                limit=limit,
                next_offset=offset + len(rows),
            )
        finally:
            self.db.rollback()

    def categories(
        self, mode, source_id=None, query="", severity="Todas", minutes=1440
    ):
        clause, values = self._where(mode, source_id, query, severity, minutes)
        rows = self.db.execute(
            "SELECT coalesce(nullif(json_extract(data,'$.classification'),''),'Sin información'),count(*) FROM events WHERE "
            + clause
            + " GROUP BY 1 ORDER BY count(*) DESC,1",
            values,
        )
        return [dict(label=label, count=count) for label, count in rows]

    def retain(self, before, mode="live", protected=()):
        """Explicit retention by ingestion time; leave checkpoints to prevent reimport."""
        parsed = datetime.fromisoformat(before)
        if parsed.tzinfo is None or parsed > datetime.now(timezone.utc):
            raise ValueError("Retention cutoff must be a past timezone-aware timestamp")
        if mode not in ("live", "replay"):
            raise ValueError("Invalid retention mode")
        with self.db:
            self.db.execute(
                "CREATE TEMP TABLE IF NOT EXISTS retained_case_events (id TEXT PRIMARY KEY)"
            )
            self.db.execute("DELETE FROM retained_case_events")
            self.db.executemany(
                "INSERT OR IGNORE INTO retained_case_events VALUES (?)",
                ((value,) for value in protected),
            )
            return self.db.execute(
                "DELETE FROM events WHERE mode=? AND json_extract(data,'$.ingested_at')<? AND id NOT IN (SELECT id FROM retained_case_events)",
                (mode, parsed.astimezone(timezone.utc).isoformat()),
            ).rowcount
