"""Independent bounded collection of explicitly enabled local host evidence."""

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import time

from .collector import atomic_json
from .host_events import HostEventStore
from .host_service import _process_start, _validate, load_config
from .linux_sources import local_host, read_audit, read_journal


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _snort_events(data_dir, config, checkpoint, host):
    """Only the operator-selected LIVE source is associated with this local host."""
    if not config["snort_host_binding"] or not config["snort_source_id"]:
        raise ValueError(
            "Snort requires explicit binding of one live source to this host"
        )
    path = Path(data_dir) / "live/alerts.sqlite3"
    info = path.stat()
    database_identity = f"{info.st_dev}:{info.st_ino}"
    rowid = (
        checkpoint.get("rowid", 0)
        if checkpoint.get("database") == database_identity
        else 0
    )
    # URI quoting preserves literal filename delimiters. mode=ro never creates or writes the database.
    with sqlite3.connect(
        path.resolve().as_uri() + "?mode=ro", uri=True, timeout=3
    ) as database:
        source = database.execute(
            "SELECT mode FROM sources WHERE id=?", (config["snort_source_id"],)
        ).fetchone()
        if not source or source[0] != "live":
            raise ValueError("Selected Snort source is missing or is not a live source")
        if rowid:
            prior = database.execute(
                "SELECT id FROM events WHERE rowid=?", (rowid,)
            ).fetchone()
            if not prior or prior[0] != checkpoint.get("last_id"):
                rowid = 0  # Retention/rebuild may reuse SQLite implicit rowids; event IDs deduplicate.
        rows = database.execute(
            "SELECT rowid,id,data FROM events WHERE source_id=? AND mode='live' AND rowid>? ORDER BY rowid LIMIT 500",
            (config["snort_source_id"], rowid),
        ).fetchall()
    events = []
    for sequence, original_id, raw in rows:
        original = json.loads(raw)
        events.append(
            {
                **original,
                "event_id": original_id,
                "original_id": original_id,
                "source": "snort",
                "kind": "network_alert",
                "host_id": host["host_id"],
                "hostname": host["hostname"],
                "host_bound": True,
                "src_ip": original.get("src"),
                "dst_ip": original.get("dst"),
                "raw_record": original,
                "binding_source_id": config["snort_source_id"],
            }
        )
        rowid = sequence
    return (
        events,
        dict(
            rowid=rowid,
            database=database_identity,
            last_id=rows[-1][1] if rows else checkpoint.get("last_id"),
        ),
        dict(
            state="following",
            examined=len(rows),
            backlog=len(rows) == 500,
            binding_source_id=config["snort_source_id"],
            host_bound=True,
        ),
    )


def collect_once(
    data_dir, config=None, *, journal_reader=None, audit_reader=None, retain=True
):
    """One bounded batch per enabled source; usable for fixtures and VM verification."""
    config = _validate(config) if config is not None else load_config(data_dir)
    directory = Path(data_dir) / "live"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    host = local_host()
    store = HostEventStore(directory / "host-events.sqlite3")
    statuses = {}
    try:
        for source in ("journal", "audit", "snort"):
            if not config[source + "_enabled"]:
                statuses[source] = dict(state="disabled", inserted=0)
                continue
            identity = (
                config["audit_path"]
                if source == "audit"
                else config["snort_source_id"]
                if source == "snort"
                else host["host_id"]
            )
            key = source + ":" + hashlib.sha256(identity.encode()).hexdigest()
            checkpoint = store.checkpoint(key) or {}
            try:
                if source == "journal":
                    events, cursor, status = (journal_reader or read_journal)(
                        checkpoint, host
                    )
                elif source == "audit":
                    events, cursor, status = (audit_reader or read_audit)(
                        config["audit_path"], checkpoint, host
                    )
                else:
                    events, cursor, status = _snort_events(
                        data_dir, config, checkpoint, host
                    )
                result = store.ingest(events, checkpoint_key=key, checkpoint=cursor)
                statuses[source] = {**status, **result}
                if result.get("rejected"):
                    statuses[source]["error"] = (
                        status.get("error", "")
                        + " Some events were quarantined by validation"
                    ).strip()
            except PermissionError as exc:
                statuses[source] = dict(
                    state="permission_denied", error=str(exc), inserted=0
                )
            except FileNotFoundError as exc:
                statuses[source] = dict(state="unavailable", error=str(exc), inserted=0)
            except (OSError, ValueError, sqlite3.Error, TimeoutError) as exc:
                statuses[source] = dict(state="error", error=str(exc), inserted=0)
        work = store.ingest(
            []
        )  # Drain a bounded amount of durable correlation work even while sources are idle.
        retention = (
            store.retain(config["retention_days"], config["max_events"])
            if retain
            else {}
        )
        stored = store.count()
    finally:
        store.close()
    enabled = [status for status in statuses.values() if status["state"] != "disabled"]
    healthy = {"following", "reading_existing_log"}
    state = (
        "disabled"
        if not enabled
        else "running"
        if all(s["state"] in healthy and not s.get("error") for s in enabled)
        else "degraded"
    )
    return dict(
        state=state,
        data_dir=str(Path(data_dir).resolve()),
        sources=statuses,
        host=host,
        stored=stored,
        retention=retention,
        correlation_pending=work.get("correlation_pending", 0),
        heartbeat=_utc_now(),
        pid=os.getpid(),
        boot_id=host["boot_id"],
        process_start=_process_start(os.getpid()),
    )


def collect(data_dir, stop, interval=3):
    directory = Path(data_dir) / "live"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / "host-collector.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        last_retention = 0
        status = {}
        try:
            while not stop():
                started = time.monotonic()
                try:
                    status = collect_once(
                        data_dir, retain=started - last_retention >= 3600
                    )
                    if started - last_retention >= 3600:
                        last_retention = started
                except (OSError, ValueError, sqlite3.Error) as exc:
                    status = dict(
                        state="error",
                        data_dir=str(Path(data_dir).resolve()),
                        error=str(exc),
                        heartbeat=_utc_now(),
                        pid=os.getpid(),
                        boot_id=local_host()["boot_id"],
                        process_start=_process_start(os.getpid()),
                        sources={},
                    )
                atomic_json(directory / "host-collector-health.json", status)
                while not stop() and time.monotonic() - started < interval:
                    time.sleep(0.2)
        finally:
            status.update(state="stopped", heartbeat=_utc_now())
            atomic_json(directory / "host-collector-health.json", status)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument(
        "--once",
        action="store_true",
        help="Collect one batch and print diagnostic JSON",
    )
    args = parser.parse_args()
    if args.once:
        print(json.dumps(collect_once(args.data_dir), ensure_ascii=False))
        return
    stopping = False

    def stop_signal(_signal, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    collect(args.data_dir, lambda: stopping)


if __name__ == "__main__":
    main()
