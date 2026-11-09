"""Independent, single-writer collector. No Qt, network listener or root required."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import time
from datetime import datetime, timedelta, timezone
from .core import CaseStore
from .snort import AlertStore, utc_now


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def open_source(source, store):
    source = Path(source)
    source_id = store.source_id(source, "live")
    previous = store.db.execute(
        "SELECT device,inode,offset FROM sources WHERE id=?", (source_id,)
    ).fetchone()
    candidate = source
    if previous:
        try:
            current = source.stat()
        except FileNotFoundError:
            current = None
        if current is None or (current.st_dev, current.st_ino) != previous[:2]:
            # Recover a still-retained renamed file before following the replacement.
            for index, entry in enumerate(source.parent.iterdir()):
                if index >= 1000:
                    break
                try:
                    info = entry.lstat()
                except FileNotFoundError:
                    continue
                if (
                    stat.S_ISREG(info.st_mode)
                    and (info.st_dev, info.st_ino) == previous[:2]
                    and info.st_size > previous[2]
                ):
                    candidate = entry
                    break
    fd = os.open(candidate, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("Source must be a regular file")
    return os.fdopen(fd, "rb")


def collect(data_dir, stop, interval=0.5):
    directory = Path(data_dir) / "live"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / "collector.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = AlertStore(directory / "alerts.sqlite3")
        inserted = rejected = 0
        last_retention = 0
        stream = None
        stream_source = None
        rotated_partial = None
        try:
            while not stop():
                started = time.monotonic()
                health = dict(pid=os.getpid(), heartbeat=utc_now(), state="error")
                try:
                    config = json.loads((directory / "collector.json").read_text())
                    if not isinstance(config, dict) or not isinstance(
                        config.get("source"), str
                    ):
                        raise ValueError("Invalid collector source configuration")
                    source = Path(config["source"]).resolve()
                    if stream is None or stream_source != source:
                        if stream is not None:
                            stream.close()
                        stream = None
                        stream = open_source(source, store)
                        stream_source = source
                    result = store.ingest(source, "live", limit=5000, stream=stream)
                    held = os.fstat(stream.fileno())
                    try:
                        current = source.stat()
                    except FileNotFoundError:
                        current = None
                    rotating = current and (current.st_dev, current.st_ino) != (
                        held.st_dev,
                        held.st_ino,
                    )
                    if (
                        rotating
                        and result["more"]
                        and not result["inserted"]
                        and not result["rejected"]
                    ):
                        identity = (held.st_ino, held.st_size)
                        if not rotated_partial or rotated_partial[:2] != identity:
                            rotated_partial = (*identity, time.monotonic())
                        elif time.monotonic() - rotated_partial[2] >= 2:
                            end = store.finish_rotated_fragment(
                                result["source_id"], stream
                            )
                            if end:
                                result.update(offset=end, rejected=1, more=False)
                    else:
                        rotated_partial = None
                    if (
                        current
                        and (current.st_dev, current.st_ino)
                        != (held.st_dev, held.st_ino)
                        and result["offset"] >= held.st_size
                    ):
                        stream.close()
                        stream = None
                    inserted += result["inserted"]
                    rejected += result["rejected"]
                    days = config.get("retention_days", 0)
                    if type(days) is not int or not 0 <= days <= 3650:
                        raise ValueError("Invalid retention period")
                    if days and time.monotonic() - last_retention > 3600:
                        cases = CaseStore(directory / "cases.sqlite3", mode="live")
                        try:
                            protected = [c["event_id"] for c in cases.list()]
                        finally:
                            cases.close()
                        removed = store.retain(
                            (
                                datetime.now(timezone.utc) - timedelta(days=days)
                            ).isoformat(),
                            protected=protected,
                        )
                        health["retention_removed"] = removed
                        last_retention = time.monotonic()
                    health.update(
                        state="source_missing"
                        if current is None
                        else "reading"
                        if result["more"]
                        else "following",
                        source=str(source),
                        source_id=result["source_id"],
                        offset=result["offset"],
                        more=result["more"],
                        inserted=inserted,
                        rejected=rejected,
                        stored=store.count("live", result["source_id"]),
                        batch_seconds=round(time.monotonic() - started, 6),
                    )
                except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
                    health["error"] = str(exc)
                atomic_json(directory / "collector-health.json", health)
                if (
                    not health.get("more")
                    or health.get("offset") == 0
                    or not result.get("inserted", 0)
                ):
                    time.sleep(interval)
        finally:
            if stream is not None:
                stream.close()
            store.close()
            atomic_json(
                directory / "collector-health.json",
                dict(state="stopped", heartbeat=utc_now(), pid=os.getpid()),
            )


def main():
    parser = argparse.ArgumentParser(description="JALTRIX independent alert collector")
    parser.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    stopping = False

    def halt(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, halt)
    signal.signal(signal.SIGINT, halt)
    collect(args.data_dir, lambda: stopping)


if __name__ == "__main__":
    main()
