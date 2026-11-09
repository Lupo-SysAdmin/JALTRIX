"""Atomic streaming exports of a consistent SQLite alert query."""

import csv, hashlib, json, os, tempfile
from pathlib import Path
from .snort import AlertStore
from .triage import TriageStore

FIELDS = [
    "event_id",
    "mode",
    "timestamp",
    "original_timestamp",
    "timestamp_confidence",
    "sid",
    "src",
    "src_port",
    "dst",
    "dst_port",
    "protocol",
    "message",
    "severity",
    "action",
    "source",
    "triage",
    "notes",
    "tags",
    "bookmark",
]


def export_query(data_dir, mode, source, filters, destination, metadata):
    path = Path(destination)
    source_id = hashlib.sha256(f"{mode}:{Path(source).resolve()}".encode()).hexdigest()
    store = AlertStore(Path(data_dir) / mode / "alerts.sqlite3")
    triage = TriageStore(Path(data_dir) / mode / "triage.sqlite3")
    triage.db.execute("BEGIN")
    temp = None
    count = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=path.name + ".",
            delete=False,
        ) as stream:
            temp = Path(stream.name)
            if path.suffix.lower() == ".csv":
                writer = csv.DictWriter(stream, fieldnames=FIELDS)
                writer.writeheader()
            else:
                stream.write(
                    json.dumps(
                        dict(metadata, scope="entire_matching_source"),
                        ensure_ascii=False,
                    )[:-1]
                    + ',"events":[\n'
                )
            for event in store.iter_query(
                mode,
                source_id,
                filters["query"],
                filters["severity"],
                filters["minutes"],
            ):
                state = triage.get(event["event_id"])
                event.update(
                    triage=state["state"],
                    notes=state["notes"],
                    tags=state["tags"],
                    bookmark=state["bookmark"],
                )
                if path.suffix.lower() == ".csv":
                    row = {}
                    for field in FIELDS:
                        value = str(
                            event.get(field) if event.get(field) is not None else ""
                        )
                        row[field] = (
                            "'" + value
                            if value.lstrip().startswith(("=", "+", "-", "@"))
                            else value
                        )
                    writer.writerow(row)
                else:
                    if count:
                        stream.write(",\n")
                    stream.write(json.dumps(event, ensure_ascii=False))
                count += 1
            if path.suffix.lower() != ".csv":
                stream.write('\n],"exported_count":' + str(count) + "}\n")
            stream.flush()
            os.fsync(stream.fileno())
        temp.replace(path)
        temp = None
        if path.suffix.lower() == ".csv":
            from .collector import atomic_json

            atomic_json(
                path.with_suffix(path.suffix + ".metadata.json"),
                dict(metadata, scope="entire_matching_source", exported_count=count),
            )
        return dict(kind="export", count=count, path=str(path))
    finally:
        if temp:
            temp.unlink(missing_ok=True)
        triage.close()
        store.close()
