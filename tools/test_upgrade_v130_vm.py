"""Verify installed 1.2 -> 1.3 evidence compatibility in disposable lab data."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

sys.path.insert(0, "/usr/lib/jaltrix")
from jaltrix import __version__
from jaltrix.backup import create_backup, restore_backup
from jaltrix.core import CaseStore
from jaltrix.snort import AlertStore
from jaltrix.triage import TriageStore

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("phase", choices=("before", "after"))
parser.add_argument("--data-dir", required=True, type=Path)
args = parser.parse_args()
root = args.data_dir.resolve()
expected_version = "1.2.0" if args.phase == "before" else "1.3.0"
if __version__ != expected_version:
    raise SystemExit(f"Expected installed {expected_version}, got {__version__}")
if args.phase == "before":
    root.mkdir(mode=0o700)  # Never overwrite an existing fixture or user directory.
    (root / "alerts.json").write_text(
        '{"rule":"1:42:1","src_addr":"192.0.2.1","msg":"Upgrade evidence",'
        '"seconds":1794484800}\n'
    )
    (root / "settings.ini").write_text("[General]\nlanguage=en-US\n")
source = root / "alerts.json"
expected = {}
for mode in ("live", "replay"):
    alerts = AlertStore(root / mode / "alerts.sqlite3")
    cases = CaseStore(root / mode / "cases.sqlite3", mode=mode)
    triage = TriageStore(root / mode / "triage.sqlite3")
    try:
        inserted = alerts.ingest(source, mode)["inserted"]
        assert inserted == (1 if args.phase == "before" else 0)
        event = alerts.query(mode)["events"][0]
        if args.phase == "before":
            case_id = cases.create(event)
            cases.update(case_id, "Preserve case notes", "investigating")
            triage.save(
                event["event_id"],
                0,
                "investigating",
                "Preserve triage",
                ["upgrade"],
                True,
            )
        expected[mode] = {
            "event_id": event["event_id"],
            "events": alerts.count(mode),
            "cases": cases.list(),
            "triage": triage.get(event["event_id"]),
        }
    finally:
        alerts.close()
        cases.close()
        triage.close()
if args.phase == "before":
    (root / "expected.json").write_text(json.dumps(expected, indent=2))
else:
    assert expected == json.loads((root / "expected.json").read_text())
    # Create/use the additional store without touching original Snort databases.
    from jaltrix.host_events import HostEventStore

    host = HostEventStore(root / "live/host-events.sqlite3")
    host.ingest([])
    host.close()
    with tempfile.TemporaryDirectory(prefix="jaltrix-upgrade-backup-") as temporary:
        archive = Path(temporary) / "backup.zip"
        restored = Path(temporary) / "restored"
        create_backup(root, archive)
        restore_backup(archive, restored)
        for mode in ("live", "replay"):
            with sqlite3.connect(restored / mode / "alerts.sqlite3") as db:
                assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
        assert (restored / "settings.ini").read_bytes() == (
            root / "settings.ini"
        ).read_bytes()
        with sqlite3.connect(restored / "live/host-events.sqlite3") as db:
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
print(
    json.dumps(
        {
            "phase": args.phase,
            "version": __version__,
            "result": "PASS",
            "checks": [
                "event IDs",
                "checkpoints",
                "cases/history",
                "triage",
                "live/replay separation",
            ]
            + (
                ["new host store", "backup and restore"]
                if args.phase == "after"
                else []
            ),
        }
    )
)
