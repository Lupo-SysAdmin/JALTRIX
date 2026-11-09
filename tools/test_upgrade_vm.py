"""Seed 0.4 data and verify that a native 1.0 package upgrade preserves it."""

from pathlib import Path
import argparse, json, platform, sys

assert platform.node().startswith("jaltrix-"), "Disposable VM only"
sys.path.insert(0, "/usr/lib/jaltrix")
from jaltrix.snort import AlertStore
from jaltrix.core import CaseStore
from jaltrix.triage import TriageStore

parser = argparse.ArgumentParser()
parser.add_argument("phase", choices=["before", "after"])
args = parser.parse_args()
root = Path.home() / "upgrade-validation"
root.mkdir(exist_ok=True)
source = root / "alerts.json"
database = root / "replay/alerts.sqlite3"
store = AlertStore(database)
cases = CaseStore(root / "replay/cases.sqlite3", mode="replay")
triage = TriageStore(root / "replay/triage.sqlite3")
try:
    if args.phase == "before":
        source.write_text(
            '{"rule":"1:42:1","src_addr":"192.0.2.1","msg":"upgrade evidence"}\n'
        )
        store.ingest(source)
        event = store.query("replay")["events"][0]
        case = cases.create(event)
        triage.save(
            event["event_id"],
            0,
            "investigating",
            "Preserve this note",
            ["upgrade"],
            True,
        )
        (root / "expected.json").write_text(
            json.dumps({"event": event["event_id"], "case": case})
        )
    else:
        expected = json.loads((root / "expected.json").read_text())
        event = store.query("replay")["events"][0]
        assert (
            event["event_id"] == expected["event"]
            and event["message"] == "upgrade evidence"
        )
        assert store.ingest(source)["inserted"] == 0
        assert cases.list()[0]["id"] == expected["case"]
        assert triage.get(event["event_id"])["notes"] == "Preserve this note"
        assert triage.get(event["event_id"])["bookmark"]
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "scope": "native package upgrade 0.4 to 1.0",
                    "hostname": platform.node(),
                    "checks": [
                        "events",
                        "checkpoints",
                        "cases",
                        "triage notes and bookmarks",
                    ],
                }
            )
        )
finally:
    triage.close()
    cases.close()
    store.close()
