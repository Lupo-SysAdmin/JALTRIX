"""Verify a real package replacement against the installed legacy distribution."""

import argparse
import hashlib
import importlib
import json
from pathlib import Path
import platform
import subprocess
import sys

assert platform.node().startswith("jaltrix-"), "Disposable VM only"
parser = argparse.ArgumentParser()
parser.add_argument("phase", choices=["before", "after"])
args = parser.parse_args()
before = args.phase == "before"
sys.path.insert(0, "/usr/lib/snort-soc-desktop" if before else "/usr/lib/jaltrix")
module = "snort_soc" if before else "jaltrix"
AlertStore = importlib.import_module(module + ".snort").AlertStore
CaseStore = importlib.import_module(module + ".core").CaseStore
TriageStore = importlib.import_module(module + ".triage").TriageStore
root = Path.home() / ".local/share" / ("snort-soc-desktop" if before else "jaltrix")
expected_path = Path.home() / "rename-expected.json"


def state(unit, command):
    return subprocess.run(
        ["systemctl", command, unit], capture_output=True, text=True
    ).stdout.strip()


if not before:
    importlib.import_module("jaltrix.migration").user_data_dir()
    assert not Path("/usr/bin/snort-soc").exists()
    assert not Path(
        "/usr/share/applications/io.github.LupoSysAdmin.SnortSOC.desktop"
    ).exists()
    assert Path("/usr/bin/jaltrix").is_file()
    assert Path(
        "/usr/share/applications/io.github.LupoSysAdmin.Jaltrix.desktop"
    ).is_file()
root.mkdir(parents=True, exist_ok=True)
source = root / "rename-evidence.json"
store = AlertStore(root / "replay/alerts.sqlite3")
cases = CaseStore(root / "replay/cases.sqlite3", mode="replay")
triage = TriageStore(root / "replay/triage.sqlite3")
try:
    if before:
        source.write_text('{"rule":"1:987654:1","msg":"rename evidence"}\n')
        identity = store.ingest(source)["source_id"]
        event = store.query("replay", source_id=identity)["events"][0]
        case = cases.create(event)
        triage.save(
            event["event_id"], 0, "investigating", "Keep rename note", ["rename"], True
        )
        unit = Path("/etc/systemd/system/snort-soc.service")
        expected = dict(
            event=event["event_id"], case=case, source=identity, sensor=unit.exists()
        )
        if unit.exists():
            expected.update(
                active=state(unit.name, "is-active"),
                enabled=state(unit.name, "is-enabled"),
                rules=hashlib.sha256(
                    Path("/etc/snort-soc/local.rules").read_bytes()
                ).hexdigest(),
            )
        expected_path.write_text(json.dumps(expected))
    else:
        expected = json.loads(expected_path.read_text())
        result = store.ingest(source)
        assert result["inserted"] == 0 and result["source_id"] == expected["source"]
        event = store.query("replay", source_id=expected["source"])["events"][0]
        assert event["event_id"] == expected["event"]
        assert any(case["id"] == expected["case"] for case in cases.list())
        assert triage.get(event["event_id"])["notes"] == "Keep rename note"
        assert triage.get(event["event_id"])["bookmark"]
        if expected["sensor"]:
            assert not Path("/etc/systemd/system/snort-soc.service").exists()
            assert state("jaltrix-sensor.service", "is-active") == expected["active"]
            assert state("jaltrix-sensor.service", "is-enabled") == expected["enabled"]
            assert (
                hashlib.sha256(
                    Path("/etc/jaltrix/local.rules").read_bytes()
                ).hexdigest()
                == expected["rules"]
            )
        print(
            json.dumps(
                dict(
                    result="PASS",
                    scope="legacy package to JALTRIX 1.0.1",
                    hostname=platform.node(),
                    checks=[
                        "old launcher/menu removed",
                        "data directory migration",
                        "event IDs",
                        "checkpoints",
                        "cases",
                        "triage",
                        "sensor state and rules",
                    ],
                )
            )
        )
finally:
    for item in (store, cases, triage):
        item.close()
