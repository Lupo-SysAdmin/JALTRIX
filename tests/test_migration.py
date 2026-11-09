import json
from types import SimpleNamespace

import pytest

from jaltrix import migration
from jaltrix.snort import AlertStore
from jaltrix.core import CaseStore
from jaltrix.triage import TriageStore
from jaltrix.collector import open_source


def test_data_migration_preserves_evidence_and_checkpoints(tmp_path):
    base = tmp_path / "data"
    old = base / migration.OLD_DATA
    old.mkdir(parents=True)
    source = old / "events.json"
    source.write_text('{"rule":"1:42:1","msg":"evidence"}\n')
    store = AlertStore(old / "live/alerts.sqlite3")
    result = store.ingest(source, "live")
    event = store.query("live")["events"][0]
    cases = CaseStore(old / "live/cases.sqlite3", mode="live")
    case = cases.create(event)
    triage = TriageStore(old / "live/triage.sqlite3")
    triage.save(
        event["event_id"], 0, "investigating", "Retain notes", ["migration"], True
    )
    for obj in (store, cases, triage):
        obj.close()
    new = migration.user_data_dir(base, tmp_path / "config")
    assert new.name == "jaltrix" and not new.is_symlink()
    assert old.is_symlink() and source.is_file()
    store = AlertStore(new / "live/alerts.sqlite3")
    try:
        assert store.source_id(new / source.name, "live") == result["source_id"]
        assert store.ingest(new / source.name, "live")["inserted"] == 0
        assert store.query("live")["events"][0]["event_id"] == event["event_id"]
        with source.open("a") as output:
            output.write('{"rule":"1:43:1","msg":"after rename"}\n')
        stream = open_source(new / source.name, store)
        try:
            assert (
                store.ingest(new / source.name, "live", stream=stream)["inserted"] == 1
            )
        finally:
            stream.close()
        assert store.count("live", result["source_id"]) == 2
        # Repeated launch does not move or alter the database again.
        assert migration.user_data_dir(base, tmp_path / "config") == new
    finally:
        store.close()
    cases = CaseStore(new / "live/cases.sqlite3", mode="live")
    triage = TriageStore(new / "live/triage.sqlite3")
    try:
        assert cases.list()[0]["id"] == case
        assert triage.get(event["event_id"])["notes"] == "Retain notes"
        assert triage.get(event["event_id"])["bookmark"]
    finally:
        cases.close()
        triage.close()


def test_conflicting_datasets_are_never_merged(tmp_path):
    for name in (migration.OLD_DATA, "jaltrix"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "marker").write_text(name)
    with pytest.raises(RuntimeError, match="conflict"):
        migration.user_data_dir(tmp_path, tmp_path / "config")
    for name in (migration.OLD_DATA, "jaltrix"):
        assert (tmp_path / name / "marker").read_text() == name


def test_new_install_has_no_legacy_alias(tmp_path):
    new = migration.user_data_dir(tmp_path, tmp_path / "config")
    assert new == tmp_path / "jaltrix"
    assert not (tmp_path / migration.OLD_DATA).exists()


@pytest.mark.parametrize("active", [False, True])
def test_collector_migration_preserves_enabled_and_running_state(
    tmp_path, monkeypatch, active
):
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0 if active else 3)

    monkeypatch.setattr(migration, "run", run)
    unit = tmp_path / "config/systemd/user/jaltrix-ingest.service"
    unit.parent.mkdir(parents=True)
    unit.write_text(
        "[Service]\nExecStart=/usr/bin/python3 /usr/lib/snort-soc-desktop/snort_soc/worker_entry.py --data-dir /custom/evidence\n"
    )
    migration.user_data_dir(tmp_path / "data", tmp_path / "config")
    assert "/usr/lib/jaltrix/jaltrix/worker_entry.py" in unit.read_text()
    assert "/custom/evidence" in unit.read_text()
    assert not any("enable" in call or "disable" in call for call in calls)
    assert any("start" in call for call in calls) == active
    calls.clear()
    migration.user_data_dir(tmp_path / "data", tmp_path / "config")
    assert not calls


def test_source_modes_remain_isolated_after_rename(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    source = old / "alerts.json"
    source.write_text(json.dumps({"rule": "1:42:1"}) + "\n")
    store = AlertStore(tmp_path / "alerts.sqlite3")
    try:
        prior = {
            mode: store.ingest(source, mode)["source_id"] for mode in ("live", "replay")
        }
        migration.move_with_alias(old, new)
        for mode in prior:
            assert store.ingest(new / source.name, mode)["source_id"] == prior[mode]
            assert store.count(mode) == 1
        assert prior["live"] != prior["replay"]
    finally:
        store.close()
