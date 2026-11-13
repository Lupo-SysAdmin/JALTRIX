from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from jaltrix.core import CaseStore
from jaltrix.host_events import APPLICATION_ID, HostEventStore, MAX_BATCH
from jaltrix.snort import AlertStore


STAMP = datetime(2026, 11, 12, 12, tzinfo=timezone.utc)


def event(identity="e1", second=0, **changes):
    return {
        "event_id": identity,
        "original_id": "cursor-" + identity,
        "source": "journal",
        "host_id": "host-a",
        "hostname": "lab-a",
        "timestamp": (STAMP + timedelta(seconds=second)).isoformat(),
        "kind": "auth_success",
        "service": "sshd",
        "outcome": "success",
        "user": "alice",
        "src_ip": "192.0.2.1",
        "message": "Accepted publickey for alice",
        "raw_record": {
            "__CURSOR": "cursor-" + identity,
            "MESSAGE": "original evidence",
        },
        **changes,
    }


def sequence():
    return [
        event("f" + str(i), i, kind="auth_failure", outcome="failure") for i in range(5)
    ] + [event("success", 10)]


def test_roundtrip_provider_dedup_checkpoint_and_private_schema(tmp_path):
    path = tmp_path / "live/host-events.sqlite3"
    original = event()
    store = HostEventStore(path)
    result = store.ingest(
        [original], checkpoint_key="journal", checkpoint={"cursor": "cursor-e1"}
    )
    assert result["inserted"] == 1
    copy = event("other-id", original_id=original["original_id"])
    assert store.ingest([original, copy])["duplicates"] == 2
    assert store.count() == 1
    saved = store.get_event("e1")
    assert saved["event_id"] == "e1" and saved["raw_record"] == original["raw_record"]
    assert saved["timestamp"].endswith("+00:00") and saved["mode"] == "live"
    assert store.checkpoint("journal") == {"cursor": "cursor-e1"}
    assert store.db.execute("PRAGMA user_version").fetchone()[0] == 1
    assert store.db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
    assert path.stat().st_mode & 0o777 == 0o600
    store.close()
    reopened = HostEventStore(path)
    assert reopened.count() == 1
    assert reopened.checkpoint("journal") == {"cursor": "cursor-e1"}
    reopened.close()


def test_missing_or_naive_time_is_not_fabricated(tmp_path):
    store = HostEventStore(tmp_path / "host.sqlite3")
    store.ingest(
        [
            event(timestamp="2026-11-12T12:00:00"),
            event("b", timestamp_confidence="unknown"),
        ]
    )
    assert all(
        e["timestamp"] is None and e["timestamp_confidence"] == "unknown"
        for e in store.events()
    )
    assert store.get_event("e1")["original_timestamp"] == "2026-11-12T12:00:00"
    assert store.correlations() == []
    store.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "demo"},
        {"mode": "replay"},
        {"host_id": ""},
        {"original_id": ""},
        {"source": "invented"},
        {"kind": "invented"},
        {"src_ip": "invalid"},
        {"auid": True},
        {"auid": "1000"},
        {"dst_port": 65536},
        {"host_bound": "true"},
        {"event_id": "bad\0id"},
        {"message": "invalid \ud800 unicode"},
        {"raw_record": "x" * 131073},
    ],
)
def test_reject_invalid_records_without_losing_checkpoint(tmp_path, changes):
    store = HostEventStore(tmp_path / "host.sqlite3")
    result = store.ingest(
        [event(**changes), event("valid")], "journal", {"position": 2}
    )
    assert result["inserted"] == result["rejected"] == 1
    assert store.checkpoint("journal") == {"position": 2}
    assert store.count() == 1
    assert store.db.execute("SELECT count(*) FROM host_quarantine").fetchone()[0] == 1
    store.close()


def test_id_collision_cannot_replace_original_evidence(tmp_path):
    store = HostEventStore(tmp_path / "host.sqlite3")
    store.ingest([event()])
    conflict = event(host_id="host-b", raw_record={"forged": "replacement"})
    assert store.ingest([conflict])["rejected"] == 1
    assert store.get_event("e1")["host_id"] == "host-a"
    assert store.get_event("e1")["raw_record"]["MESSAGE"] == "original evidence"
    store.close()


def test_transaction_failure_rolls_back_events_correlations_and_checkpoint(
    tmp_path, monkeypatch
):
    store = HostEventStore(tmp_path / "host.sqlite3")
    store.ingest([], "journal", {"cursor": "before"})

    def unavailable(_database):
        raise RuntimeError("injected interruption")

    monkeypatch.setattr("jaltrix.correlation.process_pending", unavailable)
    with pytest.raises(RuntimeError):
        store.ingest(sequence(), "journal", {"cursor": "after"})
    assert store.checkpoint("journal") == {"cursor": "before"}
    assert store.count() == 0
    assert store.correlations() == []
    assert (
        store.db.execute("SELECT count(*) FROM host_correlation_work").fetchone()[0]
        == 0
    )
    store.close()


def test_filtering_pagination_hosts_and_literal_search(tmp_path):
    store = HostEventStore(tmp_path / "host.sqlite3")
    store.ingest(
        [
            event("first", message="100% verified_thing"),
            event(
                "second",
                2,
                host_id="host-b",
                hostname="lab-b",
                kind="process_exec",
                source="audit",
            ),
            event("third", 3, source="audit", kind="file_change"),
        ]
    )
    assert store.count(source="audit") == 2
    assert store.count(host_id="host-b", kind="process_exec") == 1
    assert store.count(query="%") == 1
    assert store.count(query="' OR 1=1 --") == 0
    assert [e["event_id"] for e in store.events(limit=1, offset=1)] == ["second"]
    hosts = {h["host_id"]: h for h in store.hosts()}
    assert hosts["host-a"]["event_count"] == 2
    assert set(hosts["host-a"]["sources"]) == {"journal", "audit"}
    with pytest.raises(ValueError):
        store.events(limit=0)
    store.close()


def test_quarantine_and_input_bounds(tmp_path):
    store = HostEventStore(tmp_path / "host.sqlite3")
    assert store.ingest([{}] * 1005)["rejected"] == 1005
    assert (
        store.db.execute("SELECT count(*) FROM host_quarantine").fetchone()[0] == 1000
    )
    with pytest.raises(ValueError, match="batch"):
        store.ingest((event(str(i)) for i in range(MAX_BATCH + 1)))
    with pytest.raises(ValueError):
        store.ingest([event()], "journal", {"huge": "x" * 65536})
    assert store.count() == 0
    store.close()


def test_pin_actual_case_preserves_every_evidence_event_across_retention(tmp_path):
    path = tmp_path / "live/host-events.sqlite3"
    store = HostEventStore(path)
    store.ingest(sequence() + [event("unrelated", 20)])
    correlation = store.correlations()[0]
    cases = CaseStore(tmp_path / "live/cases.sqlite3", "live")
    old_case = cases.create(
        {
            "event_id": "snort-existing-id",
            "mode": "live",
            "message": "Existing Snort case",
        }
    )
    case = cases.create(
        {
            "event_id": "host-correlation:" + correlation["id"],
            "mode": "live",
            "message": correlation["title"],
        }
    )
    store.pin_correlation(correlation["id"], case)
    store.pin_correlation(correlation["id"], case)
    store.db.execute("UPDATE host_events SET ingested_at='2000-01-01T00:00:00+00:00'")
    result = store.retain(1, 1)
    assert result == {
        "removed": 1,
        "preserved": 6,
        "stored": 6,
        "pinned_over_limit": True,
    }
    assert len(store.correlation_events(correlation["id"])) == 6
    assert store.get_correlation(correlation["id"])["case_ids"] == [case]
    assert {c["id"] for c in cases.list()} == {old_case, case}
    store.close()
    store = HostEventStore(path)
    assert store.get_correlation(correlation["id"])["case_ids"] == [case]
    with pytest.raises(ValueError, match="Unknown"):
        store.pin_correlation("missing", case)
    store.close()
    cases.db.close()


def test_unpinned_correlation_removed_when_evidence_expires(tmp_path):
    store = HostEventStore(tmp_path / "host.sqlite3")
    store.ingest(sequence())
    assert len(store.correlations()) == 1
    assert store.retain(0, 1)["removed"] == 5
    assert store.count() == 1 and store.correlations() == []
    store.close()


def test_existing_snort_database_and_ids_remain_untouched(tmp_path):
    source = tmp_path / "alert_json.txt"
    source.write_text(
        json.dumps(
            {
                "seconds": 1794484800,
                "rule": "1:1000001:1",
                "src_addr": "192.0.2.1",
                "dst_addr": "198.51.100.1",
                "msg": "Original",
            }
        )
        + "\n"
    )
    old_path = tmp_path / "live/alerts.sqlite3"
    old = AlertStore(old_path)
    old.ingest(source, mode="live")
    original = old.events("live")
    old.close()
    original_bytes = old_path.read_bytes()
    store = HostEventStore(tmp_path / "live/host-events.sqlite3")
    store.ingest(sequence())
    store.close()
    assert old_path.read_bytes() == original_bytes
    with pytest.raises(ValueError, match="not a JALTRIX"):
        HostEventStore(old_path)
    assert old_path.read_bytes() == original_bytes
    old = AlertStore(old_path)
    assert old.events("live") == original
    old.close()


def test_corrupt_or_newer_database_is_not_reinitialized(tmp_path):
    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a database")
    with pytest.raises(sqlite3.DatabaseError):
        HostEventStore(corrupt)
    assert corrupt.read_bytes() == b"not a database"
    future = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(future)
    connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
    connection.execute("PRAGMA user_version=99")
    connection.close()
    before = future.read_bytes()
    with pytest.raises(ValueError, match="newer"):
        HostEventStore(future)
    assert future.read_bytes() == before
