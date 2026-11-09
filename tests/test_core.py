from snort_soc.core import CaseStore, demo_events, filter_events, summarize
import pytest


def test_deterministic_and_reserved_addresses():
    events = demo_events()
    assert events == demo_events()
    assert len({e["event_id"] for e in events}) == 240
    assert all(e["mode"] == "demo" and e["src"].startswith("192.0.2.") for e in events)


def test_combined_filters_and_time_window():
    events = demo_events()
    rows = filter_events(
        events, query="192.0.2.1", severity="Crítica", category="Web", minutes=15
    )
    assert rows
    assert all(e["severity"] == "Crítica" and e["category"] == "Web" for e in rows)
    assert len(filter_events(events, minutes=15)) == 48
    assert filter_events(events, query="no-such-value") == []


def test_summary_tracks_filtered_population():
    rows = filter_events(demo_events(), severity="Crítica")
    summary = summarize(rows)
    assert summary["total"] == summary["critical"] == 60
    assert sum(b["count"] for b in summary["series"]) == 60
    assert summarize([])["sources"] == 0


def test_cases_persist_and_create_is_idempotent(tmp_path):
    path = tmp_path / "demo/cases.sqlite3"
    store = CaseStore(path)
    event = demo_events()[0]
    case_id = store.create(event)
    assert store.create(event) == case_id
    store.close()
    store = CaseStore(path)
    assert len(store.list()) == 1
    assert store.list()[0]["event_id"] == event["event_id"]
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        store.create(dict(event, mode="live"))
    store.close()


def test_graph_preserves_empty_time_intervals():
    events = demo_events(2)
    events[0]["timestamp"] = "2026-11-09T14:30:00+00:00"
    events[1]["timestamp"] = "2026-11-09T14:20:00+00:00"
    summary = summarize(events)
    assert summary["bin_minutes"] == 1
    assert len(summary["series"]) == 11
    assert sum(point["count"] == 0 for point in summary["series"]) == 9
