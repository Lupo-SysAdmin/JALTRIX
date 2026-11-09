import json
import pytest
from snort_soc.snort import AlertStore, normalize


def record(**changes):
    return dict(
        timestamp="11/09-14:20:21.000001",
        seconds=1794234021,
        rule="1:1000001:1",
        src_ap="192.0.2.1:45000",
        dst_ap="198.51.100.1:9999",
        proto="UDP",
        priority=1,
        msg="LAB",
        action="would_drop",
        **changes,
    )


def line(data=None):
    return (json.dumps(record() if data is None else data) + "\n").encode()


def test_parser_preserves_action_ipv6_and_ambiguous_time():
    obj = record()
    obj.pop("seconds")
    obj["src_ap"] = "2001:db8::1:443"
    e = normalize(json.dumps(obj), "s", "g", 0, "replay", "/lab")
    assert e["src"] == "2001:db8::1" and e["src_port"] == 443
    assert e["timestamp"] is None and e["timestamp_confidence"] == "unknown"
    assert e["action"] == "would_drop"  # Never convert this to a prevention claim.
    assert e["priority"] == 1 and e["severity"] == "Alta"
    assert e["original_timestamp"] == obj["timestamp"]


def test_checkpoint_restart_partial_and_repeated_legitimate_events(tmp_path):
    path = tmp_path / "alert_json.txt"
    raw = line()
    path.write_bytes(raw + raw[:30])
    store = AlertStore(tmp_path / "db.sqlite")
    assert store.ingest(path)["inserted"] == 1
    store.close()
    store = AlertStore(tmp_path / "db.sqlite")
    assert store.ingest(path)["inserted"] == 0
    with path.open("ab") as f:
        f.write(raw[30:])
    assert store.ingest(path)["inserted"] == 1
    assert len({e["event_id"] for e in store.events("replay")}) == 2
    assert store.ingest(path)["inserted"] == 0
    store.close()


def test_rotation_truncation_quarantine_and_mode_separation(tmp_path):
    path = tmp_path / "alerts"
    path.write_bytes(line())
    store = AlertStore(tmp_path / "db.sqlite")
    assert store.ingest(path)["inserted"] == 1
    path.rename(tmp_path / "rotated")
    path.write_bytes(line() + b"not-json\n")
    result = store.ingest(path)
    assert result["inserted"] == result["rejected"] == 1
    path.write_bytes(line())
    assert store.ingest(path)["inserted"] == 1
    assert store.count("replay") == 3
    assert store.count("live") == 0
    assert store.db.execute("SELECT count(*) FROM quarantine").fetchone()[0] == 1
    store.close()


def test_copytruncate_regrowth_detected_by_tail(tmp_path):
    path = tmp_path / "alerts"
    path.write_bytes(line())
    store = AlertStore(tmp_path / "db.sqlite")
    store.ingest(path)
    obj = record()
    obj["msg"] = "NEW"
    path.write_bytes(line(obj) + line(obj))
    assert store.ingest(path)["inserted"] == 2
    store.close()


@pytest.mark.parametrize(
    "raw",
    ["[]", "{}", '{"rule":"bad"}', '{"src_addr":"999.1.1.1"}', '{"seconds":true}'],
)
def test_invalid_records_rejected(raw):
    with pytest.raises(ValueError):
        normalize(raw, "s", "g", 0, "replay", "/file")
