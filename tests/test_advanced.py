import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import pytest
from snort_soc.capture import inspect, page, convert_to_pcap
from snort_soc.snort import AlertStore
from snort_soc.observations import InterfaceSampler, topology

LAB = Path(__file__).parent / "fixtures/lab"


def test_capture_pcapng_conversion_and_malformed(tmp_path):
    ng = tmp_path / "test.pcapng"
    shutil.copyfile(LAB / "benign.pcapng", ng)
    info = inspect(ng)
    assert info["format"] == "PCAPNG" and info["packets"] == 3
    rows = page(ng, limit=2)
    assert rows[0]["src"] == "192.0.2.10" and rows[0]["dst_port"] == 9999
    assert len(page(ng, offset=2)) == 1
    target = tmp_path / "converted.pcap"
    convert_to_pcap(ng, target)
    assert inspect(target)["packets"] == 3
    assert page(target)[0]["src"] == rows[0]["src"]
    bad = tmp_path / "bad.pcapng"
    bad.write_bytes(ng.read_bytes()[:-2])
    with pytest.raises(ValueError):
        inspect(bad)


def test_sql_pages_cidr_and_retention(tmp_path):
    source = tmp_path / "alerts.txt"
    source.write_text(
        "".join(
            json.dumps(
                dict(
                    rule=f"1:{1000 + i}:1",
                    src_addr="192.0.2.10",
                    dst_addr="198.51.100.1",
                    src_port=123,
                    dst_port=443,
                    proto="TCP",
                    msg="Árbol",
                    seconds=1700000000 + i,
                )
            )
            + "\n"
            for i in range(1200)
        )
    )
    store = AlertStore(tmp_path / "alerts.sqlite")
    store.ingest(source)
    query = store.query("replay", query="src:192.0.2.0/24 port:443 árbol", limit=500)
    assert query["matched"] == 1200 and len(query["events"]) == 500
    nextpage = store.query("replay", offset=query["next_offset"])
    assert nextpage["events"][0]["event_id"] != query["events"][0]["event_id"]
    assert store.query("replay", query="sid:1000")["matched"] == 1
    with pytest.raises(ValueError):
        store.query("replay", query="src:not-an-ip")
    assert store.retain("2000-01-01T00:00:00+00:00", mode="replay") == 0
    with pytest.raises(ValueError):
        store.retain("2999-01-01T00:00:00+00:00")
    assert store.ingest(source)["inserted"] == 0
    store.close()


def test_collector_independent_restart_and_missing_source(tmp_path):
    source = tmp_path / "alerts.json"
    source.touch()
    directory = tmp_path / "live"
    directory.mkdir()
    (directory / "collector.json").write_text(json.dumps({"source": str(source)}))
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))

    def start():
        return subprocess.Popen(
            [sys.executable, "-m", "snort_soc.collector", "--data-dir", str(tmp_path)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def health_until(predicate):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                h = json.loads((directory / "collector-health.json").read_text())
                if predicate(h):
                    return h
            except (FileNotFoundError, ValueError):
                pass
            time.sleep(0.05)
        raise AssertionError("Collector did not reach expected state")

    p = start()
    try:
        health_until(lambda h: h["state"] == "following")
        source.write_text(
            json.dumps({"rule": "1:42:1", "src_addr": "192.0.2.1"}) + "\n"
        )
        health_until(lambda h: h.get("stored") == 1)
    finally:
        p.terminate()
        p.communicate(timeout=5)
    p = start()
    try:
        h = health_until(
            lambda h: h.get("state") == "following" and h.get("pid") == p.pid
        )
        assert h["stored"] == 1 and h["inserted"] == 0
        source.unlink()
        health_until(lambda h: h["state"] == "source_missing")
        source.write_text(
            json.dumps({"rule": "1:43:1", "src_addr": "192.0.2.2"}) + "\n"
        )
        health_until(lambda h: h.get("stored") == 2)
    finally:
        p.terminate()
        p.communicate(timeout=5)


def test_interface_counter_reset_and_topology(tmp_path):
    directory = tmp_path / "eth0/statistics"
    directory.mkdir(parents=True)
    for name in [
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_dropped",
        "tx_dropped",
    ]:
        (directory / name).write_text("100")
    ticks = iter([1.0, 3.0, 4.0])
    sampler = InterfaceSampler(tmp_path, lambda: next(ticks))
    assert not sampler.sample("eth0")["ready"]
    (directory / "rx_bytes").write_text("350")
    assert sampler.sample("eth0")["rx_mbps"] == 0.001
    (directory / "rx_bytes").write_text("0")
    assert not sampler.sample("eth0")["ready"]
    with pytest.raises(ValueError):
        sampler.sample("../etc")
    assert topology(
        [
            {"src": "192.0.2.1", "dst": "198.51.100.1", "protocol": "TCP"},
            {"src": "—", "dst": "—"},
        ]
    ) == [dict(src="192.0.2.1", dst="198.51.100.1", protocol="TCP", alerts=1)]


def test_analyst_mapping_revisions_and_offline_geo(tmp_path):
    from snort_soc.enrichment import MappingStore, GeoDatabase

    store = MappingStore(tmp_path / "mappings.sqlite")
    store.save(
        "1:42:1",
        "T1046",
        "Network Service Discovery",
        "low",
        "Analyst assessed rule metadata",
        "test",
    )
    store.save(
        "1:42:1",
        "T1046",
        "Network Service Discovery",
        "medium",
        "Reviewed packet evidence",
        "test",
    )
    assert store.summarize([{"sid": "1:42:1"}])[0]["revision"] == 2
    assert store.summarize([{"sid": "1:42:2"}]) == []
    with pytest.raises(ValueError):
        store.save("1:42:1", "../bad", "x", "high", "reason", "actor")
    store.close()
    geo = tmp_path / "geo.csv"
    geo.write_text(
        "network,country,latitude,longitude,source\n8.8.8.0/24,US,37,-122,Synthetic test location\n"
    )
    db = GeoDatabase(geo)
    assert db.lookup("8.8.8.8")["approximate"]
    assert db.lookup("192.168.1.1") is None
    assert db.lookup("1.1.1.1") is None


def test_triage_concurrency_and_scoped_exception(tmp_path):
    from snort_soc.triage import TriageStore
    from snort_soc.response import ResponseStore

    triage = TriageStore(tmp_path / "triage.sqlite")
    triage.save("event1", 0, "false_positive", "Checked payload", ["lab"], True)
    with pytest.raises(ValueError):
        triage.save("event1", 0, "new", "", [], False)
    assert triage.get("event1")["bookmark"]
    triage.close()
    store = ResponseStore(tmp_path / "response.sqlite")
    identifier = store.propose("allowlist", "192.0.2.1", "Approved lab fixture")
    store.activate_triage(identifier, "1:42:1")
    assert store.exceptions()[0]["signature"] == "1:42:1"
    store.revoke(identifier)
    assert store.exceptions() == [] and store.verify_audit()
    store.close()


def test_privileged_validation_rejects_injection():
    from snort_soc.privileged import profile, rules_valid, nft_command

    with pytest.raises(ValueError):
        profile("lo;touch x", "127.0.0.0/8")
    with pytest.raises(ValueError):
        profile("lo", "127.0.0.1/8'; os.execute('id')")
    with pytest.raises(ValueError):
        rules_valid("include /etc/shadow")
    with pytest.raises(ValueError):
        rules_valid(
            "alert udp any any -> any any (sid:1;)\nalert udp any any -> any any (sid:1;)"
        )
    with pytest.raises(PermissionError):
        nft_command("host")


def test_rotated_descriptor_and_restart_recovery(tmp_path):
    from snort_soc.collector import open_source

    source = tmp_path / "alert_json.txt"
    record = lambda n: json.dumps({"rule": f"1:{n}:1", "src_addr": "192.0.2.1"}) + "\n"
    source.write_text(record(1) + record(2) + record(3))
    store = AlertStore(tmp_path / "alerts.sqlite")
    stream = open_source(source, store)
    assert store.ingest(source, "live", limit=1, stream=stream)["inserted"] == 1
    source.rename(tmp_path / "alert_json.txt.1")
    source.write_text(record(4))
    assert store.ingest(source, "live", stream=stream)["inserted"] == 2
    stream.close()
    stream = open_source(source, store)
    assert store.ingest(source, "live", stream=stream)["inserted"] == 1
    stream.close()
    with source.open("a") as out:
        out.write(record(5))
    source.rename(tmp_path / "alert_json.txt.2")
    source.write_text(record(6))
    # Recovery after process restart locates the recorded inode among retained files.
    stream = open_source(source, store)
    assert store.ingest(source, "live", stream=stream)["inserted"] == 1
    stream.close()
    stream = open_source(source, store)
    assert store.ingest(source, "live", stream=stream)["inserted"] == 1
    assert store.count("live") == 6
    stream.close()
    store.close()


def test_complete_query_export_and_case_retention(tmp_path):
    from snort_soc.reporting import export_query
    import csv

    source = tmp_path / "alerts.json"
    source.write_text(
        "".join(
            json.dumps(
                dict(
                    rule=f"1:{n + 1}:1",
                    src_addr="192.0.2.1",
                    msg="=formula",
                    seconds=1700000000 + n,
                )
            )
            + "\n"
            for n in range(1200)
        )
    )
    store = AlertStore(tmp_path / "replay/alerts.sqlite3")
    store.ingest(source)
    preserved = store.query("replay")["events"][0]["event_id"]
    filters = dict(query="src:192.0.2.0/24", severity="Todas", minutes=0)
    for suffix in ("json", "csv"):
        target = tmp_path / f"export.{suffix}"
        result = export_query(
            tmp_path, "replay", source, filters, target, {"filters": filters}
        )
        assert result["count"] == 1200
        if suffix == "json":
            data = json.loads(target.read_text())
            assert len(data["events"]) == data["exported_count"] == 1200
        else:
            with target.open() as stream:
                rows = list(csv.DictReader(stream))
            assert len(rows) == 1200 and rows[0]["message"] == "'=formula"
    store.db.execute(
        "UPDATE events SET data=json_set(data,'$.ingested_at','2000-01-01T00:00:00+00:00')"
    )
    store.db.commit()
    assert (
        store.retain("2001-01-01T00:00:00+00:00", mode="replay", protected=[preserved])
        == 1199
    )
    assert store.count("replay") == 1
    assert store.ingest(source)["inserted"] == 0
    store.close()


def test_rotated_incomplete_fragment_and_packet_bytes(tmp_path):
    from snort_soc.capture import packet_bytes

    source = tmp_path / "alert.json"
    source.write_bytes(b'{"rule":"1:42:1"}\n{"rule":')
    store = AlertStore(tmp_path / "alerts.sqlite")
    with source.open("rb") as stream:
        result = store.ingest(source, "live", stream=stream)
        assert result["inserted"] == 1 and result["more"]
        assert (
            store.finish_rotated_fragment(result["source_id"], stream)
            == source.stat().st_size
        )
        assert store.ingest(source, "live", stream=stream)["inserted"] == 0
    assert store.db.execute("SELECT count(*) FROM quarantine").fetchone()[0] == 1
    store.close()
    assert packet_bytes(LAB / "benign.pcapng", 1)
    with pytest.raises(ValueError):
        packet_bytes(LAB / "benign.pcapng", 999)
