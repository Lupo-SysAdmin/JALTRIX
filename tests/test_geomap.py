import json

from jaltrix.core import demo_events
from jaltrix.enrichment import GeoDatabase
from jaltrix.geomap import build_map
from jaltrix.snort import AlertStore


def database(tmp_path):
    csv = tmp_path / "geo.csv"
    csv.write_text(
        "network,country,latitude,longitude,source\n8.0.0.0/8,US,40,-74,synthetic test\n8.8.8.0/24,CO,4.7,-74.1,synthetic specific test\n1.1.1.0/24,AU,-33,151,synthetic test\n"
    )
    return GeoDatabase(csv)


def test_geo_aggregates_entire_query_and_drills_beyond_first_page(tmp_path):
    geo = database(tmp_path)
    source = tmp_path / "alerts.json"
    rows = [
        dict(
            rule="1:42:1",
            src_addr="8.8.8.8",
            priority=1,
            **{"class": "web-application-attack"},
        )
        for _ in range(1105)
    ]
    rows += [
        dict(
            rule="1:43:1",
            src_addr="1.1.1.1",
            priority=2,
            **{"class": "attempted-admin"},
        )
        for _ in range(200)
    ]
    rows += [
        dict(rule="1:44:1", src_addr=ip) for ip in ("10.0.0.1", "192.0.2.1", "9.9.9.9")
    ]
    source.write_text("".join(json.dumps(row) + "\n" for row in rows))
    path = tmp_path / "replay/alerts.sqlite3"
    store = AlertStore(path)
    identity = store.ingest(source)["source_id"]
    # Other sources and modes in the same database must not leak into this map.
    other = tmp_path / "other.json"
    other.write_text(json.dumps(rows[0]) + "\n")
    store.ingest(other)
    store.ingest(source, "live")
    assert store.query("replay", source_id=identity)["next_offset"] == 500
    tabs = store.categories("replay", identity)
    assert sum(c["count"] for c in tabs) == 1308
    assert (
        store.query("replay", source_id=identity, category="attempted-admin")["matched"]
        == 200
    )
    store.close()
    options = dict(database=geo, path=path, source=source, mode="replay", minutes=0)
    result = build_map(**options)
    assert (
        result["total"] == 1308
        and result["located"] == 1305
        and result["unlocated"] == 3
    )
    assert [(c["country"], c["alerts"], c["sources"]) for c in result["countries"]] == [
        ("CO", 1105, 1),
        ("AU", 200, 1),
    ]
    assert len(result["events"]) == 100
    point = next(p for p in result["markers"] if p["country"] == "CO")
    assert point["x"] == (180 - 74.1) / 360 and point["y"] == (90 - 4.7) / 180
    selected = build_map(**options, country="CO", marker=point["key"], offset=1100)
    assert selected["matched"] == 1105 and len(selected["events"]) == 5
    assert all(e["src"] == "8.8.8.8" for e in selected["events"])
    assert build_map(**options, category="attempted-admin")["located"] == 200
    assert build_map(**options, query="src:1.1.1.1", severity="Media")["located"] == 200
    unknown = build_map(**dict(options, database=None))
    assert unknown["markers"] == [] and unknown["unlocated"] == 1308


def test_demo_geography_is_explicit_and_never_used_for_real_ips(tmp_path):
    result = build_map(demo=demo_events())
    assert result["demo"] and result["located"] == 240 and len(result["countries"]) == 6
    assert all("sintética" in p["source"] for p in result["markers"])
    assert sum(c["alerts"] for c in result["countries"]) == 240
    assert database(tmp_path).lookup("192.0.2.1") is None
    assert database(tmp_path).lookup("10.0.0.1") is None
    assert database(tmp_path).lookup("8.8.8.8")["country"] == "CO"


def test_country_grouping_merges_addresses_and_longest_prefix_ipv6(tmp_path):
    source = tmp_path / "geo.csv"
    source.write_text(
        "network,country,latitude,longitude,source\n2606:4700::/32,US,40,-74,test\n2606:4700:4700::/48,AU,-33,151,specific\n"
    )
    geo = GeoDatabase(source)
    assert geo.lookup("2606:4700:4700::1111")["country"] == "AU"
    assert geo.lookup("2606:4700:1234::1")["country"] == "US"
    assert geo.lookup("fe80::1") is None
    result = build_map(demo=demo_events())
    assert all(c["sources"] == 4 and c["alerts"] == 40 for c in result["countries"])
