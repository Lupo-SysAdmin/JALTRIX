from datetime import datetime, timezone
import json
import os
import sqlite3
from types import SimpleNamespace

import pytest

from jaltrix import host_collector, host_service
from jaltrix.host_events import HostEventStore
from jaltrix.linux_sources import local_host


def test_disabled_by_default_does_not_call_sources(tmp_path):
    def forbidden(*args):
        pytest.fail("Disabled source was called")

    assert not any(
        host_service.load_config(tmp_path)[key]
        for key in ("journal_enabled", "audit_enabled", "snort_enabled")
    )
    result = host_collector.collect_once(
        tmp_path, journal_reader=forbidden, audit_reader=forbidden
    )
    assert result["state"] == "disabled" and result["stored"] == 0


def test_configuration_requires_explicit_selected_snort_binding(tmp_path):
    for value in (
        {"snort_enabled": True},
        {"snort_enabled": True, "snort_host_binding": True},
        {"snort_enabled": True, "snort_source_id": "source"},
        {"journal_enabled": "true"},
    ):
        with pytest.raises(ValueError):
            host_service.save_config(tmp_path, value)
    config = host_service.save_config(tmp_path, {"journal_enabled": True})
    assert config == host_service.load_config(tmp_path)
    assert (tmp_path / "live/host-collector.json").stat().st_mode & 0o777 == 0o600


def test_checkpoint_commits_with_events_and_restart_deduplicates(tmp_path):
    calls = []

    def reader(checkpoint, host):
        calls.append(checkpoint)
        event = dict(
            event_id="e1",
            original_id="cursor1",
            host_id=host["host_id"],
            hostname=host["hostname"],
            source="journal",
            kind="auth_success",
            timestamp="2026-11-12T12:00:00+00:00",
            service="sshd",
            user="alice",
            src_ip="192.0.2.4",
            outcome="success",
        )
        return [event], {"cursor": "cursor1"}, {"state": "following"}

    result = host_collector.collect_once(
        tmp_path, {"journal_enabled": True}, journal_reader=reader
    )
    assert result["sources"]["journal"]["inserted"] == 1 and result["stored"] == 1
    result = host_collector.collect_once(
        tmp_path, {"journal_enabled": True}, journal_reader=reader
    )
    assert calls == [{}, {"cursor": "cursor1"}]
    assert result["sources"]["journal"]["duplicates"] == 1 and result["stored"] == 1


def test_source_permission_error_is_degraded_without_checkpoint_advance(tmp_path):
    def denied(*args):
        raise PermissionError("audit.log is unreadable")

    result = host_collector.collect_once(
        tmp_path, {"audit_enabled": True}, audit_reader=denied
    )
    assert result["state"] == "degraded"
    assert result["sources"]["audit"]["state"] == "permission_denied"
    assert result["stored"] == 0


def make_snort_database(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(path)
    database.executescript(
        "CREATE TABLE sources(id TEXT PRIMARY KEY, mode TEXT); CREATE TABLE events(id TEXT PRIMARY KEY,source_id TEXT, mode TEXT,data TEXT);"
    )
    database.executemany(
        "INSERT INTO sources VALUES(?,?)",
        [("local", "live"), ("other", "live"), ("import", "replay")],
    )
    for identity, source, mode in (
        ("event-local", "local", "live"),
        ("event-other", "other", "live"),
        ("event-import", "import", "replay"),
    ):
        database.execute(
            "INSERT INTO events VALUES(?,?,?,?)",
            (
                identity,
                source,
                mode,
                json.dumps(
                    dict(
                        event_id=identity,
                        source_id=source,
                        mode=mode,
                        timestamp="2026-11-12T12:00:00+00:00",
                        src="192.0.2.4",
                        dst="192.0.2.5",
                        dst_port=22,
                    )
                ),
            ),
        )
    database.commit()
    return database


def test_snort_bridge_only_selected_live_source_preserves_ids_and_recovers_rowid_reuse(
    tmp_path,
):
    database = make_snort_database(tmp_path / "live/alerts.sqlite3")
    config = dict(snort_enabled=True, snort_host_binding=True, snort_source_id="local")
    result = host_collector.collect_once(tmp_path, config)
    assert result["stored"] == 1 and result["sources"]["snort"]["inserted"] == 1
    store = HostEventStore(tmp_path / "live/host-events.sqlite3")
    event = store.events()[0]
    assert event["event_id"] == "event-local" and event["original_id"] == "event-local"
    assert event["host_bound"] and event["src_ip"] == "192.0.2.4"
    assert event["dst_port"] == 22
    store.close()
    database.execute("DELETE FROM events")
    database.execute(
        "INSERT INTO events VALUES(?,?,?,?)",
        (
            "replacement",
            "local",
            "live",
            json.dumps(dict(src="192.0.2.8", dst="192.0.2.9", dst_port=22)),
        ),
    )
    database.commit()
    result = host_collector.collect_once(tmp_path, config)
    assert result["stored"] == 2 and result["sources"]["snort"]["inserted"] == 1
    result = host_collector.collect_once(
        tmp_path, dict(config, snort_source_id="import")
    )
    assert result["sources"]["snort"]["state"] == "error"
    database.close()


def test_real_audit_parse_integrates_with_store_integer_ids(tmp_path, monkeypatch):
    from jaltrix import linux_sources

    monkeypatch.setattr(
        linux_sources.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(pw_name="alice", pw_dir="/home/alice"),
    )
    path = tmp_path / "audit.log"
    path.write_text(
        'type=SYSCALL msg=audit(1760000000.123:1): arch=c000003e syscall=257 success=yes items=1 a2=441 auid=1000 uid=0 pid=123 exe="/usr/bin/tee"\n'
        'type=PATH msg=audit(1760000000.123:1): name="/home/alice/.ssh/authorized_keys" nametype=NORMAL\n'
        "type=EOE msg=audit(1760000000.123:1):\n"
    )
    result = host_collector.collect_once(
        tmp_path, dict(audit_enabled=True, audit_path=str(path))
    )
    assert result["stored"] == 1
    store = HostEventStore(tmp_path / "live/host-events.sqlite3")
    event = store.events()[0]
    assert (
        event["auid"] == 1000
        and event["uid"] == 0
        and event["pid"] == 123
        and event["exe"] == "/usr/bin/tee"
    )
    store.close()


def test_health_does_not_trust_old_pid_boot_or_reused_process(tmp_path):
    directory = tmp_path / "live"
    directory.mkdir()
    value = dict(
        state="running",
        data_dir=str(tmp_path.resolve()),
        heartbeat=datetime.now(timezone.utc).isoformat(),
        pid=os.getpid(),
        boot_id=local_host()["boot_id"],
        process_start=host_service._process_start(os.getpid()),
    )
    path = directory / "host-collector-health.json"
    path.write_text(json.dumps(value))
    assert host_service.health(tmp_path)["fresh"]
    for altered in (
        dict(value, boot_id="old-boot"),
        dict(value, data_dir=str(tmp_path / "restored")),
        dict(value, process_start="0"),
        dict(value, heartbeat="2000-01-01T00:00:00+00:00"),
        dict(value, pid=99999999),
    ):
        path.write_text(json.dumps(altered))
        result = host_service.health(tmp_path)
        assert not result["fresh"] and result["state"] == "stale"


def test_service_is_separate_rootless_and_stop_disables_it(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(
        host_service.subprocess, "run", lambda args, **kwargs: calls.append(args)
    )
    host_service.control(tmp_path / "data", config={"journal_enabled": True})
    unit = (tmp_path / "config/systemd/user/jaltrix-host-events.service").read_text()
    assert "NoNewPrivileges=yes" in unit and "host_worker_entry.py" in unit
    assert all("--user" in call for call in calls)
    assert not any("jaltrix-ingest.service" in call for call in calls)
    host_service.control(tmp_path / "data", action="stop")
    assert calls[-2] == [
        "systemctl",
        "--user",
        "disable",
        "--now",
        "jaltrix-host-events.service",
    ]


def test_user_service_refuses_to_replace_or_stop_another_data_directory(
    tmp_path, monkeypatch
):
    calls = []
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(
        host_service.subprocess, "run", lambda args, **kwargs: calls.append(args)
    )
    host_service.control(tmp_path / "first", config={"journal_enabled": True})
    previous_calls = list(calls)
    for action in ("start", "stop"):
        with pytest.raises(ValueError, match="another data directory"):
            host_service.control(
                tmp_path / "second", action=action, config={"journal_enabled": True}
            )
    assert calls == previous_calls
    host_service.control(tmp_path / "first", action="stop")
    host_service.control(tmp_path / "second", config={"journal_enabled": True})
