from datetime import datetime, timedelta, timezone

import pytest

from jaltrix.host_events import HostEventStore

STAMP = datetime(2026, 11, 12, 12, tzinfo=timezone.utc)


def event(identity, seconds=0, **changes):
    return {
        "event_id": identity,
        "original_id": identity,
        "host_id": "host-a",
        "hostname": "lab-a",
        "source": "journal",
        "timestamp": (STAMP + timedelta(seconds=seconds)).isoformat(),
        "kind": "auth_success",
        "service": "sshd",
        "outcome": "success",
        "user": "alice",
        "src_ip": "192.0.2.5",
        "raw_record": {"identity": identity},
        **changes,
    }


def failures():
    return [
        event("failure-" + str(i), i, kind="auth_failure", outcome="failure")
        for i in range(5)
    ]


def key_event(**changes):
    values = dict(
        source="audit",
        service="auditd",
        kind="file_change",
        auid=1000,
        uid=0,
        user="alice",
        path="/home/alice/.ssh/authorized_keys",
        src_ip=None,
    )
    return event("keys", 40, **(values | changes))


def network_event(**changes):
    values = dict(
        source="snort",
        service=None,
        user=None,
        kind="network_alert",
        host_bound=True,
        dst_ip="198.51.100.4",
        dst_port=22,
        outcome="unknown",
    )
    return event("snort-alert", 0, **(values | changes))


def sudo_event(**changes):
    values = dict(kind="privilege_use", service="sudo", src_ip=None, target_user="root")
    return event("sudo", 50, **(values | changes))


@pytest.fixture
def store(tmp_path):
    result = HostEventStore(tmp_path / "host.sqlite3")
    yield result
    result.close()


def test_three_rules_have_explainable_immutable_original_evidence(store):
    originals = failures() + [
        event("login", 20),
        key_event(),
        network_event(),
        sudo_event(),
    ]
    result = store.ingest(originals)
    assert result["inserted"] == 9 and result["correlations_created"] == 3
    correlations = {c["rule_id"]: c for c in store.correlations()}
    assert set(correlations) == {
        "ssh_failures_then_success",
        "ssh_then_authorized_keys",
        "network_ssh_sudo",
    }
    assert len(correlations["ssh_failures_then_success"]["event_ids"]) == 6
    assert len(correlations["ssh_then_authorized_keys"]["event_ids"]) == 2
    assert len(correlations["network_ssh_sudo"]["event_ids"]) == 3
    by_id = {e["event_id"]: e for e in originals}
    for correlation in correlations.values():
        assert correlation["automatic_response"] is False
        assert "no demuestra" in correlation["explanation"]
        assert "does not prove" in correlation["explanation_en"]
        assert correlation["observed_seconds"] <= correlation["window_seconds"]
        for evidence in store.correlation_events(correlation["id"]):
            assert evidence["raw_record"] == by_id[evidence["event_id"]]["raw_record"]
    ids = {c["id"] for c in correlations.values()}
    assert store.ingest(originals)["duplicates"] == 9
    assert {c["id"] for c in store.correlations()} == ids


@pytest.mark.parametrize(
    "changes",
    [
        {"host_id": "other-host"},
        {"src_ip": "192.0.2.6"},
        {"user": "bob"},
        {"source": "audit"},
        {"service": "other"},
        {"outcome": "unknown"},
        {"timestamp": None},
        {"timestamp": "2026-11-12T12:00:00"},
        {"timestamp_confidence": "unknown"},
        {"timestamp_confidence": "inferred_timezone"},
    ],
)
def test_failures_require_five_matching_known_ssh_observations(store, changes):
    records = failures()
    records[-1].update(changes)
    store.ingest(records + [event("login", 10)])
    assert store.correlations() == []


def test_repeated_provider_event_and_audit_copy_do_not_inflate_failure_count(store):
    records = failures()[:4]
    store.ingest(
        records
        + [records[0]] * 6
        + [
            event("audit-copy", source="audit", kind="auth_failure", outcome="failure"),
            event("login", 10),
        ]
    )
    assert store.correlations() == []


@pytest.mark.parametrize("seconds,expected", [(300, 1), (305, 0), (-1, 0), (0, 0)])
def test_failures_window_and_order(store, seconds, expected):
    store.ingest(failures() + [event("login", seconds)])
    assert len(store.correlations()) == expected


@pytest.mark.parametrize(
    "changes",
    [
        {"path": "/tmp/.ssh/authorized_keys"},
        {"path": "/tmp/authorized_keys"},
        {"path": "/home/alice/.ssh/authorized_keys.backup"},
        {"path": "/home/alice/authorized_keys"},
        {"path": "home/alice/.ssh/authorized_keys"},
        {"path": "/home/a/b/.ssh/authorized_keys"},
        {"outcome": "failure"},
        {"outcome": "unknown"},
        {"auid": None},
        {"auid": 4294967295},
        {"user": "bob"},
        {"user": None},
        {"host_id": "other-host"},
        {"source": "journal"},
        {"timestamp": None},
    ],
)
def test_authorized_keys_requires_real_target_actor_and_success(store, changes):
    store.ingest([event("login", 10), key_event(**changes)])
    assert store.correlations() == []


def test_audit_root_effective_uid_does_not_join_an_unrelated_root_login(store):
    store.ingest(
        [
            event("root-login", 10, user="root"),
            key_event(
                uid=0, auid=1000, user="alice", path="/root/.ssh/authorized_keys"
            ),
        ]
    )
    assert store.correlations() == []
    store.ingest([event("alice-login", 15)])
    assert [c["rule_id"] for c in store.correlations()] == ["ssh_then_authorized_keys"]


def test_custom_verified_home_and_normalized_target_path(store):
    store.ingest(
        [
            event("login", 10),
            key_event(
                path="/srv/users/alice/./.ssh/authorized_keys",
                home_dir="/srv/users/alice",
            ),
        ]
    )
    assert len(store.correlations()) == 1


@pytest.mark.parametrize(
    "which,changes",
    [
        ("network", {"host_bound": False}),
        ("network", {"host_bound": None}),
        ("network", {"dst_port": 2222}),
        ("network", {"host_id": "other-host"}),
        ("network", {"src_ip": "192.0.2.20"}),
        ("network", {"timestamp": None}),
        ("login", {"host_id": "other-host"}),
        ("login", {"outcome": "failure"}),
        ("login", {"src_ip": None}),
        ("login", {"user": "bob"}),
        ("sudo", {"host_id": "other-host"}),
        ("sudo", {"user": "root"}),
        ("sudo", {"outcome": "unknown"}),
        ("sudo", {"service": "other"}),
        ("sudo", {"source": "audit"}),
        ("sudo", {"user": "unknown"}),
    ],
)
def test_network_chain_never_guesses_host_or_actor_binding(store, which, changes):
    records = {
        "network": network_event(),
        "login": event("login", 20),
        "sudo": sudo_event(),
    }
    records[which].update(changes)
    store.ingest(records.values())
    assert store.correlations() == []


@pytest.mark.parametrize(
    "network_time,login_time,sudo_time,expected",
    [
        (0, 10, 600, 1),
        (0, 10, 601, 0),
        (20, 10, 50, 0),
        (0, 60, 50, 0),
        (10, 10, 50, 0),
        (0, 50, 50, 0),
    ],
)
def test_network_chain_enforces_complete_window_and_order(
    store, network_time, login_time, sudo_time, expected
):
    network, login, sudo = network_event(), event("login", login_time), sudo_event()
    network["timestamp"] = (STAMP + timedelta(seconds=network_time)).isoformat()
    sudo["timestamp"] = (STAMP + timedelta(seconds=sudo_time)).isoformat()
    store.ingest([network, login, sudo])
    assert len(store.correlations()) == expected


def test_late_out_of_order_events_revisit_only_affected_windows(store):
    store.ingest([sudo_event(), key_event(), event("login", 20)])
    assert {c["rule_id"] for c in store.correlations()} == {"ssh_then_authorized_keys"}
    store.ingest([network_event()])
    store.ingest(list(reversed(failures())))
    assert len(store.correlations()) == 3
    assert store.ingest([])["correlations_created"] == 0


def test_pending_work_survives_restart_and_late_arrival_behind_cursor(tmp_path):
    path = tmp_path / "host.sqlite3"
    store = HostEventStore(path)
    # More than a single bounded page of anchors, all in one affected bucket.
    anchors = [event(f"login-{i:04d}", 20 + i / 1000) for i in range(300)]
    result = store.ingest(anchors)
    assert result["correlation_pending"] > 0 and store.correlations() == []
    store.close()
    store = HostEventStore(path)
    result = store.ingest(failures())
    for _ in range(12):
        if not result["correlation_pending"]:
            break
        result = store.ingest([])
    assert result["correlation_pending"] == 0
    assert len(store.correlations(limit=1000)) == 300
    store.close()


def test_pinned_evidence_is_unchanged_by_late_additional_matches(store):
    store.ingest(failures() + [event("login", 20)])
    original = store.correlations()[0]
    store.pin_correlation(original["id"], "CASE-12345678")
    store.ingest([event("late-failure", 19, kind="auth_failure", outcome="failure")])
    current = store.get_correlation(original["id"])
    assert current["event_ids"] == original["event_ids"]
    assert current["case_ids"] == ["CASE-12345678"]
