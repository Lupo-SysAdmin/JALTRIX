import pytest
from snort_soc.response import ResponseStore
from snort_soc.core import CaseStore, demo_events


def test_proposals_audit_and_revoke(tmp_path):
    store = ResponseStore(tmp_path / "response.sqlite")
    identifier = store.propose("blocklist", "192.0.2.1", "Lab only")
    assert store.list()[0]["state"] == "CANDIDATE"
    assert store.verify_audit()
    store.revoke(identifier)
    store.revoke(identifier)
    assert store.list()[0]["state"] == "REVOKED"
    assert store.verify_audit()
    store.db.execute('UPDATE audit SET payload="tampered" WHERE seq=1')
    assert not store.verify_audit()
    store.close()


@pytest.mark.parametrize(
    "target", ["127.0.0.1", "0.0.0.0/0", "224.0.0.1", "192.0.2.0/24", "invalid"]
)
def test_reject_wide_or_protected_proposals(tmp_path, target):
    store = ResponseStore(tmp_path / "response.sqlite")
    with pytest.raises(ValueError):
        store.propose("blocklist", target, "test")
    store.close()


def test_case_notes_and_status_history(tmp_path):
    store = CaseStore(tmp_path / "cases.sqlite")
    identifier = store.create(demo_events()[0])
    store.update(identifier, "Reviewed evidence", "investigating")
    assert store.list()[0]["notes"] == "Reviewed evidence"
    assert store.db.execute("SELECT COUNT(*) FROM case_history").fetchone()[0] == 1
    with pytest.raises(ValueError):
        store.update(identifier, "", "fake-state")
    store.close()
