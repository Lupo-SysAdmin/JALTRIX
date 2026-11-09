from pathlib import Path
import pytest
from jaltrix.engine import inspect_pcap, find_engine, replay
from jaltrix.snort import AlertStore
from jaltrix.integrations.edr import UnconfiguredEDR

LAB = Path(__file__).parent / "fixtures/lab"


def test_pcap_validation_and_hash(tmp_path):
    info = inspect_pcap(LAB / "benign.pcap")
    assert info["packets"] == 3
    assert len(info["sha256"]) == 64
    invalid = tmp_path / "bad.pcap"
    invalid.write_bytes((LAB / "benign.pcap").read_bytes()[:-1])
    with pytest.raises(ValueError):
        inspect_pcap(invalid)


def test_edr_fails_closed():
    edr = UnconfiguredEDR()
    assert not edr.discover_capabilities()["isolate"].available
    assert edr.list_endpoints() == []
    with pytest.raises(PermissionError):
        edr.isolate("any", "action-1")
    assert not edr.verify("any", "action-1")


@pytest.mark.parametrize("capture_name", ["benign.pcap", "benign.pcapng"])
def test_real_snort_offline(tmp_path, capture_name):
    if find_engine() is None:
        pytest.skip("Real Snort engine unavailable")
    info = replay(LAB / capture_name, LAB / "local.rules", tmp_path / "runs")
    store = AlertStore(tmp_path / "alerts.sqlite")
    result = store.ingest(info["log_path"], "replay")
    assert result["rejected"] == 0
    assert result["inserted"] == 2
    alerts = store.events("replay")
    assert all(e["src"] == "192.0.2.10" and e["rule_sid"] == 1000001 for e in alerts)
    assert all(e["timestamp_confidence"] == "epoch_seconds" for e in alerts)
    assert store.ingest(info["log_path"])["inserted"] == 0
    store.close()


def test_real_rule_validation(tmp_path):
    from jaltrix.engine import validate_draft

    if find_engine() is None:
        pytest.skip("Real Snort engine unavailable")
    assert validate_draft((LAB / "local.rules").read_text(), tmp_path)["valid"]
    assert not validate_draft(
        "alert udp any any -> any 9999 (not_a_real_option;)", tmp_path
    )["valid"]
