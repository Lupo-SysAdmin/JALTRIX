import copy
import pytest
from jaltrix.services import ServiceManager, manageable, UNITS


def state(active="inactive", boot="disabled", owner=":1.1"):
    return {
        "owner": owner,
        "units": [{"name": UNITS[0], "load": "loaded", "active": active, "boot": boot}],
    }


class FakeManager(ServiceManager):
    def __init__(self):
        self.state = state()
        self.calls = []
        self.fail_verify = False

    def snapshot(self):
        return copy.deepcopy(self.state)

    def call(self, owner, method, signature, args, reply, interactive=False, **kwargs):
        self.calls.append((method, args, interactive))
        if method in ("StartUnit", "StopUnit"):
            assert args[0] == "jaltrix-sensor.service"
            if not self.fail_verify:
                self.state["units"][0]["active"] = (
                    "active" if method == "StartUnit" else "inactive"
                )
            return ("/org/freedesktop/systemd1/job/1",)
        if method in ("EnableUnitFiles", "DisableUnitFiles"):
            assert args[0] == ["jaltrix-sensor.service"]
            self.state["units"][0]["boot"] = (
                "enabled" if method == "EnableUnitFiles" else "disabled"
            )
        return ()

    def wait_job(self, owner, job):
        pass


def test_start_stop_do_not_change_boot():
    m = FakeManager()
    m.apply("enable", m.snapshot())
    m.apply("start", m.snapshot())
    actual = m.apply("stop", m.snapshot())
    assert actual["units"][0]["active"] == "inactive"
    assert actual["units"][0]["boot"] == "enabled"
    assert all(interactive for _, _, interactive in m.calls)


def test_stale_state_and_unknown_action_are_rejected():
    m = FakeManager()
    previous = m.snapshot()
    m.state["units"][0]["active"] = "active"
    with pytest.raises(ValueError):
        m.apply("stop", previous)
    with pytest.raises(ValueError):
        m.apply("restart-anything", m.snapshot())
    assert m.calls == []


def test_queued_job_is_not_verified_success():
    m = FakeManager()
    m.fail_verify = True
    with pytest.raises(ValueError):
        m.apply("start", m.snapshot())


def test_masked_or_foreign_service_cannot_be_managed():
    m = FakeManager()
    m.state["units"][0]["boot"] = "masked"
    assert not manageable(m.snapshot())
    with pytest.raises(ValueError):
        m.apply("enable", m.snapshot())
    m.state = state()
    m.state["units"][0]["name"] = "unrelated.service"
    assert not manageable(m.snapshot())
