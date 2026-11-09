"""Validate host-scope nft adapter only inside a disposable JALTRIX VM."""

import json, os, socket, subprocess, time
from pathlib import Path

assert socket.gethostname().startswith("jaltrix-") and os.geteuid() == 0
HELPER = "/usr/lib/jaltrix/jaltrix/privileged.py"


def run(args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)


def request(action, **kwargs):
    result = subprocess.run(
        ["/usr/bin/python3", "-I", HELPER],
        input=json.dumps(
            dict(
                action=action,
                reason="Disposable VM host firewall regression",
                approved=True,
                **kwargs,
            )
        ),
        env=dict(os.environ, PKEXEC_UID="1000"),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(json.loads(result.stdout))
    return json.loads(result.stdout)


policy = Path("/etc/jaltrix/response-policy.json")
assert not policy.exists(), "Existing policy preserved"
assert run(["nft", "list", "table", "inet", "jaltrix"], False).returncode != 0, (
    "Existing table preserved"
)
assert not Path("/run/netns/jaltrix-host-peer").exists()
try:
    run(["ip", "netns", "add", "jaltrix-host-peer"])
    run(["ip", "link", "add", "jxhost0", "type", "veth", "peer", "name", "jxpeer0"])
    run(["ip", "link", "set", "jxpeer0", "netns", "jaltrix-host-peer"])
    run(["ip", "addr", "add", "10.77.0.1/30", "dev", "jxhost0"])
    run(["ip", "link", "set", "jxhost0", "up"])
    run(
        [
            "ip",
            "-n",
            "jaltrix-host-peer",
            "addr",
            "add",
            "10.77.0.2/30",
            "dev",
            "jxpeer0",
        ]
    )
    run(["ip", "-n", "jaltrix-host-peer", "link", "set", "jxpeer0", "up"])

    def ping():
        return run(["ping", "-c", "1", "-W", "1", "10.77.0.2"], False).returncode == 0

    assert ping()
    request("configure_firewall", allowed="10.77.0.0/30", enabled=True)
    base = dict(scope="host", target="10.77.0.2", ttl=3)
    assert request("firewall_apply", **base)["effective"]
    assert not ping()
    time.sleep(3)
    assert not request("firewall_status", **base)["effective"]
    assert ping()
    for target in ["10.77.0.1", "127.0.0.1", "8.8.8.8"]:
        try:
            request("firewall_apply", scope="host", target=target, ttl=60)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Protected or out-of-policy target accepted")
    base["ttl"] = 60
    request("firewall_apply", **base)
    request("configure_firewall", allowed="10.77.0.0/30", enabled=False)
    assert not request("firewall_revoke", **base)["effective"] and ping()
    print(
        json.dumps(
            dict(
                result="PASS",
                scope="Ubuntu disposable VM host namespace",
                checks=[
                    "block real traffic",
                    "kernel TTL",
                    "protect own IP/loopback",
                    "reject out-of-policy target",
                    "revoke after disabling policy",
                ],
            ),
            indent=2,
        )
    )
finally:
    run(["nft", "delete", "table", "inet", "jaltrix"], False)
    policy.unlink(missing_ok=True)
    run(["ip", "link", "delete", "jxhost0"], False)
    run(["ip", "netns", "delete", "jaltrix-host-peer"], False)
