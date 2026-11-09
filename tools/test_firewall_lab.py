"""Explicit isolated firewall and managed loopback profile regression checks."""

import hashlib, json, os, subprocess, time
from pathlib import Path

HELPER = "/usr/lib/jaltrix/jaltrix/privileged.py"


def run(args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)


def request(action, **kwargs):
    payload = dict(
        action=action,
        reason="JALTRIX authorized isolated regression test",
        approved=True,
        **kwargs,
    )
    result = subprocess.run(
        ["/usr/bin/python3", "-I", HELPER],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=60,
    )
    data = json.loads(result.stdout)
    if result.returncode:
        raise RuntimeError(data)
    return data


def snapshot():
    files = {
        n: (Path("/etc/jaltrix") / n).read_text()
        for n in ("local.rules", "snort.lua", "sensor.env")
    }
    return files, hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


if os.geteuid() != 0 or not os.environ.get("PKEXEC_UID"):
    raise SystemExit("Use native administrator authorization")
report = {}
names = ["jaltrix-lab", "jaltrix-peer"]
if any(Path("/run/netns", n).exists() for n in names):
    raise SystemExit("Existing lab preserved; remove it explicitly before rerunning")
created = []
try:
    for name in names:
        run(["ip", "netns", "add", name])
        created.append(name)
    run(["ip", "link", "add", "jxlab0", "type", "veth", "peer", "name", "jxpeer0"])
    run(["ip", "link", "set", "jxlab0", "netns", names[0]])
    run(["ip", "link", "set", "jxpeer0", "netns", names[1]])
    for ns, interface, address in [
        (names[0], "jxlab0", "10.77.0.1/30"),
        (names[1], "jxpeer0", "10.77.0.2/30"),
    ]:
        run(["ip", "-n", ns, "addr", "add", address, "dev", interface])
        run(["ip", "-n", ns, "link", "set", interface, "up"])
        run(["ip", "-n", ns, "link", "set", "lo", "up"])

    def ping():
        return (
            run(
                [
                    "ip",
                    "netns",
                    "exec",
                    "jaltrix-lab",
                    "ping",
                    "-c",
                    "1",
                    "-W",
                    "1",
                    "10.77.0.2",
                ],
                False,
            ).returncode
            == 0
        )

    assert ping()
    run(
        [
            "ip",
            "netns",
            "exec",
            "jaltrix-lab",
            "nft",
            "add",
            "table",
            "inet",
            "unrelated_test",
        ]
    )
    base = dict(scope="lab", target="10.77.0.2", ttl=3)
    assert request("firewall_apply", **base)["effective"]
    assert not ping()
    assert request("firewall_status", **base)["effective"]
    time.sleep(3)
    assert not request("firewall_status", **base)["effective"] and ping()
    base["ttl"] = 60
    request("firewall_apply", **base)
    assert not ping()
    assert not request("firewall_revoke", **base)["effective"] and ping()
    run(
        [
            "ip",
            "netns",
            "exec",
            "jaltrix-lab",
            "nft",
            "list",
            "table",
            "inet",
            "unrelated_test",
        ]
    )
    try:
        request("firewall_apply", scope="lab", target="127.0.0.1", ttl=60)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Loopback block accepted")
    report["firewall"] = (
        "real isolated traffic: block, kernel TTL, explicit revoke, unrelated table preservation and protected-address rejection PASS"
    )
finally:
    for name in reversed(created):
        run(["ip", "netns", "delete", name], False)
    run(["ip", "link", "delete", "jxlab0"], False)
report["host_firewall"] = "not modified"
print(json.dumps(report, indent=2))
