"""Administrative integration test. Only the managed loopback lab unit is touched."""

import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from jaltrix.services import ServiceManager

assert (
    Path("/etc/jaltrix/sensor.env").read_text().splitlines()[0] == "SNORT_INTERFACE=lo"
), "Lab-only test refused"
Path("/etc/jaltrix/sensor.env").write_text("SNORT_INTERFACE=lo\nSNORT_CHECKSUM=none\n")
shutil.copyfile(
    ROOT / "packaging/systemd/jaltrix-sensor.service",
    "/etc/systemd/system/jaltrix-sensor.service",
)
subprocess.run(["systemctl", "daemon-reload"], check=True)
manager = ServiceManager()
before = manager.snapshot()
assert (
    before["units"][0]["active"] == "inactive"
    and before["units"][0]["boot"] == "disabled"
), "Preserve existing running/boot state; test refused"
results = {"before": before, "steps": []}
try:
    for action in ["start", "enable", "stop", "start", "disable"]:
        result = manager.apply(action, manager.snapshot())
        results["steps"].append({"action": action, "state": result})
    # The service is now active and disabled at boot. Send only local benign traffic.
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 9999))
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    deadline = time.monotonic() + 10
    log = Path("/var/log/jaltrix/alert_json.txt")
    matched = False
    capture_started = int(time.time())
    while time.monotonic() < deadline:
        sender.sendto(b"SNORT_SOC_LAB service integration", ("127.0.0.1", 9999))
        time.sleep(0.3)
        if log.exists():
            for line in log.read_text().splitlines():
                record = json.loads(line)
                if (
                    record.get("src_addr") == "127.0.0.1"
                    and record.get("rule") == "1:1000001:1"
                    and record.get("seconds", 0) >= capture_started
                    and record.get("src_port") == sender.getsockname()[1]
                ):
                    matched = True
        if matched:
            break
    sender.close()
    receiver.close()
    assert matched, "No real loopback alert was recorded"
    results["loopback_alert"] = "PASS"
    # An independently executed engine process continues even without any GUI.
    properties = subprocess.check_output(
        [
            "systemctl",
            "show",
            "jaltrix-sensor.service",
            "-p",
            "User",
            "-p",
            "MainPID",
            "-p",
            "AmbientCapabilities",
        ],
        text=True,
    )
    results["service_properties"] = properties
    assert "User=jaltrix-sensor" in properties
    results["result"] = "PASS"
finally:
    manager.apply("stop", manager.snapshot())
    manager.apply("disable", manager.snapshot())
    results["after"] = manager.snapshot()
    path = ROOT / "artifacts/service-integration.json"
    path.write_text(json.dumps(results, indent=2))
    path.chmod(0o644)
print(json.dumps(results, indent=2))
