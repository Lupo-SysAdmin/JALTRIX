"""Exercise first sensor creation in a disposable project VM, restoring its profile."""

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import time

assert platform.node().startswith("jaltrix-"), "Disposable VM only"
assert os.geteuid() == 0, "Run with sudo inside the lab VM"
unit = "jaltrix-sensor.service"
helper = "/usr/lib/jaltrix/jaltrix/privileged.py"
actor = os.environ.get("SUDO_UID", "1000")
backup = Path("/var/lib/jaltrix/setup-validation-backup")
assert not backup.exists(), "Previous test needs review"
paths = [
    Path("/etc/jaltrix"),
    Path("/var/log/jaltrix"),
    Path("/etc/systemd/system") / unit,
]
active = (
    subprocess.run(
        ["systemctl", "is-active", unit], capture_output=True, text=True
    ).stdout.strip()
    == "active"
)
enabled = (
    subprocess.run(
        ["systemctl", "is-enabled", unit], capture_output=True, text=True
    ).stdout.strip()
    == "enabled"
)
backup.mkdir(mode=0o700)
moved = []
created = False


def call(request):
    result = subprocess.run(
        ["/usr/bin/python3", "-I", helper],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        env=dict(os.environ, PKEXEC_UID=actor),
        timeout=120,
    )
    return result.returncode, json.loads(result.stdout)


request = dict(
    action="initialize",
    approved=True,
    reason="Disposable VM setup validation",
    engine="/usr/local/lib/jaltrix-engine/bin/snort",
    interface="lo",
    network="127.0.0.0/8",
    rules='alert udp any any -> any 19999 (msg:"JALTRIX onboarding connectivity"; content:"JALTRIX_SETUP_TEST"; sid:1000010; rev:1;)\n',
)
try:
    subprocess.run(["systemctl", "stop", unit], check=True)
    subprocess.run(["systemctl", "disable", unit], check=True)
    for index, path in enumerate(paths):
        if path.exists():
            saved = backup / str(index)
            path.rename(saved)
            moved.append((path, saved))
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    invalid = dict(
        request,
        rules="alert udp any any -> any 19999 (invalid_option; sid:1000011; rev:1;)",
    )
    code, result = call(invalid)
    assert code != 0, result
    assert not any(p.exists() for p in paths), "Failed validation left a profile"
    code, result = call(request)
    assert code == 0, result
    created = True
    assert (
        result["state"] == "verified" and not result["active"] and not result["enabled"]
    )
    assert (
        subprocess.run(
            ["systemctl", "is-active", unit], capture_output=True, text=True
        ).stdout.strip()
        == "inactive"
    )
    assert (
        subprocess.run(
            ["systemctl", "is-enabled", unit], capture_output=True, text=True
        ).stdout.strip()
        == "disabled"
    )
    digest = hashlib.sha256((paths[0] / "local.rules").read_bytes()).hexdigest()
    code, refused = call(request)
    assert code != 0 and "preserved" in refused["error"]
    assert hashlib.sha256((paths[0] / "local.rules").read_bytes()).hexdigest() == digest
    subprocess.run(["systemctl", "start", unit], check=True)
    time.sleep(2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for _ in range(3):
            sender.sendto(b"JALTRIX_SETUP_TEST", ("127.0.0.1", 19999))
            time.sleep(0.2)
    time.sleep(2)
    logfile = paths[1] / "alert_json.txt"
    read = subprocess.run(
        ["runuser", "-u", "jaltrix", "--", "cat", str(logfile)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "JALTRIX onboarding connectivity" in read.stdout
    report = dict(
        result="PASS",
        scope="New isolated sensor on Ubuntu VM: invalid rules reject before writes; creation stays inactive/disabled; existing profile protected; service start plus benign loopback UDP produces an alert readable by the operator",
        version=result,
    )
    Path("/home/jaltrix/setup-sensor-report.json").write_text(
        json.dumps(report, indent=2)
    )
    print(json.dumps(report))
finally:
    if created:
        subprocess.run(["systemctl", "stop", unit], check=True)
        for path in paths:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
    for path, saved in moved:
        assert not path.exists(), "Refusing to overwrite unexpected test state"
        saved.rename(path)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    if enabled:
        subprocess.run(["systemctl", "enable", unit], check=True)
    if active:
        subprocess.run(["systemctl", "start", unit], check=True)
    backup.rmdir()
