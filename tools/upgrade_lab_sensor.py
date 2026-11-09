"""Upgrade only the existing loopback lab unit; preserve its running/boot state."""

from pathlib import Path
import os, shutil, subprocess, runpy

assert os.geteuid() == 0 and os.environ.get("PKEXEC_UID")
root = Path(__file__).resolve().parents[1]
config = Path("/etc/snort-soc/sensor.env").read_text()
assert config.splitlines()[0] == "SNORT_INTERFACE=lo", (
    "Only loopback lab profiles are eligible"
)
engine = Path("/usr/local/lib/snort-soc-engine")
assert engine.stat().st_uid == 0 and not engine.is_symlink()
engine.chmod(0o755)
unit = Path("/etc/systemd/system/snort-soc.service")
assert "/usr/local/lib/snort-soc-engine/bin/snort" in unit.read_text()
active = (
    subprocess.run(
        ["systemctl", "is-active", "snort-soc.service"], capture_output=True, text=True
    ).stdout.strip()
    == "active"
)
backup = Path("/var/lib/jaltrix/snort-soc.service.before-v040")
if not backup.exists():
    shutil.copyfile(unit, backup)
shutil.copyfile(root / "packaging/systemd/snort-soc.service", unit)
unit.chmod(0o644)
subprocess.run(["systemctl", "daemon-reload"], check=True)
if active:
    subprocess.run(
        ["systemctl", "restart", "snort-soc.service"], check=True, timeout=45
    )
runpy.run_path(str(root / "tools/test_advanced_admin.py"), run_name="__main__")
