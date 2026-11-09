"""Explicit administrator setup of an isolated loopback-only passive sensor.
Does not start/enable the service or overwrite an existing sensor configuration.
"""

from pathlib import Path
import os
import pwd
import shutil
import subprocess
import sys

if os.geteuid() != 0:
    raise SystemExit("Run through administrator authentication")
root = Path(__file__).resolve().parents[1]
operator = sys.argv[1]
pwd.getpwnam(operator)
config = Path("/etc/jaltrix")
if config.exists():
    raise SystemExit("Existing /etc/jaltrix preserved; setup refused")
source = root / ".runtime/snort-3.13.2.0"
if not (source / "bin/snort").is_file():
    raise SystemExit("Build the private engine first")
try:
    pwd.getpwnam("jaltrix-sensor")
except KeyError:
    subprocess.run(
        [
            "useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "jaltrix-sensor",
        ],
        check=True,
    )
engine = Path("/usr/local/lib/jaltrix-engine")
if engine.exists():
    raise SystemExit("Existing engine preserved; setup refused")
(engine / "bin").mkdir(parents=True, mode=0o755)
(engine / "lib").mkdir(mode=0o755)
engine.chmod(0o755)
shutil.copyfile(source / "bin/snort", engine / "bin/snort")
(engine / "bin/snort").chmod(0o755)
for name in ["libdaq.so.3.0.0", "libdaq.so.3", "libdaq.so"]:
    src, dst = source / "lib" / name, engine / "lib" / name
    if src.is_symlink():
        dst.symlink_to(os.readlink(src))
    else:
        shutil.copyfile(src, dst)
        dst.chmod(0o644)
config.mkdir(mode=0o755)
(config / "sensor.env").write_text("SNORT_INTERFACE=lo\nSNORT_CHECKSUM=none\n")
(config / "snort.lua").write_text(
    "ips = { enable_builtin_rules = false }\nalert_json = { file = true, limit = 32, fields = 'timestamp seconds pkt_num proto src_addr src_port dst_addr dst_port rule msg class priority action' }\n"
)
shutil.copyfile(root / "tests/fixtures/lab/local.rules", config / "local.rules")
for path in config.iterdir():
    path.chmod(0o644)
log = Path("/var/log/jaltrix")
log.mkdir(exist_ok=True, mode=0o750)
owner = pwd.getpwnam("jaltrix-sensor")
os.chown(log, owner.pw_uid, owner.pw_gid)
subprocess.run(["setfacl", "-m", f"u:{operator}:rx", str(log)], check=True)
subprocess.run(["setfacl", "-d", "-m", f"u:{operator}:rx", str(log)], check=True)
shutil.copyfile(
    root / "packaging/systemd/jaltrix-sensor.service",
    "/etc/systemd/system/jaltrix-sensor.service",
)
subprocess.run(["systemctl", "daemon-reload"], check=True)
subprocess.run(
    ["systemd-analyze", "verify", "/etc/systemd/system/jaltrix-sensor.service"],
    check=True,
)
print("Installed root-owned sensor profile on lo, stopped and disabled.")
