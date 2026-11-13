"""Optional user-session service for host evidence, separate from Snort ingestion."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from .collector import atomic_json
from .linux_sources import local_host

UNIT = "jaltrix-host-events.service"
DEFAULTS = dict(
    journal_enabled=False,
    audit_enabled=False,
    audit_path="/var/log/audit/audit.log",
    snort_enabled=False,
    snort_host_binding=False,
    snort_source_id="",
    retention_days=30,
    max_events=100000,
)


def _validate(config):
    if not isinstance(config, dict):
        raise ValueError("Host source configuration must be an object")
    result = {**DEFAULTS, **{k: v for k, v in config.items() if k in DEFAULTS}}
    for key in (
        "journal_enabled",
        "audit_enabled",
        "snort_enabled",
        "snort_host_binding",
    ):
        if type(result[key]) is not bool:
            raise ValueError(f"{key} must be a boolean")
    for key, low, high in (("retention_days", 1, 3650), ("max_events", 1000, 1000000)):
        if type(result[key]) is not int or not low <= result[key] <= high:
            raise ValueError(f"{key} must be between {low} and {high}")
    if (
        not isinstance(result["audit_path"], str)
        or not Path(result["audit_path"]).is_absolute()
        or "\x00" in result["audit_path"]
    ):
        raise ValueError("Audit source must be an absolute file path")
    if (
        not isinstance(result["snort_source_id"], str)
        or len(result["snort_source_id"]) > 256
    ):
        raise ValueError("Invalid Snort source identity")
    if result["snort_enabled"] and (
        not result["snort_host_binding"] or not result["snort_source_id"]
    ):
        raise ValueError(
            "Select a live Snort source and explicitly bind it to this host first"
        )
    return result


def load_config(data_dir):
    try:
        config = json.loads((Path(data_dir) / "live/host-collector.json").read_text())
    except FileNotFoundError:
        return dict(DEFAULTS)
    return _validate(config)


read_config = load_config


def save_config(data_dir, config):
    value = _validate(config)
    directory = Path(data_dir) / "live"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_json(directory / "host-collector.json", value)
    return value


configure = save_config


def source_capabilities(config=None):
    config = _validate(config or DEFAULTS)
    path = Path(config["audit_path"])
    return dict(
        host=local_host(),
        journal=dict(
            available=bool(shutil.which("journalctl")),
            access="Verified when collecting; system journal permission is required",
        ),
        audit=dict(
            exists=path.exists(),
            readable=os.access(path, os.R_OK),
            path=str(path),
            coverage="Only existing records; auditd and appropriate rules must be configured separately",
        ),
        service=dict(available=bool(shutil.which("systemctl")), scope="user session"),
    )


def health(data_dir):
    try:
        value = json.loads(
            (Path(data_dir) / "live/host-collector-health.json").read_text()
        )
        age = (
            datetime.now(timezone.utc) - datetime.fromisoformat(value["heartbeat"])
        ).total_seconds()
        pid = value.get("pid")
        same_boot = value.get("boot_id") == local_host()["boot_id"]
        same_directory = value.get("data_dir") == str(Path(data_dir).resolve())
        alive = False
        if type(pid) is int and pid > 0:
            try:
                os.kill(pid, 0)
                # A reused PID must not turn old health into a healthy collector.
                alive = _process_start(pid) == value.get("process_start")
            except (ProcessLookupError, PermissionError, OSError):
                pass
        value["fresh"] = bool(
            0 <= age < 20
            and same_boot
            and same_directory
            and alive
            and value.get("state") != "stopped"
        )
        if not value["fresh"] and value.get("state") not in ("stopped", "disabled"):
            value["state"] = "stale"
        return value
    except (OSError, ValueError, TypeError, KeyError):
        return dict(state="unavailable", fresh=False, sources={})


def _process_start(pid):
    # comm can contain spaces and parentheses; fields after the final ')' start at field 3.
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def _quote(value):
    value = str(value)
    if any(c in value for c in "\n\r\x00"):
        raise ValueError("Control characters are not allowed in a systemd path")
    return (
        '"'
        + value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("%", "%%")
        .replace("$", "$$")
        + '"'
    )


def control(data_dir, action="start", config=None):
    if action not in ("start", "stop"):
        raise ValueError("Invalid host collector action")
    directory = Path(data_dir).resolve()
    unit_dir = (
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        / "systemd/user"
    )
    destination = unit_dir / UNIT
    marker = "# JALTRIX-Data-Dir=" + json.dumps(str(directory))
    if destination.is_symlink():
        raise ValueError("Refusing symbolic host collector unit")
    if destination.exists() and marker not in destination.read_text().splitlines():
        raise ValueError(
            "This user already has a host collector for another data directory. Manage it from its original JALTRIX instance first."
        )
    if config is not None:
        save_config(directory, config)
    if action == "start":
        settings = load_config(directory)
        if not any(
            settings[key]
            for key in ("journal_enabled", "audit_enabled", "snort_enabled")
        ):
            raise ValueError("Enable at least one host evidence source before starting")
        save_config(directory, settings)
        unit_dir.mkdir(parents=True, exist_ok=True)
        entry = Path(__file__).with_name("host_worker_entry.py").resolve()
        command = " ".join(
            _quote(v) for v in (sys.executable, entry, "--data-dir", directory)
        )
        unit = (
            marker
            + "\n"
            + "[Unit]\nDescription=JALTRIX optional Linux host evidence\n\n[Service]\nType=simple\nExecStart="
            + command
            + "\nRestart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=yes\n\n[Install]\nWantedBy=default.target\n"
        )
        fd = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "w") as stream:
            stream.write(unit)
        for arguments in (["daemon-reload"], ["enable", UNIT], ["restart", UNIT]):
            subprocess.run(
                ["systemctl", "--user", *arguments],
                check=True,
                capture_output=True,
                timeout=15,
            )
    else:
        # Stopping this optional collector also prevents an unexpected restart at next login.
        subprocess.run(
            ["systemctl", "--user", "disable", "--now", UNIT],
            check=True,
            capture_output=True,
            timeout=15,
        )
        destination.unlink(missing_ok=True)
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            check=True,
            capture_output=True,
            timeout=15,
        )
    return health(directory)
