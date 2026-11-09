"""User-session systemd control for the rootless independent collector."""

import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone
from .collector import atomic_json

UNIT = "jaltrix-ingest.service"


def health(data_dir):
    try:
        value = json.loads((Path(data_dir) / "live/collector-health.json").read_text())
        age = (
            datetime.now(timezone.utc) - datetime.fromisoformat(value["heartbeat"])
        ).total_seconds()
        value["fresh"] = 0 <= age < 15 and value["state"] != "stopped"
        return value
    except (OSError, ValueError, KeyError):
        return dict(state="unavailable", fresh=False)


def control(data_dir, source=None, action="start"):
    if action not in ("start", "stop"):
        raise ValueError("Invalid collector action")
    if action == "start":
        source = Path(source).resolve(strict=True)
        if not source.is_file():
            raise ValueError("Source must be a regular file")
        directory = Path(data_dir).resolve() / "live"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            retention = json.loads((directory / "collector.json").read_text()).get(
                "retention_days", 0
            )
        except (OSError, ValueError):
            retention = 0
        atomic_json(
            directory / "collector.json",
            {"source": str(source), "retention_days": retention},
        )
        unit_dir = (
            Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
            / "systemd/user"
        )
        unit_dir.mkdir(parents=True, exist_ok=True)

        def quote(value):
            return (
                '"'
                + str(value)
                .replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("%", "%%")
                .replace("$", "$$")
                + '"'
            )

        entry = Path(__file__).with_name("worker_entry.py").resolve()
        args = " ".join(
            quote(v)
            for v in (sys.executable, entry, "--data-dir", Path(data_dir).resolve())
        )
        unit = (
            "[Unit]\nDescription=JALTRIX continuous alert ingestion\nConditionPathExists="
            + quote(entry)
            + "\n\n[Service]\nType=simple\nExecStart="
            + args
            + "\nRestart=on-failure\nRestartSec=3\nUMask=0077\nNoNewPrivileges=yes\n\n[Install]\nWantedBy=default.target\n"
        )
        destination = unit_dir / UNIT
        if destination.is_symlink():
            raise ValueError("Refusing symbolic unit path")
        destination.write_text(unit)
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            check=True,
            capture_output=True,
            timeout=15,
        )
        subprocess.run(
            ["systemctl", "--user", "enable", UNIT],
            check=True,
            capture_output=True,
            timeout=15,
        )
    subprocess.run(
        ["systemctl", "--user", "restart" if action == "start" else "stop", UNIT],
        check=True,
        capture_output=True,
        timeout=20,
    )
    return health(data_dir)
