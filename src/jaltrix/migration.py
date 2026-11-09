"""One-time compatibility with pre-JALTRIX installations; never delete evidence.

Legacy aliases preserve absolute evidence links and external integrations. New
installations create only JALTRIX paths. No engine, rules or sensor is installed.
"""

import fcntl
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile

OLD_DATA = "snort-soc-desktop"
OLD_UNIT = "snort-soc.service"
NEW_UNIT = "jaltrix-sensor.service"
OLD_ACCOUNT = "snort-soc"
NEW_ACCOUNT = "jaltrix-sensor"
REPLACEMENTS = (
    ("/usr/lib/snort-soc-desktop/snort_soc/", "/usr/lib/jaltrix/jaltrix/"),
    ("/usr/local/lib/snort-soc-engine", "/usr/local/lib/jaltrix-engine"),
    ("/etc/snort-soc", "/etc/jaltrix"),
    ("/var/log/snort-soc", "/var/log/jaltrix"),
)


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=60)


def exists(path):
    return path.exists() or path.is_symlink()


def check_move(old, new):
    if not exists(old):
        return False
    if old.is_symlink():
        if new.is_dir() and old.resolve() == new.resolve():
            return False
        raise RuntimeError(f"Unexpected legacy symbolic link: {old}")
    if not old.is_dir() or exists(new):
        raise RuntimeError(
            f"Migration conflict; both locations preserved: {old}, {new}"
        )
    return True


def move_with_alias(old, new):
    if not check_move(old, new):
        return False
    old.rename(new)
    try:
        old.symlink_to(new.name, target_is_directory=True)
    except Exception:
        new.rename(old)
        raise
    return True


def user_data_dir(base=None, config=None):
    base = Path(base or os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    config = Path(config or os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    base.mkdir(parents=True, exist_ok=True)
    old, new = base / OLD_DATA, base / "jaltrix"
    # Serialize simultaneous GUI launches and prevent overwrite of two datasets.
    fd = os.open(
        base / ".jaltrix-migration.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        check_move(old, new)
        unit = config / "systemd/user/jaltrix-ingest.service"
        if unit.is_symlink():
            raise RuntimeError("Refusing symbolic collector unit")
        original = unit.read_text() if unit.exists() else ""
        updated = original
        for before, after in REPLACEMENTS:
            updated = updated.replace(before, after)
        updated = updated.replace(str(old), str(new))
        active = False
        if original != updated:
            active = (
                run(
                    "systemctl",
                    "--user",
                    "is-active",
                    "jaltrix-ingest.service",
                    check=False,
                ).returncode
                == 0
            )
            if active:
                run("systemctl", "--user", "stop", "jaltrix-ingest.service")
        try:
            move_with_alias(old, new)
            if original != updated:
                backup = unit.with_suffix(".service.before-jaltrix")
                if not backup.exists():
                    backup.write_text(original)
                    backup.chmod(0o600)
                temp = unit.with_suffix(".service.jaltrix-new")
                with temp.open("x") as output:
                    output.write(updated)
                temp.replace(unit)
                run("systemctl", "--user", "daemon-reload")
        finally:
            if active:
                run("systemctl", "--user", "start", "jaltrix-ingest.service")
    return new


def migrate_system():
    if os.geteuid() != 0:
        raise PermissionError(
            "System migration requires native administrator authentication"
        )
    unit_dir = Path("/etc/systemd/system")
    old_unit, new_unit = unit_dir / OLD_UNIT, unit_dir / NEW_UNIT
    if not old_unit.exists():
        return {"status": "unchanged", "reason": "No legacy managed sensor"}
    from importlib.util import spec_from_file_location, module_from_spec

    # This file also runs with python -I, without a package import path.
    spec = spec_from_file_location(
        "jaltrix_trust", Path(__file__).with_name("privileged.py")
    )
    helper = module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.trusted(old_unit)
    if exists(new_unit) or any(
        (unit_dir / (name + ".d")).exists() for name in (OLD_UNIT, NEW_UNIT)
    ):
        raise RuntimeError(
            "Existing new unit or service overrides preserved; manual review required"
        )
    pairs = [(Path(a), Path(b)) for a, b in REPLACEMENTS[1:]]
    for old, new in pairs:
        if check_move(old, new):
            if old != Path("/var/log/snort-soc"):
                helper.trusted(old)
    owner = pwd.getpwnam(OLD_ACCOUNT)
    if owner.pw_uid == 0:
        raise RuntimeError("Unexpected privileged legacy account")
    try:
        pwd.getpwnam(NEW_ACCOUNT)
    except KeyError:
        pass
    else:
        raise RuntimeError("New sensor account already exists; accounts preserved")
    original = old_unit.read_text()
    if (
        "/usr/local/lib/snort-soc-engine/bin/snort" not in original
        or "User=snort-soc" not in original
    ):
        raise RuntimeError("Unrecognized sensor unit; preserved for manual review")
    active = run("systemctl", "is-active", OLD_UNIT, check=False).returncode == 0
    enabled = run("systemctl", "is-enabled", OLD_UNIT, check=False).stdout.strip()
    if enabled not in ("enabled", "disabled"):
        raise RuntimeError(f"Unsupported legacy enable state preserved: {enabled}")
    state = Path("/var/lib/jaltrix")
    state.mkdir(mode=0o755, exist_ok=True)
    helper.trusted(state)
    backup = Path(tempfile.mkdtemp(prefix="migration-1.0.1-", dir=state))
    (backup / OLD_UNIT).write_text(original)
    (backup / "state.json").write_text(json.dumps(dict(active=active, enabled=enabled)))
    text = original
    for before, after in REPLACEMENTS:
        text = text.replace(before, after)
    text = text.replace("User=snort-soc", "User=jaltrix-sensor").replace(
        "Group=snort-soc", "Group=jaltrix-sensor"
    )
    text = text.replace("LogsDirectory=snort-soc", "LogsDirectory=jaltrix").replace(
        "Snort SOC managed", "JALTRIX managed"
    )
    moved, renamed_user, renamed_group = [], False, False
    try:
        run("systemctl", "stop", OLD_UNIT)
        run("systemctl", "disable", OLD_UNIT)
        run("usermod", "--login", NEW_ACCOUNT, OLD_ACCOUNT)
        renamed_user = True
        run("groupmod", "--new-name", NEW_ACCOUNT, OLD_ACCOUNT)
        renamed_group = True
        for old, new in pairs:
            if move_with_alias(old, new):
                moved.append((old, new))
        with new_unit.open("x") as output:
            output.write(text)
        new_unit.chmod(0o644)
        run("systemd-analyze", "verify", str(new_unit))
        old_unit.unlink()
        run("systemctl", "daemon-reload")
        if enabled == "enabled":
            run("systemctl", "enable", NEW_UNIT)
        if active:
            run("systemctl", "start", NEW_UNIT)
            run("systemctl", "is-active", NEW_UNIT)
    except Exception:
        run("systemctl", "stop", NEW_UNIT, check=False)
        run("systemctl", "disable", NEW_UNIT, check=False)
        new_unit.unlink(missing_ok=True)
        for old, new in reversed(moved):
            old.unlink()
            new.rename(old)
        if renamed_group:
            run("groupmod", "--new-name", OLD_ACCOUNT, NEW_ACCOUNT)
        if renamed_user:
            run("usermod", "--login", OLD_ACCOUNT, NEW_ACCOUNT)
        old_unit.write_text(original)
        run("systemctl", "daemon-reload")
        if enabled == "enabled":
            run("systemctl", "enable", OLD_UNIT)
        if active:
            run("systemctl", "start", OLD_UNIT)
        raise
    return {
        "status": "migrated",
        "active": active,
        "enabled": enabled,
        "backup": str(backup),
    }


if __name__ == "__main__":
    if sys.argv[1:] != ["--system"]:
        raise SystemExit("Usage: python3 -I migration.py --system")
    print(json.dumps(migrate_system()))
