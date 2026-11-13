"""Exercise real journal/audit evidence in an explicitly authorized disposable Linux VM.

Run as the VM user over SSH (with a real login audit identity). No data/log bodies
are printed. The watch, exact authorized_keys bytes and new user unit are restored
in finally blocks. This does not install auditd or alter persistent audit rules.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import uuid


def run(arguments, *, check=True):
    return subprocess.run(
        arguments, check=check, text=True, capture_output=True, timeout=20
    )


def wait_for(function, *, seconds=35):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = function()
        if result:
            return result
        time.sleep(1)
    raise AssertionError("Timed out waiting for verified host collector state")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-disposable-lab", action="store_true", required=True)
    parser.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="Dev src directory or installed /usr/lib/jaltrix",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0 or not os.environ.get("SSH_CONNECTION"):
        raise SystemExit("Run as the disposable VM user through an actual SSH login")
    sys.path.insert(0, str(args.source_root.resolve()))
    from jaltrix.backup import create_backup, restore_backup
    from jaltrix.core import CaseStore
    from jaltrix.host_collector import collect_once
    from jaltrix.host_events import HostEventStore
    from jaltrix.host_service import UNIT, control, health, save_config

    target = Path.home() / ".ssh/authorized_keys"
    metadata = target.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise SystemExit(
            "Lab authorized_keys must be a regular file owned by this user"
        )
    original = target.read_bytes()
    original_digest = hashlib.sha256(original).hexdigest()
    unit = (
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        / "systemd/user"
        / UNIT
    )
    if unit.exists() or unit.is_symlink():
        raise SystemExit(
            "Refusing to overwrite a pre-existing host collector user unit"
        )
    assert run(["systemctl", "is-active", "auditd"]).stdout.strip() == "active"
    assert Path("/var/log/audit/audit.log").is_file() and os.access(
        "/var/log/audit/audit.log", os.R_OK
    )
    audit_uid = Path("/proc/self/loginuid").read_text().strip()
    assert audit_uid == str(os.getuid()), (
        "Actual SSH auid must identify the acting user"
    )
    key = "jaltrix_v130_" + uuid.uuid4().hex[:12]
    watch_added = service_created = changed = False
    summary = dict(
        result="FAIL",
        platform=Path("/etc/os-release").read_text().splitlines()[0],
        timestamp=datetime.now(timezone.utc).isoformat(),
        actual_sources=["journald", "auditd"],
        journal_auth_verified=False,
        sudo_rs_verified=False,
        audit_actor_verified=False,
        real_correlation="ssh_then_authorized_keys",
        automated_response=False,
    )
    try:
        with tempfile.TemporaryDirectory(prefix="jaltrix-host-v130-") as temporary:
            root = Path(temporary)
            data = root / "data"
            save_config(data, dict(journal_enabled=True, audit_enabled=True))
            run(["sudo", "-n", "auditctl", "-w", str(target), "-p", "wa", "-k", key])
            watch_added = True
            run(["sudo", "-n", "/usr/bin/true"])
            time.sleep(
                0.1
            )  # Ensure a strictly later audit timestamp than the real SSH login.
            changed = True
            with target.open("ab") as stream:
                stream.write(b"\n# JALTRIX disposable audit integration check\n")
                stream.flush()
                os.fsync(stream.fileno())
            # Restore immediately; only the transient comment was used to generate kernel evidence.
            target.write_bytes(original)
            changed = False
            assert hashlib.sha256(target.read_bytes()).hexdigest() == original_digest

            found = []
            for _ in range(25):
                collect_once(data)
                store = HostEventStore(data / "live/host-events.sqlite3")
                try:
                    found = [
                        item
                        for item in store.correlations()
                        if item["rule_id"] == "ssh_then_authorized_keys"
                    ]
                    journal_events = store.events(source="journal", limit=1000)
                    audited = store.events(
                        source="audit", kind="file_change", limit=1000
                    )
                    auth = [
                        event
                        for event in journal_events
                        if event["kind"] == "auth_success"
                        and event["user"] == Path.home().name
                    ]
                    sudo = [
                        event
                        for event in journal_events
                        if event["kind"] == "privilege_use"
                        and event["user"] == Path.home().name
                    ]
                    own_audit = [
                        event
                        for event in audited
                        if event["path"] == str(target)
                        and event["auid"] == os.getuid()
                        and any(key in line for line in event["raw_record"])
                    ]
                    if found and own_audit and auth and sudo:
                        break
                finally:
                    store.close()
                time.sleep(3.1)
            assert found and own_audit and auth and sudo, (
                "Missing real source/correlation evidence"
            )
            summary.update(
                journal_auth_verified=True,
                sudo_rs_verified=True,
                audit_actor_verified=True,
                journal_auth_events=len(auth),
                journal_sudo_events=len(sudo),
                watched_file_events=len(own_audit),
            )

            store = HostEventStore(data / "live/host-events.sqlite3")
            cases = CaseStore(data / "live/cases.sqlite3", mode="live")
            try:
                correlation = next(
                    item
                    for item in found
                    if any(
                        event["event_id"] in item["event_ids"] for event in own_audit
                    )
                )
                evidence_before = store.correlation_events(correlation["id"])
                assert any(event["source"] == "journal" for event in evidence_before)
                assert any(event["source"] == "audit" for event in evidence_before)
                case_id = cases.create(
                    dict(
                        event_id="host-correlation:" + correlation["id"],
                        mode="live",
                        message=correlation["title_en"],
                    )
                )
                store.pin_correlation(correlation["id"], case_id)
                retained = store.retain(days=1, max_events=1)
                assert store.correlation_events(correlation["id"]) == evidence_before
                assert retained["preserved"] >= 2
            finally:
                cases.close()
                store.close()
            summary.update(case_pin_verified=True, pinned_retention_verified=True)

            # Real user service runs independently of this one-shot process and any GUI.
            service_created = True
            control(data, action="start")
            first_health = wait_for(
                lambda: value if (value := health(data)).get("fresh") else None
            )
            first_pid = first_health["pid"]
            control(data, action="start")
            second_health = wait_for(
                lambda: (
                    value
                    if (value := health(data)).get("fresh")
                    and value.get("pid") != first_pid
                    else None
                )
            )
            summary.update(
                user_service_started=True,
                user_service_restarted=True,
                user_service_fresh=second_health["fresh"],
                service_sources={
                    name: status["state"]
                    for name, status in second_health["sources"].items()
                },
            )
            archive, restored = root / "backup.zip", root / "restored"
            create_backup(data, archive)
            restore_backup(archive, restored)
            assert not health(restored)["fresh"], (
                "Restored health must not claim original service is monitoring the restored data"
            )
            restored_store = HostEventStore(restored / "live/host-events.sqlite3")
            restored_cases = CaseStore(restored / "live/cases.sqlite3", mode="live")
            try:
                assert (
                    restored_store.correlation_events(correlation["id"])
                    == evidence_before
                )
                assert case_id in [case["id"] for case in restored_cases.list()]
            finally:
                restored_store.close()
                restored_cases.close()
            summary.update(backup_restore_verified=True, restored_health_stale=True)
            control(data, action="stop")
            assert not health(data)["fresh"]
            summary.update(user_service_stopped=True, result="PASS")
    finally:
        cleanup_errors = []
        if changed:
            target.write_bytes(original)
        summary["authorized_keys_restored"] = (
            hashlib.sha256(target.read_bytes()).hexdigest() == original_digest
        )
        if watch_added:
            removed = run(
                ["sudo", "-n", "auditctl", "-W", str(target), "-p", "wa", "-k", key],
                check=False,
            )
            if removed.returncode:
                cleanup_errors.append("Could not remove the test audit watch")
            listed = run(["sudo", "-n", "auditctl", "-l"], check=False)
            summary["audit_watch_removed"] = (
                listed.returncode == 0 and key not in listed.stdout
            )
        if (
            service_created
            and unit.exists()
            and ("# JALTRIX-Data-Dir=" + json.dumps(str(data.resolve())))
            in unit.read_text().splitlines()
        ):
            stopped = run(
                ["systemctl", "--user", "disable", "--now", UNIT], check=False
            )
            if stopped.returncode:
                cleanup_errors.append("Could not stop the test user service")
            unit.unlink(missing_ok=True)
            run(["systemctl", "--user", "daemon-reload"])
        if service_created:
            summary["user_unit_removed"] = not unit.exists()
        summary["cleanup_errors"] = cleanup_errors
        if cleanup_errors or not summary["authorized_keys_restored"]:
            summary["result"] = "FAIL"
        rendered = json.dumps(summary, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n")
        print(rendered)
        if cleanup_errors:
            raise AssertionError("Lab cleanup failed")


if __name__ == "__main__":
    main()
