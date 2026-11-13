from types import SimpleNamespace
import json
import os
import sys

import pytest

from jaltrix import linux_sources as sources

HOST = dict(host_id="test-host", hostname="test.local", boot_id="boot")


def journal(
    message="Accepted password for alice from 192.0.2.4 port 4567 ssh2", **extra
):
    return {
        "__CURSOR": "s=cursor",
        "__REALTIME_TIMESTAMP": "1760000000000000",
        "_BOOT_ID": "boot",
        "_EXE": "/usr/sbin/sshd",
        "_COMM": "sshd",
        "_UID": "0",
        "MESSAGE": message,
        **extra,
    }


def audit_lines(
    serial=1,
    *,
    success="yes",
    flags="441",
    auid="1000",
    path="/home/alice/.ssh/authorized_keys",
    eoe=True,
):
    result = [
        f'type=SYSCALL msg=audit(1760000000.123:{serial}): arch=c000003e syscall=257 success={success} exit=3 a0=ffffff9c a1=123 a2={flags} a3=1b6 items=1 auid={auid} uid=0 euid=0 exe="/usr/bin/tee"',
        f'type=CWD msg=audit(1760000000.123:{serial}): cwd="/home/alice"',
        f'type=PATH msg=audit(1760000000.123:{serial}): item=0 name="{path}" inode=22 nametype=NORMAL',
    ]
    if eoe:
        result.append(f"type=EOE msg=audit(1760000000.123:{serial}):")
    return result


@pytest.fixture(autouse=True)
def actor(monkeypatch):
    def account(uid):
        if uid == 1000:
            return SimpleNamespace(pw_name="alice", pw_dir="/home/alice")
        raise KeyError(uid)

    monkeypatch.setattr(sources.pwd, "getpwuid", account)


def test_journal_requires_trusted_executable_and_preserves_cursor():
    event = sources.journal_event(journal(), HOST)
    assert event["kind"] == "auth_success"
    assert event["user"] == "alice" and event["src_ip"] == "192.0.2.4"
    assert event["original_id"] == "s=cursor"
    assert event["timestamp"].endswith("+00:00")
    assert (
        sources.journal_event(
            journal(_EXE="/usr/bin/logger", SYSLOG_IDENTIFIER="sshd"), HOST
        )
        is None
    )
    assert sources.journal_event(journal(_UID="1000"), HOST) is None
    assert sources.journal_event(
        journal(_EXE="/usr/lib/openssh/sshd-session", _COMM="sshd-session"), HOST
    )
    failure = sources.journal_event(
        journal("Failed password for invalid user bob from 2001:db8::2 port 33 ssh2"),
        HOST,
    )
    assert failure["kind"] == "auth_failure" and failure["outcome"] == "failure"


def test_sudo_rs_preserves_acting_user_not_root_target():
    event = sources.journal_event(
        journal(
            "alice : PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/true",
            _EXE="/usr/lib/cargo/bin/sudo",
            _COMM="sudo",
            _UID="1000",
        ),
        HOST,
    )
    assert event["user"] == "alice" and event["target_user"] == "root"
    assert event["service"] == "sudo" and event["outcome_scope"] == "sudo_authorization"


def test_journal_persistent_cursor_and_stale_cursor_not_reset():
    calls = []

    def runner(args):
        calls.append(args)
        return dict(
            lines=[json.dumps(journal()).encode()],
            stderr="",
            returncode=0,
            limited=False,
        )

    events, cursor, status = sources.read_journal({}, HOST, runner)
    assert len(events) == 1 and cursor["cursor"] == "s=cursor"
    assert "--since=-15min" in calls[0]
    assert "--system" not in calls[0]  # sudo-rs can log as the invoking user.

    def stale(args):
        calls.append(args)
        return dict(
            lines=[], stderr="Failed to seek to cursor", returncode=1, limited=False
        )

    events, same, status = sources.read_journal(cursor, HOST, stale)
    assert not events and same == cursor and status["state"] == "cursor_unavailable"
    assert "--cursor=s=cursor" in calls[1]


def test_bounded_subprocess_retains_complete_lines():
    result = sources.bounded_command(
        [
            sys.executable,
            "-c",
            "import sys; [print('{\"n\":1}', flush=True) for _ in range(10000)]",
        ],
        max_lines=3,
    )
    assert result["limited"] and len(result["lines"]) == 3
    with pytest.raises(TimeoutError):
        sources.bounded_command(
            [sys.executable, "-c", "import time; time.sleep(3)"], timeout=0.1
        )


def test_audit_success_actor_hex_path_and_readonly_exclusion():
    lines = audit_lines()
    lines[2] = lines[2].replace(
        '"/home/alice/.ssh/authorized_keys"',
        "/home/alice/.ssh/authorized_keys".encode().hex(),
    )
    event = sources.audit_events(lines, "generation", HOST)[0]
    assert event["kind"] == "file_change"
    assert event["user"] == "alice" and event["auid"] == 1000
    assert (
        event["path"] == "/home/alice/.ssh/authorized_keys"
        and event["home_dir"] == "/home/alice"
    )
    assert event["outcome"] == "success" and event["boot_id"] is None
    assert (
        sources.audit_events(audit_lines(flags="0"), "g", HOST)[0]["kind"]
        == "system_event"
    )
    assert (
        sources.audit_events(audit_lines(success="no"), "g", HOST)[0]["outcome"]
        == "failure"
    )
    assert (
        sources.audit_events(audit_lines(auid="4294967295"), "g", HOST)[0]["user"]
        is None
    )


def test_audit_execve_arguments_decode_without_execution():
    lines = [
        'type=SYSCALL msg=audit(1760000000.123:1): arch=c000003e syscall=59 success=yes items=0 auid=1000 exe="/usr/bin/printf"',
        'type=EXECVE msg=audit(1760000000.123:1): argc=2 a0="printf" a1=68656c6c6f20776f726c64',
        "type=EOE msg=audit(1760000000.123:1):",
    ]
    event = sources.audit_events(lines, "g", HOST)[0]
    assert event["kind"] == "process_exec" and event["arguments"] == [
        "printf",
        "hello world",
    ]


def test_audit_restart_keeps_multipart_and_offset(tmp_path):
    path = tmp_path / "audit.log"
    lines = audit_lines()
    path.write_text("\n".join(lines[:2]) + "\n")
    first, checkpoint, status = sources.read_audit(path, host=HOST, now=100)
    assert not first and status["pending"] == 1
    # JSON round-trip simulates persistence/restart.
    checkpoint = json.loads(json.dumps(checkpoint))
    with path.open("a") as stream:
        stream.write("\n".join(lines[2:]) + "\n")
    events, checkpoint, status = sources.read_audit(path, checkpoint, HOST, now=101)
    assert len(events) == 1 and events[0]["kind"] == "file_change"
    assert len(events[0]["raw_record"]) == 4 and status["pending"] == 0
    assert sources.read_audit(path, checkpoint, HOST, now=110)[0] == []


def test_audit_rotation_drains_renamed_file_before_replacement(tmp_path):
    path = tmp_path / "audit.log"
    lines = audit_lines(1)
    path.write_text("\n".join(lines) + "\n")
    events, checkpoint, _ = sources.read_audit(path, host=HOST, now=100)
    with path.open("a") as stream:
        stream.write("\n".join(audit_lines(2)) + "\n")
    path.rename(tmp_path / "audit.log.1")
    path.write_text("\n".join(audit_lines(3)) + "\n")
    second, checkpoint, _ = sources.read_audit(path, checkpoint, HOST, now=101)
    assert [e["audit_serial"] for e in second] == ["2"]
    third, checkpoint, _ = sources.read_audit(path, checkpoint, HOST, now=102)
    assert [e["audit_serial"] for e in third] == ["3"]
    assert (
        len({events[0]["event_id"], second[0]["event_id"], third[0]["event_id"]}) == 3
    )


def test_audit_truncation_partial_line_and_unknown_contents(tmp_path):
    path = tmp_path / "audit.log"
    text = "\n".join(audit_lines()) + "\n"
    path.write_text(text)
    events, checkpoint, _ = sources.read_audit(path, host=HOST, now=100)
    path.write_text("ordinary text\n")
    after, next_checkpoint, status = sources.read_audit(path, checkpoint, HOST, now=101)
    assert not after and status["state"] == "invalid_records"
    assert next_checkpoint["generation"] != checkpoint["generation"]
    assert next_checkpoint["rejected_lines_total"] == 1
    path.write_text(text[:-1])
    events, checkpoint, status = sources.read_audit(path, host=HOST, now=100)
    assert checkpoint["offset"] < path.stat().st_size and not events


def test_audit_noeoe_waits_then_assembles_or_preserves_incomplete(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("\n".join(audit_lines(eoe=False)) + "\n")
    _, checkpoint, _ = sources.read_audit(path, host=HOST, now=100)
    events, _, _ = sources.read_audit(path, checkpoint, HOST, now=104)
    assert events[0]["kind"] == "file_change"
    path.write_text(audit_lines()[0] + "\n")
    _, checkpoint, _ = sources.read_audit(path, host=HOST, now=100)
    events, _, status = sources.read_audit(path, checkpoint, HOST, now=104)
    assert events[0]["kind"] == "system_event" and not events[0]["assembly_complete"]
    assert "Incomplete" in status["error"]


def test_audit_rejects_symlink_fifo_remote_node_and_oversize(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("\n".join("node=remote " + line for line in audit_lines()) + "\n")
    assert sources.read_audit(path, host=HOST)[0] == []
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        sources.read_audit(link, host=HOST)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        sources.read_audit(fifo, host=HOST)
    path.write_text("x" * (sources.MAX_RECORD + 5))
    with pytest.raises(ValueError):
        sources.read_audit(path, host=HOST)


def test_denied_sudo_command_is_not_successful_privilege_use():
    for reason in (
        "user NOT in sudoers",
        "command not allowed",
        "3 incorrect password attempts",
        "authentication failure",
    ):
        record = journal(
            f"alice : {reason} ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/true",
            _EXE="/usr/bin/sudo",
            _COMM="sudo",
        )
        assert sources.journal_event(record, HOST) is None


def test_missing_rotation_gap_is_explicit(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("\n".join(audit_lines()) + "\n")
    _, checkpoint, _ = sources.read_audit(path, host=HOST)
    # Keep the old inode occupied until a distinct replacement exists.
    path.rename(tmp_path / "old")
    path.write_text("\n".join(audit_lines(2)) + "\n")
    (tmp_path / "old").unlink()
    _, _, status = sources.read_audit(path, checkpoint, HOST)
    assert "no longer exists" in status["error"]


def test_large_noeoe_audit_backlog_progresses_in_bounded_restart_batches(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text(
        "\n".join(
            line for serial in range(1, 701) for line in audit_lines(serial, eoe=False)
        )
        + "\n"
    )
    checkpoint, events, offsets = {}, [], []
    for tick in range(40):
        batch, checkpoint, status = sources.read_audit(
            path, checkpoint, HOST, now=100 + tick * 4
        )
        checkpoint = json.loads(json.dumps(checkpoint))
        assert len(json.dumps(checkpoint).encode()) < 65536
        events.extend(batch)
        offsets.append(checkpoint["offset"])
        if checkpoint["offset"] == path.stat().st_size and not checkpoint["pending"]:
            break
    assert checkpoint["offset"] == path.stat().st_size and not checkpoint["pending"]
    files = [event for event in events if event["kind"] == "file_change"]
    assert len(files) == 700 and len({event["event_id"] for event in files}) == 700
    assert offsets == sorted(offsets)


def test_fedora_sshd_session_executable_is_recognized():
    event = sources.journal_event(
        journal(_EXE="/usr/libexec/openssh/sshd-session", _COMM="sshd-session"), HOST
    )
    assert event["kind"] == "auth_success" and event["service"] == "sshd"


def test_journal_resume_verifies_anchor_and_skips_only_that_event():
    original = {"cursor": "s=cursor", "initial_scope": "previous_15_minutes"}
    calls = []

    def runner(arguments):
        calls.append(arguments)
        return dict(
            lines=[
                json.dumps(journal()).encode(),
                json.dumps(journal(__CURSOR="next-cursor")).encode(),
            ],
            stderr="",
            returncode=0,
            limited=False,
        )

    events, checkpoint, status = sources.read_journal(original, HOST, runner)
    assert "--cursor=s=cursor" in calls[0]
    assert [event["original_id"] for event in events] == ["next-cursor"]
    assert checkpoint["cursor"] == "next-cursor" and status["examined"] == 1

    def idle(arguments):
        return dict(
            lines=[json.dumps(journal()).encode()],
            stderr="",
            returncode=0,
            limited=False,
        )

    events, checkpoint, status = sources.read_journal(original, HOST, idle)
    assert not events and checkpoint == original and status["state"] == "following"
    assert status["examined"] == 0


@pytest.mark.parametrize(
    "lines", [[json.dumps(journal(__CURSOR="nearest-retained-entry")).encode()], []]
)
def test_journal_vacuum_fallback_with_zero_exit_never_advances_checkpoint(lines):
    original = {"cursor": "well-formed-but-vacuumed-entry"}

    def nearest(arguments):
        return dict(lines=lines, stderr="", returncode=0, limited=False)

    events, checkpoint, status = sources.read_journal(original, HOST, nearest)
    assert events == [] and checkpoint == original
    assert status["state"] == "cursor_unavailable" and "retained" in status["error"]
