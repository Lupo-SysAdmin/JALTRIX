"""Read-only Linux evidence adapters. No privileges, audit rules or responses are changed."""

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import pwd
import re
import selectors
import socket
import stat
import subprocess
import time
import uuid

MAX_RECORD = 32768
MAX_BATCH = 500


def local_host():
    """Stable opaque machine identity; never export the machine-id itself."""
    machine = ""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            machine = Path(path).read_text().strip()
        except OSError:
            continue
        if machine:
            break
    hostname = socket.gethostname()
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        boot_id = None
    return dict(
        host_id=hashlib.sha256(
            ("jaltrix-host:" + (machine or hostname)).encode()
        ).hexdigest(),
        hostname=hostname,
        boot_id=boot_id,
        identity_basis="machine-id" if machine else "hostname",
    )


def _timestamp(seconds):
    try:
        return datetime.fromtimestamp(float(seconds), timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _event(source, original_id, host, **fields):
    return dict(
        event_id=hashlib.sha256(
            f"{source}:{host['host_id']}:{original_id}".encode()
        ).hexdigest(),
        original_id=original_id,
        source=source,
        host_id=host["host_id"],
        hostname=host["hostname"],
        **fields,
    )


def _integer(value):
    try:
        number = int(value)
        return number if 0 <= number < 4294967295 else None
    except (TypeError, ValueError):
        return None


def _journal_time(value):
    text = str(value or "")
    return (
        _timestamp(int(text) / 1_000_000)
        if text.isdigit() and len(text) <= 18
        else None
    )


def journal_event(record, host):
    """Only trusted journal metadata can classify a message as sshd/sudo/systemd."""
    if not isinstance(record, dict) or not isinstance(record.get("__CURSOR"), str):
        return None
    message = record.get("MESSAGE", "")
    if not isinstance(message, str):
        return None
    exe, comm = record.get("_EXE"), record.get("_COMM")
    details = dict(
        raw_record=record,
        boot_id=record.get("_BOOT_ID"),
        timestamp=_journal_time(record.get("__REALTIME_TIMESTAMP")),
        exe=exe,
        uid=_integer(record.get("_UID")),
        auid=_integer(record.get("_AUDIT_LOGINUID")),
        pid=_integer(record.get("_PID")),
    )
    fields = None
    if (
        exe
        in (
            "/usr/sbin/sshd",
            "/usr/bin/sshd",
            "/usr/lib/openssh/sshd-session",
            "/usr/lib/ssh/sshd-session",
            "/usr/libexec/openssh/sshd-session",
        )
        and comm in ("sshd", "sshd-session")
        and str(record.get("_UID")) == "0"
    ):
        match = re.match(
            r"(Accepted|Failed) (?:password|publickey|keyboard-interactive(?:/pam)?|none) for (?:invalid user )?(\S+) from (\S+) port (\d+)\b",
            message,
        )
        if match:
            try:
                address = str(ipaddress.ip_address(match[3]))
            except ValueError:
                return None
            success = match[1] == "Accepted"
            fields = dict(
                kind="auth_success" if success else "auth_failure",
                service="sshd",
                outcome="success" if success else "failure",
                user=match[2],
                src_ip=address,
                message=message,
                src_port=int(match[4]),
            )
    elif (
        exe
        in ("/usr/bin/sudo", "/bin/sudo", "/usr/lib/cargo/bin/sudo", "/usr/bin/sudo-rs")
        and comm == "sudo"
    ):
        match = re.match(
            r"\s*(\S+)\s*:\s*(?:(?:TTY|PWD|HOST)=[^;]*;\s*)+USER=([^;]+);\s*COMMAND=(.+)",
            message,
        )
        if match:
            # A policy-authorized sudo command is evidence of privilege use, not its exit status.
            fields = dict(
                kind="privilege_use",
                service="sudo",
                outcome="success",
                user=match[1],
                target_user=match[2].strip(),
                command=match[3],
                message=message,
                outcome_scope="sudo_authorization",
            )
    elif (
        exe in ("/usr/lib/systemd/systemd", "/lib/systemd/systemd")
        and str(record.get("_PID")) == "1"
    ):
        if re.match(
            r"(?:Started|Stopped|Starting|Stopping|Failed to start|Reloaded|Reloading)\b",
            message,
        ):
            fields = dict(
                kind="service_change",
                service="systemd",
                message=message,
                outcome="failure" if message.startswith("Failed") else "unknown",
                unit=record.get("UNIT"),
            )
    return (
        _event("journal", record["__CURSOR"], host, **details, **fields)
        if fields
        else None
    )


def bounded_command(arguments, *, timeout=8, max_lines=MAX_BATCH, max_bytes=2_000_000):
    """Read complete JSON lines without allowing a subprocess to fill unbounded memory."""
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C"},
    )
    selector = selectors.DefaultSelector()
    buffers = {"out": bytearray(), "err": bytearray()}
    lines, total, limited = [], 0, False
    deadline = time.monotonic() + timeout
    try:
        for stream, name in ((process.stdout, "out"), (process.stderr, "err")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError("journalctl exceeded the collection time limit")
            for key, _ in selector.select(
                min(0.1, max(0, deadline - time.monotonic()))
            ):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                buffers[key.data].extend(chunk)
                if key.data == "out":
                    while b"\n" in buffers["out"] and len(lines) < max_lines:
                        line, _, remaining = buffers["out"].partition(b"\n")
                        buffers["out"] = bytearray(remaining)
                        if len(line) > MAX_RECORD:
                            raise ValueError(
                                "journal record exceeds the safe record limit; cursor retained"
                            )
                        lines.append(bytes(line))
                if len(lines) >= max_lines or total >= max_bytes:
                    limited = True
                    break
                if len(buffers["out"]) > MAX_RECORD or len(buffers["err"]) > MAX_RECORD:
                    raise ValueError(
                        "journal output exceeds the safe record limit; cursor retained"
                    )
            if limited:
                break
        if limited:
            process.terminate()
        try:
            code = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            code = process.wait(timeout=1)
        return dict(
            lines=lines,
            stderr=buffers["err"].decode("utf-8", "replace")[:4096],
            returncode=code,
            limited=limited,
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        selector.close()
        process.stdout.close()
        process.stderr.close()


def read_journal(checkpoint=None, host=None, runner=bounded_command):
    host, checkpoint = host or local_host(), checkpoint or {}
    arguments = [
        "journalctl",
        "--output=json",
        "--no-pager",
        "--all",
        "--no-tail",
    ]
    if checkpoint.get("cursor"):
        arguments.append("--after-cursor=" + checkpoint["cursor"])
    else:
        arguments.append("--since=-15min")
    arguments += [
        "SYSLOG_IDENTIFIER=sshd",
        "SYSLOG_IDENTIFIER=sshd-session",
        "SYSLOG_IDENTIFIER=sudo",
        "SYSLOG_IDENTIFIER=systemd",
    ]
    result = runner(arguments)
    error = result["stderr"].strip()
    if result["returncode"] and not result["limited"]:
        state = (
            "permission_denied"
            if "permission" in error.lower()
            else "cursor_unavailable"
            if checkpoint.get("cursor")
            else "unavailable"
        )
        return [], checkpoint, dict(state=state, error=error or "journalctl failed")
    events, cursor, rejected = [], checkpoint.get("cursor"), 0
    for line in result["lines"]:
        try:
            record = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            # Without a cursor the line cannot be safely skipped on the next run.
            return (
                [],
                checkpoint,
                dict(
                    state="invalid_record",
                    error="Invalid journal JSON; cursor retained",
                ),
            )
        if not isinstance(record, dict) or not isinstance(record.get("__CURSOR"), str):
            return (
                [],
                checkpoint,
                dict(
                    state="invalid_record",
                    error="Missing journal cursor; cursor retained",
                ),
            )
        cursor = record["__CURSOR"]
        event = journal_event(record, host)
        if event:
            events.append(event)
        else:
            rejected += 1
    checkpoint = {
        **checkpoint,
        "cursor": cursor,
        "initial_scope": "previous_15_minutes",
    }
    return (
        events,
        checkpoint,
        dict(
            state="partial_access" if error else "following",
            error=error,
            examined=len(result["lines"]),
            ignored=rejected,
            backlog=result["limited"],
            initial_scope="previous_15_minutes",
        ),
    )


_AUDIT_ID = re.compile(r"\btype=(\w+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)")
_TOKEN = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*)=(\"(?:[^\"\\]|\\.)*\"|[^\s]+)")


def audit_fields(text):
    fields = {}
    for key, value in _TOKEN.findall(text):
        if value.startswith('"'):
            try:
                value = json.loads(value)
            except ValueError:
                value = value[1:-1]
        elif key in {"name", "exe", "cwd", "proctitle", "comm"} or re.fullmatch(
            r"a\d+", key
        ):
            if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
                # Syscall a0..a3 are register values; callers only decode EXECVE arguments.
                if not key.startswith("a"):
                    value = bytes.fromhex(value).decode("utf-8", "replace")
        fields[key] = value
    return fields


def _actor(auid):
    try:
        uid = int(auid)
        if uid < 0 or uid == 4294967295:
            return None, None
        account = pwd.getpwuid(uid)
        return account.pw_name, account.pw_dir
    except (ValueError, TypeError, KeyError):
        return None, None


def _write_syscall(fields):
    """Recognize successful write/metadata operations, never a plain read-only open."""
    syscall = fields.get("syscall", "")
    arch = fields.get("arch", "")
    # Audit numeric syscall IDs are architecture-specific.
    numbers = {
        "c000003e": {
            1: "write",
            2: "open",
            18: "pwrite64",
            20: "writev",
            59: "execve",
            76: "truncate",
            77: "ftruncate",
            82: "rename",
            83: "mkdir",
            84: "rmdir",
            85: "creat",
            86: "link",
            87: "unlink",
            88: "symlink",
            90: "chmod",
            91: "fchmod",
            92: "chown",
            93: "fchown",
            94: "lchown",
            257: "openat",
            258: "mkdirat",
            260: "fchownat",
            263: "unlinkat",
            264: "renameat",
            265: "linkat",
            266: "symlinkat",
            268: "fchmodat",
            316: "renameat2",
            322: "execveat",
        },
        "c00000b7": {
            35: "unlinkat",
            38: "renameat",
            46: "ftruncate",
            52: "fchmod",
            53: "fchmodat",
            54: "fchownat",
            56: "openat",
            64: "write",
            66: "writev",
            68: "pwrite64",
            221: "execve",
            276: "renameat2",
            281: "execveat",
        },
    }
    if syscall.isdigit():
        syscall = numbers.get(arch, {}).get(int(syscall), "unknown")
    if syscall in ("open", "openat"):
        try:
            flags = int(fields.get("a1" if syscall == "open" else "a2", ""), 16)
            return bool(
                flags
                & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            ), syscall
        except ValueError:
            return False, syscall
    return syscall in {
        "write",
        "pwrite64",
        "writev",
        "truncate",
        "ftruncate",
        "rename",
        "renameat",
        "renameat2",
        "mkdir",
        "mkdirat",
        "rmdir",
        "creat",
        "link",
        "linkat",
        "unlink",
        "unlinkat",
        "symlink",
        "symlinkat",
        "chmod",
        "fchmod",
        "fchmodat",
        "chown",
        "fchown",
        "lchown",
        "fchownat",
    }, syscall


def audit_events(lines, generation, host=None, *, complete=True):
    host = host or local_host()
    records = []
    for line in lines:
        match = _AUDIT_ID.search(line)
        if match:
            records.append(
                (match[1], audit_fields(match[4]), match[2], match[3], match[4])
            )
    if not records:
        return []
    syscall = next((r[1] for r in records if r[0] == "SYSCALL"), {})
    actor, home_dir = _actor(syscall.get("auid"))
    outcome = {"yes": "success", "no": "failure"}.get(syscall.get("success"), "unknown")
    writable, operation = _write_syscall(syscall)
    base = f"{generation}:{records[0][2]}:{records[0][3]}"
    details = dict(
        timestamp=_timestamp(records[0][2]),
        user=actor,
        auid=_integer(syscall.get("auid")),
        uid=_integer(syscall.get("uid")),
        pid=_integer(syscall.get("pid")),
        outcome=outcome,
        raw_record=lines,
        boot_id=None,
        audit_serial=records[0][3],
        assembly_complete=complete,
        service="auditd",
        exe=syscall.get("exe"),
        syscall=operation,
    )
    events = []
    cwd = next((r[1].get("cwd") for r in records if r[0] == "CWD"), None)
    if writable and complete:
        for index, (_, fields, *_rest) in enumerate(
            r for r in records if r[0] == "PATH"
        ):
            path = fields.get("name", "")
            if not path or path == "(null)" or fields.get("nametype") == "PARENT":
                continue
            if not path.startswith("/"):
                if not cwd or not cwd.startswith("/"):
                    continue
                path = posixpath.join(cwd, path)
            path = posixpath.normpath(path)
            events.append(
                _event(
                    "audit",
                    f"{base}:path:{index}",
                    host,
                    **details,
                    kind="file_change",
                    path=path,
                    home_dir=home_dir,
                    message=f"Audit {operation}: {path}",
                    change_scope="write_or_metadata_access",
                )
            )
    if operation in ("execve", "execveat") and complete:
        arguments = {}
        for record_type, _, _, _, raw_fields in records:
            if record_type != "EXECVE":
                continue
            for key, value in _TOKEN.findall(raw_fields):
                if re.fullmatch(r"a\d+", key):
                    if value.startswith('"'):
                        try:
                            value = json.loads(value)
                        except ValueError:
                            value = value[1:-1]
                    elif len(value) % 2 == 0 and re.fullmatch(r"[a-fA-F0-9]+", value):
                        value = bytes.fromhex(value).decode("utf-8", "replace")
                    arguments[int(key[1:])] = value
        events.append(
            _event(
                "audit",
                f"{base}:exec",
                host,
                **details,
                kind="process_exec",
                arguments=[arguments[k] for k in sorted(arguments)],
                message="Audit process execution",
            )
        )
    if not events:
        events.append(
            _event(
                "audit",
                base,
                host,
                **details,
                kind="system_event",
                message="Audit " + ", ".join(dict.fromkeys(r[0] for r in records)),
            )
        )
    return events


def _open_audit(path, checkpoint):
    candidate, warning = path, ""
    previous = (checkpoint.get("device"), checkpoint.get("inode"))
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if checkpoint and (current is None or (current.st_dev, current.st_ino) != previous):
        recovered = False
        for index, item in enumerate(path.parent.iterdir()):
            if index >= 1000:
                break
            try:
                info = item.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == previous:
                if info.st_size > checkpoint.get("offset", 0):
                    candidate = item
                recovered = True
                break
        if not recovered:
            warning = (
                "Rotated audit file no longer exists; an unread gap cannot be excluded"
            )
    fd = os.open(candidate, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("Audit source must be an existing regular file")
    return os.fdopen(fd, "rb"), warning


def _digest(stream, offset):
    stream.seek(max(0, offset - 128))
    return hashlib.sha256(stream.read(min(offset, 128))).hexdigest()


def read_audit(path, checkpoint=None, host=None, *, now=None, limit=MAX_BATCH):
    """Resume regular audit files; pending multipart evidence and offsets commit together."""
    path, host = Path(path), host or local_host()
    checkpoint = dict(checkpoint or {})
    now = time.time() if now is None else now
    pending = dict(checkpoint.get("pending", {}))
    events, invalid, examined = [], 0, 0
    capacity_limited = False
    stream, rotation_warning = _open_audit(path, checkpoint)
    with stream:
        info = os.fstat(stream.fileno())
        same = (info.st_dev, info.st_ino) == (
            checkpoint.get("device"),
            checkpoint.get("inode"),
        )
        offset = checkpoint.get("offset", 0) if same else 0
        warning = rotation_warning
        generation = checkpoint.get("generation") if same else uuid.uuid4().hex
        if same and (
            info.st_size < offset
            or _digest(stream, offset) != checkpoint.get("tail_digest")
        ):
            offset, generation = 0, uuid.uuid4().hex
            warning = "Audit file was truncated or rewritten; a gap cannot be excluded"
            # Preserve incomplete prior-generation evidence explicitly, without positive correlations.
            for group in pending.values():
                events.extend(
                    audit_events(
                        group["lines"], group["generation"], host, complete=False
                    )
                )
            pending = {}
        elif checkpoint and not same:
            warning = (
                rotation_warning
                or "Following rotated audit file; history depends on retained rotation files"
            )
        stream.seek(offset)
        for _ in range(limit):
            start = stream.tell()
            raw = stream.readline(MAX_RECORD + 1)
            if not raw:
                break
            if len(raw) > MAX_RECORD:
                raise ValueError(
                    "Audit record exceeds the safe record limit; checkpoint retained"
                )
            if not raw.endswith(b"\n"):
                stream.seek(start)
                break
            examined += 1
            line = raw.decode("utf-8", "replace").rstrip("\n")
            match = _AUDIT_ID.search(line)
            if not match:
                invalid += 1
                continue
            node = re.search(r"(?:^|\s)node=(\S+)", line[: match.start()])
            if node and node[1] != host["hostname"]:
                invalid += 1
                warning = "Remote-node audit records cannot be bound to this local host"
                continue
            # timestamp + serial prevents collisions across reboot; generation distinguishes rewrites.
            key = f"{match[2]}:{match[3]}"
            group = pending.setdefault(
                key, dict(lines=[], generation=generation, seen=now)
            )
            group["lines"].append(line)
            if len(json.dumps(pending).encode()) > 48000:
                # Commit already-read evidence and retry this complete line next batch.
                group["lines"].pop()
                if not group["lines"]:
                    del pending[key]
                stream.seek(start)
                examined -= 1
                capacity_limited = True
                break
            group["seen"] = now
            if match[1] == "EOE":
                events.extend(audit_events(group["lines"], group["generation"], host))
                del pending[key]
        offset = stream.tell()
        at_end = offset >= info.st_size
        if pending:
            # A busy log may never reach EOF; aged groups still need bounded progress.
            newest_key = next(reversed(pending))
            for key, group in list(pending.items()):
                if key == newest_key and not at_end and not capacity_limited:
                    continue
                if now - group["seen"] < 3:
                    continue
                parsed = [_AUDIT_ID.search(line) for line in group["lines"]]
                syscall = next(
                    (audit_fields(m[4]) for m in parsed if m and m[1] == "SYSCALL"),
                    None,
                )
                path_count = sum(bool(m and m[1] == "PATH") for m in parsed)
                complete = syscall is None or (
                    str(syscall.get("items", "")).isdigit()
                    and path_count == int(syscall["items"])
                )
                events.extend(
                    audit_events(
                        group["lines"], group["generation"], host, complete=complete
                    )
                )
                if not complete:
                    warning = "Incomplete audit multipart event retained as uncorrelated evidence"
                del pending[key]
        checkpoint = dict(
            device=info.st_dev,
            inode=info.st_ino,
            generation=generation,
            offset=offset,
            tail_digest=_digest(stream, offset),
            pending=pending,
            rejected_lines_total=checkpoint.get("rejected_lines_total", 0) + invalid,
        )
    state = "invalid_records" if invalid else "reading_existing_log"
    return (
        events,
        checkpoint,
        dict(
            state=state,
            error=warning,
            examined=examined,
            rejected_lines=invalid,
            pending=len(pending),
            backlog=not at_end,
            capacity_limited=capacity_limited,
            coverage="Existing audit records only; auditd, suitable rules and read permission are required",
        ),
    )
