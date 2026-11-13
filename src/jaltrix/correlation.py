"""Explainable, bounded, local temporal correlations; never automated response.

A durable queue revisits only affected host/time buckets, including when an older
record arrives late. Readers never run correlation scans. Correlation IDs depend
on their rule and anchor observation, and evidence is immutable once matched.
"""

from datetime import datetime
import hashlib
import json
import posixpath

BUCKET_SECONDS = 600
MAX_BUCKETS_PER_PASS = 4
MAX_ANCHORS_PER_BUCKET = 128
MAX_LOGINS_PER_SUDO = 64
UNKNOWN_USERS = frozenset(("", "?", "-", "unknown", "(unknown)", "unset"))


def schedule(db, host_id, epoch):
    bucket = int(epoch // BUCKET_SECONDS)
    # An observation can contribute only to anchors at or after its timestamp,
    # within ten minutes. Two buckets cover that entire possible interval.
    for affected in (bucket, bucket + 1):
        db.execute(
            "INSERT INTO host_correlation_work(host_id,bucket) VALUES (?,?) "
            "ON CONFLICT(host_id,bucket) DO UPDATE SET generation=generation+1",
            (host_id, affected),
        )


def _known_user(event):
    user = event.get("user")
    return isinstance(user, str) and user.strip().lower() not in UNKNOWN_USERS


def _login(event):
    return (
        event["source"] == "journal"
        and event["service"] == "sshd"
        and event["kind"] == "auth_success"
        and event["outcome"] == "success"
        and _known_user(event)
        and bool(event.get("src_ip"))
    )


def _authorized_keys(event):
    path = event.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    normalized = posixpath.normpath(path)
    parts = normalized.split("/")
    conventional = normalized == "/root/.ssh/authorized_keys" or (
        len(parts) == 5
        and parts[1] == "home"
        and parts[2] not in ("", ".", "..")
        and parts[3:] == [".ssh", "authorized_keys"]
    )
    home = event.get("home_dir")
    actual_home = (
        isinstance(home, str)
        and home.startswith("/")
        and posixpath.normpath(home) != "/"
        and normalized
        == posixpath.join(posixpath.normpath(home), ".ssh/authorized_keys")
    )
    return conventional or actual_home


def _epoch(event):
    return datetime.fromisoformat(event["timestamp"]).timestamp()


def _store(db, rule, anchor, evidence, window, title, title_en, reason, reason_en):
    identity = json.dumps(
        [rule, anchor["host_id"], anchor["event_id"]], separators=(",", ":")
    )
    correlation_id = "hc-" + hashlib.sha256(identity.encode()).hexdigest()
    result = {
        "id": correlation_id,
        "rule_id": rule,
        "title": title,
        "title_en": title_en,
        "host_id": anchor["host_id"],
        "hostname": anchor["hostname"],
        "timestamp": anchor["timestamp"],
        "severity": "Alta",
        "window_seconds": window,
        "observed_seconds": max(_epoch(e) for e in evidence)
        - min(_epoch(e) for e in evidence),
        "user": anchor["user"],
        "src_ip": next((e["src_ip"] for e in evidence if e.get("src_ip")), None),
        "explanation": reason
        + " Es una asociación temporal para investigar; no demuestra una intrusión ni ejecuta respuestas.",
        "explanation_en": reason_en
        + " This is a temporal association for investigation; it does not prove a compromise or execute responses.",
        "automatic_response": False,
        "evidence_count": len(evidence),
    }
    inserted = db.execute(
        "INSERT OR IGNORE INTO host_correlations VALUES (?,?,?,?,?)",
        (
            correlation_id,
            rule,
            anchor["host_id"],
            anchor["timestamp"],
            json.dumps(result, ensure_ascii=False, sort_keys=True),
        ),
    ).rowcount
    if inserted:
        db.executemany(
            "INSERT INTO host_correlation_events VALUES (?,?)",
            ((correlation_id, e["event_id"]) for e in evidence),
        )
    return inserted


def _failures_then_success(db, anchor, epoch):
    if not _login(anchor):
        return 0
    rows = db.execute(
        "SELECT data FROM host_events WHERE host_id=? AND kind='auth_failure' "
        "AND user=? AND src_ip=? AND event_time>=? AND event_time<? "
        "AND source='journal' AND service='sshd' AND outcome='failure' "
        "ORDER BY event_time DESC,id LIMIT 5",
        (anchor["host_id"], anchor["user"], anchor["src_ip"], epoch - 300, epoch),
    ).fetchall()
    if len(rows) < 5:
        return 0
    evidence = [json.loads(row[0]) for row in reversed(rows)] + [anchor]
    return _store(
        db,
        "ssh_failures_then_success",
        anchor,
        evidence,
        300,
        "Fallos SSH seguidos de acceso correcto",
        "SSH failures followed by a successful login",
        f"Al menos 5 fallos SSH y un acceso correcto en 300 s comparten host {anchor['host_id']}, usuario {anchor['user']} e IP {anchor['src_ip']}. Se conservan 5 fallos como evidencia.",
        f"At least 5 SSH failures and a successful login within 300 s share host {anchor['host_id']}, user {anchor['user']} and IP {anchor['src_ip']}. Five failures are retained as evidence.",
    )


def _login_then_keys(db, anchor, epoch):
    if not (
        anchor["source"] == "audit"
        and anchor["kind"] == "file_change"
        and anchor["outcome"] == "success"
        and _known_user(anchor)
        and type(anchor.get("auid")) is int
        and 0 <= anchor["auid"] < 4294967295
        and _authorized_keys(anchor)
    ):
        return 0
    row = db.execute(
        "SELECT data FROM host_events WHERE host_id=? AND kind='auth_success' "
        "AND user=? AND event_time>=? AND event_time<? "
        "AND source='journal' AND service='sshd' AND outcome='success' AND src_ip IS NOT NULL "
        "ORDER BY event_time DESC,id LIMIT 1",
        (anchor["host_id"], anchor["user"], epoch - 600, epoch),
    ).fetchone()
    if row is None:
        return 0
    login = json.loads(row[0])
    return _store(
        db,
        "ssh_then_authorized_keys",
        anchor,
        [login, anchor],
        600,
        "Acceso SSH y operación sobre authorized_keys",
        "SSH login and authorized_keys write/metadata operation",
        f"Un acceso SSH y una operación auditada correcta de escritura o metadatos sobre {anchor['path']} en 600 s comparten host {anchor['host_id']} y usuario actor {anchor['user']} (auid={anchor['auid']}). Una apertura con permisos de escritura no demuestra modificación del contenido. No se usa la cuenta destino de sudo como identidad del actor.",
        f"An SSH login and a successful audited write/metadata operation on {anchor['path']} within 600 s share host {anchor['host_id']} and acting user {anchor['user']} (auid={anchor['auid']}). Opening a file for writing does not prove a content modification. The sudo target account is not used as the actor identity.",
    )


def _network_login_sudo(db, anchor, epoch):
    if not (
        anchor["source"] == "journal"
        and anchor["kind"] == "privilege_use"
        and anchor["service"] == "sudo"
        and anchor["outcome"] == "success"
        and _known_user(anchor)
    ):
        return 0
    # A bounded list prevents a burst from creating an unbounded join. If more
    # than 64 logins fit, only the most recent 64 are candidates for this rule.
    logins = db.execute(
        "SELECT data,event_time FROM host_events WHERE host_id=? AND kind='auth_success' "
        "AND user=? AND event_time>=? AND event_time<? "
        "AND source='journal' AND service='sshd' AND outcome='success' AND src_ip IS NOT NULL "
        "ORDER BY event_time DESC,id LIMIT ?",
        (anchor["host_id"], anchor["user"], epoch - 600, epoch, MAX_LOGINS_PER_SUDO),
    ).fetchall()
    for data, login_time in logins:
        login = json.loads(data)
        row = db.execute(
            "SELECT data FROM host_events WHERE host_id=? AND kind='network_alert' "
            "AND src_ip=? AND event_time>=? AND event_time<? AND source='snort' "
            "AND json_extract(data,'$.host_bound')=1 AND json_extract(data,'$.dst_port')=22 "
            "ORDER BY event_time DESC,id LIMIT 1",
            (anchor["host_id"], login["src_ip"], epoch - 600, login_time),
        ).fetchone()
        if row is None:
            continue
        network = json.loads(row[0])
        return _store(
            db,
            "network_ssh_sudo",
            anchor,
            [network, login, anchor],
            600,
            "Alerta de red, acceso SSH y uso de sudo",
            "Network alert, SSH login and sudo use",
            f"Una alerta Snort al puerto 22 vinculada explícitamente al host {anchor['host_id']}, un acceso SSH desde {login['src_ip']} y sudo correcto del usuario {anchor['user']} aparecen en ese orden dentro de 600 s. SSH y sudo comparten identidad del actor; la alerta y SSH comparten IP origen.",
            f"A Snort alert to port 22 explicitly bound to host {anchor['host_id']}, an SSH login from {login['src_ip']} and successful sudo by user {anchor['user']} occur in that order within 600 s. SSH and sudo share the actor identity; the alert and SSH share the source IP.",
        )
    return 0


def process_pending(db):
    """Process a bounded amount inside the collector's existing transaction."""
    created = 0
    jobs = db.execute(
        "SELECT host_id,bucket,generation,scan_generation,cursor_time,cursor_id "
        "FROM host_correlation_work ORDER BY bucket,host_id LIMIT ?",
        (MAX_BUCKETS_PER_PASS,),
    ).fetchall()
    for host_id, bucket, generation, scan_generation, cursor_time, cursor_id in jobs:
        lower, upper = bucket * BUCKET_SECONDS, (bucket + 1) * BUCKET_SECONDS
        if cursor_time is None:
            scan_generation = generation
            cursor_time = lower
            cursor_id = ""
        rows = db.execute(
            "SELECT data,event_time,id FROM host_events WHERE host_id=? "
            "AND event_time>=? AND event_time<? "
            "AND (event_time>? OR (event_time=? AND id>?)) "
            "AND kind IN ('auth_success','file_change','privilege_use') "
            "ORDER BY event_time,id LIMIT ?",
            (
                host_id,
                lower,
                upper,
                cursor_time,
                cursor_time,
                cursor_id,
                MAX_ANCHORS_PER_BUCKET,
            ),
        ).fetchall()
        for data, epoch, _ in rows:
            anchor = json.loads(data)
            if anchor["kind"] == "auth_success":
                created += _failures_then_success(db, anchor, epoch)
            elif anchor["kind"] == "file_change":
                created += _login_then_keys(db, anchor, epoch)
            else:
                created += _network_login_sudo(db, anchor, epoch)
        if len(rows) == MAX_ANCHORS_PER_BUCKET:
            db.execute(
                "UPDATE host_correlation_work SET cursor_time=?,cursor_id=?,scan_generation=? WHERE host_id=? AND bucket=?",
                (rows[-1][1], rows[-1][2], scan_generation, host_id, bucket),
            )
        elif generation != scan_generation:
            db.execute(
                "UPDATE host_correlation_work SET cursor_time=NULL,cursor_id='',scan_generation=generation WHERE host_id=? AND bucket=?",
                (host_id, bucket),
            )
        else:
            db.execute(
                "DELETE FROM host_correlation_work WHERE host_id=? AND bucket=?",
                (host_id, bucket),
            )
    return created
