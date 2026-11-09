"""Local response proposals and tamper-evident audit; never modifies networking."""

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import sqlite3
import uuid


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class ResponseStore:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path)
        path.chmod(0o600)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS proposals (id TEXT PRIMARY KEY, kind TEXT, target TEXT, reason TEXT, expires TEXT, state TEXT);
            CREATE TABLE IF NOT EXISTS exceptions (proposal TEXT PRIMARY KEY, signature TEXT);
            CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, payload TEXT, previous TEXT, digest TEXT);
        """)

    def append_audit(self, event):
        previous = self.db.execute(
            "SELECT digest FROM audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous = previous[0] if previous else "0" * 64
        payload = canonical(event)
        digest = hashlib.sha256((previous + payload).encode()).hexdigest()
        self.db.execute(
            "INSERT INTO audit(payload,previous,digest) VALUES (?,?,?)",
            (payload, previous, digest),
        )

    def propose(self, kind, target, reason, hours=1):
        if (
            kind not in ("allowlist", "blocklist")
            or not reason.strip()
            or len(reason) > 4000
        ):
            raise ValueError("Invalid proposal type or reason")
        if not 1 <= hours <= 168:
            raise ValueError("Duration must be 1–168 hours")
        network = ipaddress.ip_network(target, strict=True)
        if network.num_addresses != 1:
            raise ValueError(
                "Only individual IP addresses are accepted in this version"
            )
        address = network.network_address
        if (
            address.is_loopback
            or address.is_multicast
            or address.is_unspecified
            or address.is_link_local
        ):
            raise ValueError("Protected address range")
        proposal_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(hours=hours)).isoformat()
        with self.db:
            self.db.execute(
                "INSERT INTO proposals VALUES (?,?,?,?,?,?)",
                (proposal_id, kind, str(address), reason, expires, "CANDIDATE"),
            )
            self.append_audit(
                dict(
                    action="propose",
                    id=proposal_id,
                    kind=kind,
                    target=str(address),
                    reason=reason,
                    timestamp=now.isoformat(),
                    expires=expires,
                    effect="local_only",
                )
            )
        return proposal_id

    def revoke(self, proposal_id):
        with self.db:
            row = self.db.execute(
                "SELECT state FROM proposals WHERE id=?", (proposal_id,)
            ).fetchone()
            if row is None:
                raise ValueError("Unknown proposal")
            if row[0] == "REVOKED":
                return
            self.db.execute(
                'UPDATE proposals SET state="REVOKED" WHERE id=?', (proposal_id,)
            )
            self.append_audit(
                dict(
                    action="revoke",
                    id=proposal_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            )

    def list(self):
        rows = []
        for row in self.db.execute("SELECT * FROM proposals ORDER BY rowid DESC"):
            item = dict(
                zip(["id", "kind", "target", "reason", "expires", "state"], row)
            )
            if item["state"] in (
                "CANDIDATE",
                "ACTIVE_TRIAGE",
            ) and datetime.fromisoformat(item["expires"]) < datetime.now(timezone.utc):
                item["state"] = "EXPIRED"
            rows.append(item)
        return rows

    def activate_triage(self, proposal_id, signature):
        import re

        if not re.fullmatch(r"\d+:\d+:\d+", signature):
            raise ValueError("Exact signature required")
        item = next((p for p in self.list() if p["id"] == proposal_id), None)
        if not item or item["kind"] != "allowlist" or item["state"] != "CANDIDATE":
            raise ValueError("Only an unexpired allowlist candidate can be activated")
        with self.db:
            self.db.execute(
                "INSERT INTO exceptions VALUES (?,?)", (proposal_id, signature)
            )
            self.db.execute(
                'UPDATE proposals SET state="ACTIVE_TRIAGE" WHERE id=?', (proposal_id,)
            )
            self.append_audit(
                dict(
                    action="activate_triage",
                    id=proposal_id,
                    signature=signature,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    effect="annotation_only",
                )
            )

    def exceptions(self):
        signatures = dict(self.db.execute("SELECT proposal,signature FROM exceptions"))
        return [
            dict(item, signature=signatures[item["id"]])
            for item in self.list()
            if item["state"] == "ACTIVE_TRIAGE" and item["id"] in signatures
        ]

    def verify_audit(self):
        previous = "0" * 64
        for payload, stored_previous, digest in self.db.execute(
            "SELECT payload,previous,digest FROM audit ORDER BY seq"
        ):
            if (
                previous != stored_previous
                or hashlib.sha256((previous + payload).encode()).hexdigest() != digest
            ):
                return False
            previous = digest
        return True

    def close(self):
        self.db.close()
