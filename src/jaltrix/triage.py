"""Mode-separated optimistic triage with append-only local change history."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import getpass


class TriageStore:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path)
        path.chmod(0o600)
        self.db.executescript("""CREATE TABLE IF NOT EXISTS triage(event TEXT PRIMARY KEY, revision INTEGER, state TEXT, notes TEXT, tags TEXT, bookmark INTEGER);
        CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY,event TEXT,actor TEXT,timestamp TEXT,before_json TEXT,after_json TEXT);""")

    def get(self, event):
        row = self.db.execute(
            "SELECT revision,state,notes,tags,bookmark FROM triage WHERE event=?",
            (event,),
        ).fetchone()
        if row:
            return dict(
                revision=row[0],
                state=row[1],
                notes=row[2],
                tags=json.loads(row[3]),
                bookmark=bool(row[4]),
            )
        return dict(revision=0, state="new", notes="", tags=[], bookmark=False)

    def save(self, event, expected, state, notes, tags, bookmark):
        if (
            not event
            or len(event) > 128
            or state not in ("new", "investigating", "resolved", "false_positive")
        ):
            raise ValueError("Invalid triage event or state")
        if (
            len(notes) > 100000
            or len(tags) > 20
            or any(not isinstance(t, str) or len(t) > 80 for t in tags)
        ):
            raise ValueError("Triage content too large")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            before = self.get(event)
            if before["revision"] != expected:
                raise ValueError(
                    "Triage changed in another window; reload before saving"
                )
            after = dict(
                revision=expected + 1,
                state=state,
                notes=notes,
                tags=tags,
                bookmark=bool(bookmark),
            )
            self.db.execute(
                "INSERT OR REPLACE INTO triage VALUES (?,?,?,?,?,?)",
                (event, expected + 1, state, notes, json.dumps(tags), int(bookmark)),
            )
            self.db.execute(
                "INSERT INTO history(event,actor,timestamp,before_json,after_json) VALUES (?,?,?,?,?)",
                (
                    event,
                    getpass.getuser(),
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(before),
                    json.dumps(after),
                ),
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return after

    def all(self):
        return {
            event: dict(
                state=state, notes=notes, tags=json.loads(tags), bookmark=bool(bookmark)
            )
            for event, state, notes, tags, bookmark in self.db.execute(
                "SELECT event,state,notes,tags,bookmark FROM triage"
            )
        }

    def close(self):
        self.db.close()
