"""Exercise installed headless backup/restore against upgraded lab evidence."""

from pathlib import Path
import json, platform, sqlite3, subprocess, tempfile

assert platform.node().startswith("jaltrix-")
source = Path.home() / "upgrade-validation"
with tempfile.TemporaryDirectory(prefix="jaltrix-backup-check-") as temp:
    root = Path(temp)
    archive = root / "backup.zip"
    restored = root / "restored"
    for arguments in [
        ["--data-dir", str(source), "--backup", str(archive)],
        ["--data-dir", str(restored), "--restore", str(archive)],
    ]:
        subprocess.run(
            ["/usr/bin/snort-soc", *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    db = sqlite3.connect(restored / "replay/alerts.sqlite3")
    assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    db.close()
    assert (restored / "expected.json").read_bytes() == (
        source / "expected.json"
    ).read_bytes()
    assert archive.stat().st_mode & 0o077 == 0
    rejected = subprocess.run(
        ["/usr/bin/snort-soc", "--data-dir", str(restored), "--restore", str(archive)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert rejected.returncode != 0 and "Traceback" not in rejected.stderr
    print(
        json.dumps(
            {
                "result": "PASS",
                "hostname": platform.node(),
                "scope": "Installed CLI backup/restore; preserve upgraded evidence; reject overwrite",
            }
        )
    )
