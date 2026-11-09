import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import zipfile
import pytest
from snort_soc.snort import AlertStore
from snort_soc.backup import create_backup, restore_backup


def test_two_writers_share_checkpoint_without_duplicates(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text(
        "".join(
            json.dumps({"rule": f"1:{n}:1", "src_addr": "192.0.2.1"}) + "\n"
            for n in range(300)
        )
    )
    database = tmp_path / "alerts.sqlite3"
    AlertStore(database).close()
    barrier = Barrier(2)

    def ingest():
        store = AlertStore(database)
        try:
            barrier.wait(timeout=5)
            return store.ingest(path, "live")["inserted"]
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(ingest) for _ in range(2)]
        assert sum(f.result(timeout=10) for f in futures) == 300
    store = AlertStore(database)
    assert store.count("live") == 300
    store.close()


def test_backup_open_wal_restore_and_integrity(tmp_path):
    root = tmp_path / "data"
    source = tmp_path / "alerts.json"
    source.write_text('{"rule":"1:42:1"}\n')
    store = AlertStore(root / "live/alerts.sqlite3")
    store.ingest(source, "live")
    (root / "settings.ini").write_text("[General]\nlanguage=en-US\n")
    archive = tmp_path / "backup.zip"
    result = create_backup(root, archive)
    assert result["files"] == 2 and archive.stat().st_mode & 0o077 == 0
    restored = tmp_path / "restored"
    restore_backup(archive, restored)
    restored_store = AlertStore(restored / "live/alerts.sqlite3")
    assert restored_store.count("live") == 1
    assert (restored / "settings.ini").read_bytes() == (
        root / "settings.ini"
    ).read_bytes()
    with pytest.raises(ValueError):
        restore_backup(archive, restored)
    with pytest.raises(ValueError):
        create_backup(root, root / "bad.zip")
    restored_store.close()
    store.close()
    corrupt = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(archive) as original, zipfile.ZipFile(corrupt, "w") as altered:
        for name in original.namelist():
            altered.writestr(
                name, b"altered" if name == "data/settings.ini" else original.read(name)
            )
    with pytest.raises(ValueError):
        restore_backup(corrupt, tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()


def test_restore_rejects_path_traversal(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr(
            "manifest.json",
            json.dumps(
                {
                    "format": "jaltrix-backup-v1",
                    "files": {"../escape": {"bytes": 0, "sha256": "x"}},
                }
            ),
        )
        stream.writestr("data/../escape", "")
    with pytest.raises(ValueError):
        restore_backup(archive, tmp_path / "restore")
    assert not (tmp_path / "escape").exists()


def test_collector_recovers_after_invalid_source_change(tmp_path):
    import os
    import subprocess
    import sys
    import time
    from pathlib import Path
    from snort_soc.collector import atomic_json

    source = tmp_path / "alerts.json"
    source.write_text('{"rule":"1:1:1"}\n')
    live = tmp_path / "live"
    live.mkdir()
    config = live / "collector.json"
    atomic_json(config, {"source": str(source)})
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    child = subprocess.Popen(
        [sys.executable, "-m", "snort_soc.collector", "--data-dir", str(tmp_path)],
        env=env,
        stderr=subprocess.PIPE,
    )

    def await_health(predicate):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                health = json.loads((live / "collector-health.json").read_text())
                if predicate(health):
                    return health
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        raise AssertionError("Collector failed to recover")

    try:
        await_health(lambda h: h.get("stored") == 1)
        atomic_json(config, {"source": str(tmp_path / "missing")})
        await_health(lambda h: h.get("state") == "error")
        atomic_json(config, {"source": str(source)})
        with source.open("a") as stream:
            stream.write('{"rule":"1:2:1"}\n')
        await_health(lambda h: h.get("stored") == 2 and h.get("state") == "following")
    finally:
        child.terminate()
        child.communicate(timeout=5)
