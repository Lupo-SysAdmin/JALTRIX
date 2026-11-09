"""Private, checksummed backups with online SQLite snapshots and safe fresh restores."""

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import zipfile

MAX_RESTORE_BYTES = 32 * 1024**3
MAX_FILES = 100000


def create_backup(data_dir, destination):
    root = Path(data_dir).resolve(strict=True)
    target = Path(destination).resolve()
    if target.is_relative_to(root):
        raise ValueError("Choose a backup destination outside the data directory")
    if not root.is_dir():
        raise ValueError("Data directory required")
    manifest = {"format": "jaltrix-backup-v1", "files": {}}
    with tempfile.TemporaryDirectory(prefix="jaltrix-backup-") as staging:
        snapshot = Path(staging) / "snapshot.sqlite3"
        fd, name = tempfile.mkstemp(prefix=target.name + ".", dir=target.parent)
        os.close(fd)
        temporary = Path(name)
        try:
            with zipfile.ZipFile(
                temporary, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                for path in sorted(root.rglob("*")):
                    if path.is_symlink():
                        raise ValueError("Backup refuses symbolic links")
                    if (
                        not path.is_file()
                        or path.name.endswith(("-wal", "-shm", ".lock", ".tmp"))
                        or path.name == "collector-health.json"
                    ):
                        continue
                    relative = path.relative_to(root).as_posix()
                    source = path
                    if path.suffix in (".sqlite", ".sqlite3"):
                        original = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
                        copied = sqlite3.connect(snapshot)
                        try:
                            original.backup(copied)
                            if (
                                copied.execute("PRAGMA integrity_check").fetchone()[0]
                                != "ok"
                            ):
                                raise ValueError("SQLite integrity check failed")
                        finally:
                            copied.close()
                            original.close()
                        source = snapshot
                    with (
                        source.open("rb") as input_file,
                        archive.open(
                            "data/" + relative, "w", force_zip64=True
                        ) as output_file,
                    ):
                        digest = hashlib.sha256()
                        size = 0
                        while chunk := input_file.read(1024 * 1024):
                            output_file.write(chunk)
                            digest.update(chunk)
                            size += len(chunk)
                    manifest["files"][relative] = {
                        "sha256": digest.hexdigest(),
                        "bytes": size,
                    }
                    if snapshot.exists():
                        snapshot.unlink()
                archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True))
            with temporary.open("rb") as stream:
                os.fsync(stream.fileno())
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    return {"kind": "backup", "path": str(target), "files": len(manifest["files"])}


def restore_backup(archive_path, destination):
    """Restore offline into a new directory only; never overwrite live evidence."""
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("Restore destination must not exist")
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if (
            len(entries) > MAX_FILES
            or len(names) != len(set(names))
            or sum(e.file_size for e in entries) > MAX_RESTORE_BYTES
        ):
            raise ValueError("Invalid backup size or duplicate entries")
        if archive.getinfo("manifest.json").file_size > 16 * 1024 * 1024:
            raise ValueError("Manifest too large")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("format") != "jaltrix-backup-v1" or not isinstance(
            manifest.get("files"), dict
        ):
            raise ValueError("Unsupported backup format")
        expected = {"manifest.json"}
        for relative, metadata in manifest["files"].items():
            path = Path(relative)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in relative
                or not path.parts
            ):
                raise ValueError("Unsafe backup path")
            expected.add("data/" + relative)
            if (
                not isinstance(metadata.get("bytes"), int)
                or not 0 <= metadata["bytes"] <= MAX_RESTORE_BYTES
            ):
                raise ValueError("Invalid entry size")
        if set(names) != expected:
            raise ValueError("Unexpected backup entries")
        with tempfile.TemporaryDirectory(
            prefix=destination.name + ".", dir=destination.parent
        ) as temp:
            stage = Path(temp) / "restored"
            stage.mkdir(mode=0o700)
            for relative, metadata in manifest["files"].items():
                path = stage / relative
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                digest = hashlib.sha256()
                size = 0
                with (
                    archive.open("data/" + relative) as source,
                    path.open("xb") as output,
                ):
                    path.chmod(0o600)
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > metadata["bytes"]:
                            raise ValueError("Backup size mismatch")
                        digest.update(chunk)
                        output.write(chunk)
                if (
                    size != metadata["bytes"]
                    or digest.hexdigest() != metadata["sha256"]
                ):
                    raise ValueError("Backup integrity mismatch")
                if path.suffix in (".sqlite", ".sqlite3"):
                    connection = sqlite3.connect(path)
                    try:
                        if (
                            connection.execute("PRAGMA integrity_check").fetchone()[0]
                            != "ok"
                        ):
                            raise ValueError("Invalid database")
                    finally:
                        connection.close()
            # The user explicitly selected an absent destination; rename does not merge data.
            if destination.exists():
                raise ValueError("Restore destination was created by another process")
            stage.rename(destination)
    return {"restored": str(destination), "files": len(manifest["files"])}
