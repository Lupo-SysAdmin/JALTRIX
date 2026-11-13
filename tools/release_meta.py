"""Shared build version and deterministic timestamps for native packages."""

from datetime import datetime, timezone
import os
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
RELEASE_DATE = "2026-11-12"
EPOCH = int(
    os.environ.get(
        "SOURCE_DATE_EPOCH",
        str(
            int(
                datetime.fromisoformat(RELEASE_DATE)
                .replace(tzinfo=timezone.utc)
                .timestamp()
            )
        ),
    )
)


def source_fingerprint():
    """Identify executable sources, tests, recipes and CI; exclude generated/private data."""
    import hashlib

    digest = hashlib.sha256()
    paths = [ROOT / "pyproject.toml", ROOT / "run.sh"]
    for directory in ("src", "tests", "tools", "packaging", ".github"):
        paths.extend(p for p in (ROOT / directory).rglob("*") if p.is_file())
    for path in sorted(paths):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()
