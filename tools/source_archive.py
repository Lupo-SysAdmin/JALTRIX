"""Reproducible corresponding-source archive; excludes private lab/runtime data."""

import gzip
import os
from pathlib import Path
import tarfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "dist/snort-soc-desktop-1.0.0.tar.gz"
DEST.parent.mkdir(exist_ok=True)
EPOCH = int(
    os.environ.get(
        "SOURCE_DATE_EPOCH",
        str(int(datetime(2026, 11, 9, tzinfo=timezone.utc).timestamp())),
    )
)
names = [
    ".github",
    ".gitignore",
    "design/branding",
    "src",
    "packaging",
    "tools",
    "tests",
    "docs",
    "pyproject.toml",
    "LICENSE",
    "NOTICE",
    "AUTHORS",
    "README.md",
    "README.en.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "run.sh",
]


def clean(info):
    if "__pycache__" in info.name or info.name.endswith((".pyc", "MASTER_BRIEF_V2.md")):
        return None
    info.mode &= ~0o022
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = EPOCH
    info.pax_headers = {}
    return info


with (
    DEST.open("wb") as output,
    gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=EPOCH) as compressed,
    tarfile.open(fileobj=compressed, mode="w") as archive,
):
    for name in names:
        archive.add(
            ROOT / name, arcname="snort-soc-desktop-1.0.0/" + name, filter=clean
        )
print(DEST)
