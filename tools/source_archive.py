"""Reproducible corresponding-source archive; excludes private lab/runtime data."""

import gzip
import tarfile
from release_meta import EPOCH, ROOT, VERSION

DEST = ROOT / f"dist/jaltrix-{VERSION}.tar.gz"
DEST.parent.mkdir(exist_ok=True)
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
        archive.add(ROOT / name, arcname=f"jaltrix-{VERSION}/" + name, filter=clean)
print(DEST)
