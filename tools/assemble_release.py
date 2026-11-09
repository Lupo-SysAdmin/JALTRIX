"""Assemble the reviewed local release, with sources, hashes and explicit limits."""

import hashlib, json, re, shutil, subprocess, tarfile, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
VERSION = "1.0.0"
validation = json.loads((ROOT / "docs/evidence/1.0.0/validation.json").read_text())
for distro in ("ubuntu", "arch", "fedora", "parrot"):
    report = json.loads((ROOT / f"artifacts/{distro}-vm-report-v100.json").read_text())
    assert report["tests_exit"] == report["gui_exit"] == 0, distro
for name in ("soak-v100.json", "soak-fast-v100.json"):
    assert json.loads((ROOT / "artifacts" / name).read_text())["result"] == "PASS"
assert "45 passed" in (ROOT / "artifacts/tests-v100.log").read_text()
assert not any(
    line.startswith("E:")
    for line in (ROOT / "artifacts/lintian-v100.log").read_text().splitlines()
)
paths = [
    DIST / "snort-soc-desktop_1.0.0-1_all.deb",
    DIST / "snort-soc-desktop-1.0.0-1.noarch.rpm",
    DIST / "snort-soc-desktop-1.0.0-1-any.pkg.tar.zst",
    DIST / "snort-soc-desktop-1.0.0.tar.gz",
]
assert all(p.is_file() for p in paths)
private_email = subprocess.run(
    ["git", "config", "--get", "user.email"], cwd=ROOT, capture_output=True, text=True
).stdout.strip()
with tarfile.open(paths[-1]) as source:
    for entry in source:
        assert not any(
            part in entry.name.split("/")
            for part in (".runtime", ".git", ".build", "dist")
        )
        if entry.isfile():
            content = source.extractfile(entry).read()
            assert not re.search(
                rb"^-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----", content, re.M
            )
            if private_email and "noreply" not in private_email:
                assert private_email.encode() not in content, (
                    "Personal git email leaked"
                )
release = DIST / f"JALTRIX-{VERSION}"
release.mkdir(exist_ok=True)
for path in paths:
    shutil.copyfile(path, release / path.name)
source_hash = hashlib.sha256(paths[-1].read_bytes()).hexdigest()
recipe = (
    (ROOT / "packaging/arch/PKGBUILD")
    .read_text()
    .replace("sha256sums=('SKIP')", f"sha256sums=('{source_hash}')")
    .replace(
        "# Local source archive only; pin a checksum for a published release.",
        "# Corresponding source archive SHA-256.",
    )
)
(release / "PKGBUILD").write_text(recipe)
(DIST / f"PKGBUILD-{VERSION}").write_text(recipe)
for source, destination in [
    ("docs/RELEASE.md", "RELEASE_NOTES.es.md"),
    ("README.en.md", "README.en.md"),
    ("LICENSE", "LICENSE"),
    ("NOTICE", "NOTICE"),
    ("docs/evidence/1.0.0/validation.json", "VALIDATION.json"),
]:
    shutil.copyfile(ROOT / source, release / destination)
shutil.copytree(
    ROOT / "docs",
    release / "docs",
    dirs_exist_ok=True,
    ignore=shutil.ignore_patterns("MASTER_BRIEF_V2.md"),
)
shutil.copytree(
    ROOT / "design/branding", release / "design/branding", dirs_exist_ok=True
)
shutil.copyfile(ROOT / "README.md", release / "README.md")
components = json.loads((ROOT / "src/snort_soc/legal/components.json").read_text())
(release / "COMPONENTS.json").write_text(
    json.dumps(
        {
            "scope": "Direct component/license inventory, not a complete transitive SBOM",
            "components": components,
        },
        indent=2,
    )
)
manifest = {
    "name": "JALTRIX",
    "version": VERSION,
    "developer": "Jan Herrera",
    "maintainer": "281252544+Lupo-SysAdmin@users.noreply.github.com",
    "license": "GPL-3.0-or-later",
    "date": "2026-11-09",
    "validation": validation,
    "publication": "Prepared locally; remote GitHub Actions not run; no public repository changes",
    "artifacts": [
        {
            "file": p.name,
            "bytes": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        }
        for p in paths
    ],
}
(release / "RELEASE_MANIFEST.json").write_text(json.dumps(manifest, indent=2))
checks = "".join(
    hashlib.sha256(p.read_bytes()).hexdigest()
    + "  "
    + p.relative_to(release).as_posix()
    + "\n"
    for p in sorted(release.rglob("*"))
    if p.is_file() and p.name != "SHA256SUMS"
)
(release / "SHA256SUMS").write_text(checks)
(DIST / "SHA256SUMS-1.0.0").write_text(
    "".join(i["sha256"] + "  " + i["file"] + "\n" for i in manifest["artifacts"])
)
with zipfile.ZipFile(
    DIST / f"JALTRIX-{VERSION}-release.zip", "w", compression=zipfile.ZIP_DEFLATED
) as bundle:
    for path in sorted(release.rglob("*")):
        if path.is_file():
            bundle.write(
                path, arcname=release.name + "/" + path.relative_to(release).as_posix()
            )
print(
    json.dumps(
        {
            "release": str(release),
            "bundle": str(DIST / f"JALTRIX-{VERSION}-release.zip"),
            "private_data_scan": "PASS",
        },
        indent=2,
    )
)
