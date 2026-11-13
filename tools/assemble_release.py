"""Assemble the reviewed local release, with sources, hashes and explicit limits."""

import hashlib, json, re, shutil, subprocess, tarfile, zipfile

from release_meta import ROOT, VERSION, RELEASE_DATE, source_fingerprint

DIST = ROOT / "dist"
validation = json.loads((ROOT / f"docs/evidence/{VERSION}/validation.json").read_text())
gates = json.loads((ROOT / "artifacts" / f"release-gates-{VERSION}.json").read_text())
required = {
    "regression_engine",
    "lint",
    "metadata",
    "upgrade",
    "real_sources",
    "installed_matrix",
    "remote_ci",
}
if gates.get("version") != VERSION or validation.get("version") != VERSION:
    raise SystemExit("Release evidence belongs to a different version")
if gates.get("source_fingerprint") != source_fingerprint():
    raise SystemExit(
        "Source changed after validation; repeat affected checks before assembling"
    )
checks = gates.get("checks", {})
if not required <= checks.keys() or any(
    checks[name].get("result") != "PASS" for name in required
):
    raise SystemExit("Required release checks are missing or unsuccessful")
paths = [
    DIST / f"jaltrix_{VERSION}-1_all.deb",
    DIST / f"jaltrix-{VERSION}-1.noarch.rpm",
    DIST / f"jaltrix-{VERSION}-1-any.pkg.tar.zst",
    DIST / f"jaltrix-{VERSION}.tar.gz",
]
for path in paths:
    if not path.is_file():
        raise SystemExit(f"Missing release artifact: {path.name}")
    if (
        gates.get("artifacts", {}).get(path.name)
        != hashlib.sha256(path.read_bytes()).hexdigest()
    ):
        raise SystemExit(f"Artifact was not verified after its last build: {path.name}")
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
release.mkdir()
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
    (f"docs/evidence/{VERSION}/validation.json", "VALIDATION.json"),
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
components = json.loads((ROOT / "src/jaltrix/legal/components.json").read_text())
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
    "date": RELEASE_DATE,
    "validation": validation,
    "source_fingerprint": gates["source_fingerprint"],
    "checks": checks,
    "publication": "https://github.com/Lupo-SysAdmin/JALTRIX — see Actions for exact commit checks",
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
(DIST / f"SHA256SUMS-{VERSION}").write_text(
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
