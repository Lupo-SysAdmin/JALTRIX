"""Run isolated distro/package checks. Requires Docker access, not privileged containers."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/matrix-v040"
OUT.mkdir(parents=True, exist_ok=True)
IMAGES = {
    "ubuntu": "ubuntu:26.04",
    "parrot": "parrotsec/core:latest",
    "fedora": "registry.fedoraproject.org/fedora:44",
    "arch": "archlinux:base-devel",
}


def run(item):
    name, image = item
    dest = OUT / name
    dest.mkdir(exist_ok=True)
    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        "jaltrix-test-" + name,
        "--cpus=2",
        "--memory=4g",
        "--pids-limit=1024",
        "-v",
        f"{ROOT}:/source:ro",
        "-v",
        f"{dest}:/result",
        image,
        "bash",
        "/source/tools/container_check.sh",
        name,
    ]
    with (dest / "run.log").open("w") as log:
        try:
            result = subprocess.run(
                cmd, stdout=log, stderr=subprocess.STDOUT, timeout=1800
            )
            code = result.returncode
        except subprocess.TimeoutExpired:
            subprocess.run(
                ["docker", "stop", "jaltrix-test-" + name],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            code = 124
    info = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"],
        capture_output=True,
        text=True,
    )
    report = {
        "image": image,
        "digest": info.stdout.strip(),
        "exit_code": code,
        "scope": "container, Xvfb X11; not VM/Wayland/systemd boot",
    }
    (dest / "summary.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(name=name, **report)), flush=True)
    return report


with ThreadPoolExecutor(max_workers=4) as pool:
    reports = dict(zip(IMAGES, pool.map(run, IMAGES.items())))
(OUT / "summary.json").write_text(json.dumps(reports, indent=2))
# Root-owned test outputs are readable; leave host app/user data untouched.
for p in OUT.rglob("*"):
    if p.is_file() and p.stat().st_uid == os.getuid():
        p.chmod(0o644)
