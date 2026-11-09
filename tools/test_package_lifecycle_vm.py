from pathlib import Path
import json, platform, subprocess

assert platform.node().startswith("jaltrix-")


def run(args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=90)


name = platform.node().split("-")[-1]
marker = Path.home() / ".local/share/jaltrix/lifecycle-marker"
marker.parent.mkdir(parents=True, exist_ok=True)
marker.write_text("preserve evidence")
collector = (
    run(
        ["systemctl", "--user", "is-active", "jaltrix-ingest.service"], False
    ).returncode
    == 0
)
if collector:
    run(["systemctl", "--user", "stop", "jaltrix-ingest.service"])
if name in ("ubuntu", "parrot"):
    remove = ["sudo", "dpkg", "--purge", "jaltrix"]
    install = ["sudo", "dpkg", "-i", "/mnt/jaltrix/jaltrix.deb"]
elif name == "fedora":
    remove = ["sudo", "rpm", "-e", "jaltrix"]
    install = ["sudo", "rpm", "-i", "/mnt/jaltrix/jaltrix.rpm"]
else:
    remove = ["sudo", "pacman", "-R", "--noconfirm", "jaltrix"]
    install = [
        "sudo",
        "pacman",
        "-U",
        "--noconfirm",
        str(Path.home() / "renamebuild/jaltrix-1.0.1-1-any.pkg.tar.zst"),
    ]
try:
    run(remove)
    assert not Path("/usr/bin/jaltrix").exists()
    assert not Path(
        "/usr/share/applications/io.github.LupoSysAdmin.Jaltrix.desktop"
    ).exists()
    assert marker.read_text() == "preserve evidence"
finally:
    run(install)
    if collector:
        run(["systemctl", "--user", "start", "jaltrix-ingest.service"])
assert Path("/usr/bin/jaltrix").is_file() and marker.read_text() == "preserve evidence"
marker.unlink()
print(
    json.dumps(
        dict(
            result="PASS",
            distro=name,
            checks=[
                "remove/purge",
                "launcher and menu removed",
                "user data retained",
                "reinstall",
                "collector state restored",
            ],
        )
    )
)
