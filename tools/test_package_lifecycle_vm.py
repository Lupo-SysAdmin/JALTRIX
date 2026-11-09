from pathlib import Path
import json, platform, subprocess

assert platform.node().startswith("jaltrix-")


def run(args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=90)


name = platform.node().split("-")[-1]
marker = Path.home() / ".local/share/snort-soc-desktop/lifecycle-marker"
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
    remove = ["sudo", "dpkg", "--purge", "snort-soc-desktop"]
    install = ["sudo", "dpkg", "-i", "/mnt/jaltrix/jaltrix.deb"]
elif name == "fedora":
    remove = ["sudo", "rpm", "-e", "snort-soc-desktop"]
    install = ["sudo", "rpm", "-i", "/mnt/jaltrix/jaltrix.rpm"]
else:
    remove = ["sudo", "pacman", "-R", "--noconfirm", "snort-soc-desktop"]
    install = [
        "sudo",
        "pacman",
        "-U",
        "--noconfirm",
        str(Path.home() / "releasebuild/snort-soc-desktop-1.0.0-1-any.pkg.tar.zst"),
    ]
try:
    run(remove)
    assert not Path("/usr/bin/snort-soc").exists()
    assert not Path(
        "/usr/share/applications/io.github.LupoSysAdmin.SnortSOC.desktop"
    ).exists()
    assert marker.read_text() == "preserve evidence"
finally:
    run(install)
    if collector:
        run(["systemctl", "--user", "start", "jaltrix-ingest.service"])
assert (
    Path("/usr/bin/snort-soc").is_file() and marker.read_text() == "preserve evidence"
)
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
