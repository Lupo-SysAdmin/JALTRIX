"""Run source tests and installed GUI on an existing full-desktop disposable VM."""

from pathlib import Path
import json, os, platform, subprocess, tarfile

assert platform.node().startswith("jaltrix-"), "Disposable VM only"
root = Path.home() / "jaltrix-validation"
root.mkdir(exist_ok=True)
with tarfile.open("/mnt/jaltrix/source.tar.gz") as archive:
    archive.extractall(root, filter="data")
source = root / "snort-soc-desktop-1.0.0"
env = dict(os.environ, QT_QPA_PLATFORM="offscreen", QT_QUICK_BACKEND="software")
engine = Path("/usr/local/lib/snort-soc-engine/bin/snort")
if engine.exists():
    env["SNORT_SOC_ENGINE"] = str(engine)
with (root / "tests.log").open("w") as log:
    tests = subprocess.run(
        ["python3", "-m", "pytest", "-q", "-ra"],
        cwd=source,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
env.update(
    QT_QPA_PLATFORM="xcb",
    DISPLAY=":0",
    XAUTHORITY=str(Path.home() / ".Xauthority"),
    XDG_RUNTIME_DIR="/run/user/" + str(os.getuid()),
)
for process in Path("/proc").glob("[0-9]*"):
    try:
        if (
            process.stat().st_uid == os.getuid()
            and b"/usr/bin/snort-soc" in (process / "cmdline").read_bytes()
        ):
            values = dict(
                part.split(b"=", 1)
                for part in (process / "environ").read_bytes().split(b"\0")
                if b"=" in part
            )
            for key in ("DISPLAY", "XAUTHORITY"):
                if key.encode() in values:
                    env[key] = values[key.encode()].decode()
            break
    except (OSError, ValueError):
        pass
with (root / "gui.log").open("w") as log:
    gui = subprocess.run(
        [
            "/usr/bin/snort-soc",
            "--about",
            "--language",
            "en-US",
            "--data-dir",
            str(root / "data"),
            "--screenshot",
            str(root / "installed.png"),
        ],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
report = dict(
    hostname=platform.node(),
    os=Path("/etc/os-release").read_text(),
    kernel=platform.release(),
    python=platform.python_version(),
    tests_exit=tests.returncode,
    gui_exit=gui.returncode,
    scope="KVM with full desktop; source suite offscreen plus installed GUI on real desktop display",
    engine=str(engine) if engine.exists() else None,
)
(root / "report.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
print((root / "tests.log").read_text()[-2000:])
assert tests.returncode == gui.returncode == 0
