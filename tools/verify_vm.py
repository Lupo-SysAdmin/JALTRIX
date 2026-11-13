"""Run source tests and installed GUI on an existing full-desktop disposable VM."""

from pathlib import Path
import argparse, json, os, platform, subprocess, tarfile, tomllib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--archive", type=Path, default=Path("/mnt/jaltrix/source.tar.gz"))
parser.add_argument("--output", type=Path, default=Path.home() / "jaltrix-validation")
args = parser.parse_args()
root = args.output.resolve()
root.mkdir(parents=True, exist_ok=True)
with tarfile.open(args.archive) as archive:
    metadata = next(
        m for m in archive.getmembers() if m.name.endswith("/pyproject.toml")
    )
    version = tomllib.loads(archive.extractfile(metadata).read().decode())["project"][
        "version"
    ]
    archive.extractall(root, filter="data")
source = root / f"jaltrix-{version}"
env = dict(os.environ, QT_QPA_PLATFORM="offscreen", QT_QUICK_BACKEND="software")
engine = Path(
    os.environ.get("JALTRIX_ENGINE", "/usr/local/lib/jaltrix-engine/bin/snort")
)
if engine.exists():
    env["JALTRIX_ENGINE"] = str(engine)
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
    DISPLAY=os.environ.get("DISPLAY", ":0"),
    XAUTHORITY=os.environ.get("XAUTHORITY", str(Path.home() / ".Xauthority")),
    XDG_RUNTIME_DIR=os.environ.get("XDG_RUNTIME_DIR", "/run/user/" + str(os.getuid())),
)
for process in Path("/proc").glob("[0-9]*"):
    try:
        if process.stat().st_uid == os.getuid() and any(
            name in (process / "cmdline").read_bytes()
            for name in (
                b"/usr/bin/jaltrix",
                b"/usr/bin/snort-soc",
                b"plasmashell",
                b"xfce4-session",
                b"kwin_x11",
            )
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
            "/usr/bin/jaltrix",
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
with (root / "map-gui.log").open("w") as log:
    mapped = subprocess.run(
        [
            "/usr/bin/jaltrix",
            "--map",
            "--language",
            "en-US",
            "--data-dir",
            str(root / "data"),
            "--screenshot",
            str(root / "installed-map.png"),
        ],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
setup_results = {}
for language in ("es-419", "en-US"):
    with (root / ("setup-" + language + ".log")).open("w") as log:
        setup_results[language] = subprocess.run(
            [
                "/usr/bin/jaltrix",
                "--setup",
                "--language",
                language,
                "--data-dir",
                str(root / ("setup-data-" + language)),
                "--screenshot",
                str(root / ("setup-" + language + ".png")),
            ],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=30,
        ).returncode
with (root / "host-ui.log").open("w") as log:
    host_ui = subprocess.run(
        [
            "python3",
            str(source / "tools/verify_installed_host_ui.py"),
            "--output",
            str(root / "host-ui"),
            "--expected-version",
            version,
        ],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        timeout=90,
    )
report = dict(
    hostname=platform.node(),
    os=Path("/etc/os-release").read_text(),
    kernel=platform.release(),
    python=platform.python_version(),
    version=version,
    tests_exit=tests.returncode,
    host_ui_exit=host_ui.returncode,
    gui_exit=gui.returncode,
    map_exit=mapped.returncode,
    setup_exit=setup_results,
    scope="Source suite offscreen plus installed GUI using supplied X11 desktop/display; see platform report for physical vs virtual display",
    engine=str(engine) if engine.exists() else None,
)
(root / "report.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
print((root / "tests.log").read_text()[-2000:])
assert (
    tests.returncode == gui.returncode == mapped.returncode == host_ui.returncode == 0
)

assert all(code == 0 for code in setup_results.values())
