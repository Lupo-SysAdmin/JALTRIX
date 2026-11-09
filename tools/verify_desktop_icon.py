"""Verify the installed launcher's actual X11 window icon in the current session."""

from pathlib import Path
import hashlib, json, os, re, subprocess, tempfile, time

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="jaltrix-icon-test-") as temporary:
    with (ROOT / "artifacts/icon-x11-v110.log").open("w") as log:
        child = subprocess.Popen(
            [
                "/usr/bin/jaltrix",
                "--about",
                "--data-dir",
                temporary,
                "--quit-after",
                "8000",
            ],
            env=dict(os.environ, QT_QPA_PLATFORM="xcb", QT_QUICK_BACKEND="software"),
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            report = None
            for _ in range(40):
                tree = subprocess.run(
                    ["xwininfo", "-root", "-tree"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                ).stdout
                for line in tree.splitlines():
                    if "JALTRIX" not in line:
                        continue
                    match = re.search(r"0x[0-9a-f]+", line)
                    if not match:
                        continue
                    props = subprocess.run(
                        [
                            "xprop",
                            "-id",
                            match[0],
                            "-notype",
                            "_NET_WM_PID",
                            "_NET_WM_ICON",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    ).stdout
                    if (
                        f"_NET_WM_PID = {child.pid}" in props
                        and "_NET_WM_ICON = " in props
                    ):
                        report = dict(
                            result="PASS",
                            pid=child.pid,
                            window=match[0],
                            scope="Installed launcher under X11; EWMH icon present",
                            icon_property_sha256=hashlib.sha256(
                                props.split("_NET_WM_ICON = ", 1)[1].encode()
                            ).hexdigest(),
                        )
                        break
                if report:
                    break
                time.sleep(0.1)
            assert report, "Window icon missing"
            (ROOT / "artifacts/icon-x11-v110.json").write_text(
                json.dumps(report, indent=2)
            )
            print(json.dumps(report))
        finally:
            child.terminate()
            child.wait(timeout=10)
