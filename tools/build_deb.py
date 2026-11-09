"""Build a private-module Debian package. No engine or rules bundled."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import gzip
import os
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist"
OUT.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix="jaltrix-deb-") as temp:
    stage = Path(temp)
    package = stage / "usr/lib/jaltrix/jaltrix"
    shutil.copytree(
        ROOT / "src/jaltrix", package, ignore=shutil.ignore_patterns("__pycache__")
    )
    launcher = stage / "usr/bin/jaltrix"
    launcher.parent.mkdir(parents=True)
    launcher.write_text(
        '#!/usr/bin/python3\nimport sys\nsys.dont_write_bytecode = True\nsys.path.insert(0, "/usr/lib/jaltrix")\nfrom jaltrix.app import main\nmain()\n'
    )
    launcher.chmod(0o755)
    for source, target in [
        (
            "packaging/desktop/io.github.LupoSysAdmin.Jaltrix.desktop",
            "usr/share/applications/io.github.LupoSysAdmin.Jaltrix.desktop",
        ),
        (
            "src/jaltrix/ui/app-icon.svg",
            "usr/share/icons/hicolor/scalable/apps/io.github.LupoSysAdmin.Jaltrix.svg",
        ),
        (
            "src/jaltrix/ui/app-icon.png",
            "usr/share/icons/hicolor/512x512/apps/io.github.LupoSysAdmin.Jaltrix.png",
        ),
        (
            "packaging/metainfo/io.github.LupoSysAdmin.Jaltrix.metainfo.xml",
            "usr/share/metainfo/io.github.LupoSysAdmin.Jaltrix.metainfo.xml",
        ),
        ("packaging/debian/copyright", "usr/share/doc/jaltrix/copyright"),
        ("NOTICE", "usr/share/doc/jaltrix/NOTICE"),
        ("README.md", "usr/share/doc/jaltrix/README.md"),
    ]:
        dest = stage / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / source, dest)
    shutil.copytree(
        ROOT / "docs",
        stage / "usr/share/doc/jaltrix/docs",
        ignore=shutil.ignore_patterns("MASTER_BRIEF_V2.md"),
    )
    control = stage / "DEBIAN/control"
    control.parent.mkdir()
    control.write_text("""Package: jaltrix
Version: 1.0.1-1
Section: net
Priority: optional
Architecture: all
Maintainer: Jan Herrera <281252544+Lupo-SysAdmin@users.noreply.github.com>
Depends: libqt6svg6, python3 (>= 3.11), python3-gi, python3-pyside6.qtcore (>= 6.8), python3-pyside6.qtgui, python3-pyside6.qtqml, python3-pyside6.qtquick, python3-pyside6.qtquickcontrols2, qml6-module-qtquick, qml6-module-qtquick-controls, qml6-module-qtquick-dialogs, qml6-module-qtquick-layouts, qml6-module-qtqml-workerscript, qml6-module-qtquick-templates, qml6-module-qtquick-window
Conflicts: snort-soc-desktop
Replaces: snort-soc-desktop
Suggests: snort, nftables, pkexec, iproute2
Homepage: https://github.com/Lupo-SysAdmin
Description: independent desktop console for Snort 3
 Bilingual es-419/en-US investigation console with isolated demo data,
 read-only alert_json ingestion and offline PCAP replay.
 Snort is configured separately. No capture service is installed.
""")
    changelog = stage / "usr/share/doc/jaltrix/changelog.Debian.gz"
    changelog.write_bytes(
        gzip.compress((ROOT / "packaging/debian/changelog").read_bytes(), mtime=0)
    )
    man = stage / "usr/share/man/man1/jaltrix.1.gz"
    man.parent.mkdir(parents=True, exist_ok=True)
    man.write_bytes(
        gzip.compress((ROOT / "packaging/man/jaltrix.1").read_bytes(), mtime=0)
    )
    shutil.copyfile(ROOT / "packaging/debian/postinst", stage / "DEBIAN/postinst")
    stage.chmod(0o755)
    # Normalize copied source permissions: privileged helper must never be group-writable.
    for item in stage.rglob("*"):
        item.chmod(
            0o755
            if item.is_dir() or item == launcher or item == stage / "DEBIAN/postinst"
            else 0o644
        )
    epoch = int(
        os.environ.get(
            "SOURCE_DATE_EPOCH",
            str(int(datetime(2026, 11, 9, tzinfo=timezone.utc).timestamp())),
        )
    )
    for item in [stage, *stage.rglob("*")]:
        os.utime(item, (epoch, epoch))
    subprocess.run(
        [
            "dpkg-deb",
            "--root-owner-group",
            "--build",
            str(stage),
            str(OUT / "jaltrix_1.0.1-1_all.deb"),
        ],
        check=True,
        env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)),
    )
