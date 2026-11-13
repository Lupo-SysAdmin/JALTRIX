"""Exercise the installed host UI, ES/EN and case timeline with labeled synthetic data.

Run on a lab desktop or explicitly selected virtual display. No source or service
is enabled. All test data stays in a fresh temporary directory.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, "/usr/lib/jaltrix")
import jaltrix
from jaltrix.app import Controller
from jaltrix.host_events import HostEventStore
from PySide6.QtCore import QEventLoop, QObject, QTimer, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--expected-version", default="1.3.0")
args = parser.parse_args()
assert jaltrix.__version__ == args.expected_version
assert Path(jaltrix.__file__).is_relative_to("/usr/lib/jaltrix")
args.output.mkdir(parents=True, exist_ok=True)
QQuickStyle.setStyle("Basic")
app = QGuiApplication([])
app.setApplicationName("JALTRIX — synthetic validation")


def wait_for(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        loop = QEventLoop()
        QTimer.singleShot(25, loop.quit)
        loop.exec()
        if predicate():
            return
    raise AssertionError("Installed UI did not reach the expected state")


with tempfile.TemporaryDirectory(prefix="jaltrix-installed-host-check-") as directory:
    root = Path(directory)
    controller = Controller(root)
    engine = QQmlApplicationEngine()
    warnings = []
    engine.warnings.connect(lambda rows: warnings.extend(w.toString() for w in rows))
    engine.rootContext().setContextProperty("soc", controller)
    engine.rootContext().setContextProperty("eventModel", controller.model)
    engine.load(QUrl.fromLocalFile(str(Path(jaltrix.__file__).parent / "ui/Main.qml")))
    assert engine.rootObjects(), warnings
    window = engine.rootObjects()[0]
    window.resize(1080, 720)
    try:
        assert not (root / "live/host-events.sqlite3").exists()
        controller.changeMode("live")
        window.setProperty("page", "Eventos del sistema")
        wait_for(lambda: controller.host.ready)
        assert controller.host.pagination["total"] == 0
        assert not any(
            controller.host.config[k]
            for k in ("journal_enabled", "audit_enabled", "snort_enabled")
        )
        view = window.findChild(QObject, "host-view")
        assert view is not None
        for language in ("es-419", "en-US"):
            controller.setLanguage(language)
            for tab in range(4):
                view.setProperty("tab", tab)
                wait_for(lambda: True)
                assert window.grabWindow().save(
                    str(args.output / f"host-{language}-{tab}.png")
                )
        # Evidence comes from a fixture, never from the machine's real logs.
        anchor = datetime.now(timezone.utc) - timedelta(minutes=2)
        store = HostEventStore(root / "live/host-events.sqlite3")
        store.ingest(
            [
                dict(
                    event_id=f"installed-lab-{i}",
                    original_id=f"synthetic-cursor-{i}",
                    host_id="synthetic-lab",
                    hostname="SYNTHETIC LABORATORY",
                    source="journal",
                    kind="auth_failure" if i < 5 else "auth_success",
                    service="sshd",
                    outcome="failure" if i < 5 else "success",
                    user="lab-user",
                    src_ip="192.0.2.10",
                    timestamp=(anchor + timedelta(seconds=i * 10)).isoformat(),
                    message="Synthetic laboratory evidence — not a real intrusion",
                    raw_record={"fixture": True},
                )
                for i in range(6)
            ]
        )
        correlation = store.correlations()[0]
        store.close()
        controller.host.refresh()
        wait_for(lambda: controller.host.pagination["total"] == 6)
        controller.host.selectCorrelation(correlation["id"])
        wait_for(lambda: len(controller.host.timeline) == 6)
        view.setProperty("tab", 1)
        wait_for(lambda: True)
        assert window.grabWindow().save(str(args.output / "host-correlations-en.png"))
        controller.host.createCase(correlation["id"])
        wait_for(lambda: len(controller.host.caseTimeline) == 6)
        assert len(controller.cases) == 1
        assert window.grabWindow().save(str(args.output / "host-case-en.png"))
        controller.useDemo()
        assert controller.host.events == [] and controller.host.caseTimeline == []
        assert not warnings, warnings
        report = dict(
            result="PASS",
            version=jaltrix.__version__,
            scope="Installed package UI; synthetic fixtures; no sources or services enabled",
            checks=[
                "initially empty",
                "sources disabled",
                "ES/EN",
                "1080x720",
                "all host tabs",
                "correlation",
                "existing case timeline",
                "demo separation",
            ],
            warnings=warnings,
        )
        (args.output / "installed-host-ui.json").write_text(
            json.dumps(report, indent=2)
        )
        print(json.dumps(report))
    finally:
        window.close()
        engine.deleteLater()
        app.processEvents()
        controller.close()
