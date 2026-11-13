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
from PySide6.QtCore import (
    QCoreApplication,
    QEvent,
    QEventLoop,
    QMetaObject,
    QObject,
    QPointF,
    QTimer,
    QUrl,
)
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
app = QGuiApplication([])
QQuickStyle.setStyle("Basic")
assert QQuickStyle.name() == "Basic"
app.setApplicationName("JALTRIX — synthetic validation")
rendered_sizes = set()


def wait_for(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        loop = QEventLoop()
        QTimer.singleShot(25, loop.quit)
        loop.exec()
        if predicate():
            return
    raise AssertionError("Installed UI did not reach the expected state")


def visual(item, name):
    if item.objectName() == name:
        return item
    for child in item.childItems():
        found = visual(child, name)
        if found is not None:
            return found
    return None


def verify_host_visible(window, view):
    # An obscured Xwayland window may not receive an initial render tick.
    # Render our own test window before inspecting the polished layout.
    frame = window.grabWindow()
    assert not frame.isNull(), (
        "The supplied desktop/display could not render the test window"
    )
    try:
        wait_for(lambda: view.isVisible() and view.width() > 0 and view.height() > 0)
    except AssertionError:
        raise AssertionError(
            dict(
                page=window.property("page"),
                window=[window.width(), window.height()],
                window_visible=window.isVisible(),
                view=[view.width(), view.height()],
                view_visible=view.isVisible(),
            )
        ) from None
    geometry = dict(
        page=window.property("page"),
        window=[window.width(), window.height()],
        content=[
            window.property("contentItem").width(),
            window.property("contentItem").height(),
        ],
        window_root=[window.contentItem().width(), window.contentItem().height()],
        view=[view.width(), view.height()],
        visible=view.isVisible(),
        font_pixels=window.property("font").pixelSize(),
        pixel_ratio=window.devicePixelRatio(),
    )
    corner = view.mapToScene(QPointF(view.width(), view.height()))
    geometry["view_right_bottom"] = [corner.x(), corner.y()]
    assert geometry["page"] == "Eventos del sistema", geometry
    assert view.width() >= 800 and view.height() >= 300, geometry
    assert geometry["content"] == geometry["window"], geometry
    assert corner.x() <= window.width() and corner.y() <= window.height(), geometry
    rendered_sizes.add((window.width(), window.height(), frame.width(), frame.height()))


with tempfile.TemporaryDirectory(prefix="jaltrix-installed-host-check-") as directory:
    root = Path(directory)
    controller = Controller(root)
    engine = QQmlApplicationEngine()
    warnings = []
    engine.warnings.connect(lambda rows: warnings.extend(w.toString() for w in rows))
    engine.rootContext().setContextProperty("soc", controller)
    engine.rootContext().setContextProperty("eventModel", controller.model)
    # Establish the small native window before Xwayland's initial configure.
    engine.setInitialProperties({"width": 1080, "height": 720})
    engine.load(QUrl.fromLocalFile(str(Path(jaltrix.__file__).parent / "ui/Main.qml")))
    assert engine.rootObjects(), warnings
    window = engine.rootObjects()[0]
    try:
        assert not (root / "live/host-events.sqlite3").exists()
        controller.changeMode("live")
        navigation = visual(window.contentItem(), "nav-Eventos del sistema")
        assert navigation is not None
        assert QMetaObject.invokeMethod(navigation, "clicked")
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
                verify_host_visible(window, view)
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
        verify_host_visible(window, view)
        assert window.grabWindow().save(str(args.output / "host-correlations-en.png"))
        controller.host.createCase(correlation["id"])
        wait_for(lambda: len(controller.host.caseTimeline) == 6)
        assert len(controller.cases) == 1
        verify_host_visible(window, view)
        assert window.grabWindow().save(str(args.output / "host-case-en.png"))
        controller.useDemo()
        assert controller.host.events == [] and controller.host.caseTimeline == []
        report = dict(
            result="PASS",
            version=jaltrix.__version__,
            scope="Installed package UI; synthetic fixtures; no sources or services enabled",
            checks=[
                "initially empty",
                "sources disabled",
                "ES/EN",
                "requested 1080x720; actual rendered sizes recorded",
                "all host tabs",
                "correlation",
                "existing case timeline",
                "demo separation",
                "visible host navigation preserved across language changes",
                "Basic style after platform initialization",
            ],
            qt_quick_style=QQuickStyle.name(),
            requested_window_size=[1080, 720],
            rendered_sizes=[
                dict(window=[width, height], image=[image_width, image_height])
                for width, height, image_width, image_height in sorted(rendered_sizes)
            ],
        )
    finally:
        window.close()
        engine.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()
        controller.close()
    assert not warnings, warnings[:20]
    report["warnings"] = warnings
    (args.output / "installed-host-ui.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
