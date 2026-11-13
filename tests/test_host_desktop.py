"""Desktop contracts for optional local evidence, without changing host services."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import threading

from PySide6.QtCore import QEventLoop, QTimer, QUrl, QObject, QMetaObject
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle

from jaltrix.app import Controller
from jaltrix.host_events import HostEventStore
from jaltrix.host_service import DEFAULTS
from jaltrix import host_service
from jaltrix.snort import AlertStore


def wait_for(predicate, message="desktop operation did not complete"):
    for _ in range(300):
        loop = QEventLoop()
        QTimer.singleShot(10, loop.quit)
        loop.exec()
        if predicate():
            return
    raise AssertionError(message)


def gui():
    QQuickStyle.setStyle("Basic")
    return QGuiApplication.instance() or QGuiApplication([])


def attach(controller):
    engine = QQmlApplicationEngine()
    errors = []
    engine.warnings.connect(
        lambda warnings: errors.extend(w.toString() for w in warnings)
    )
    engine.rootContext().setContextProperty("soc", controller)
    engine.rootContext().setContextProperty("eventModel", controller.model)
    engine.load(
        QUrl.fromLocalFile(str(Path(__file__).parents[1] / "src/jaltrix/ui/Main.qml"))
    )
    assert engine.rootObjects(), errors
    return engine, engine.rootObjects()[0], errors


def visual(item, name):
    if item.objectName() == name:
        return item
    for child in item.childItems():
        found = visual(child, name)
        if found is not None:
            return found
    return None


def fixture_events():
    start = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
    return [
        dict(
            event_id=f"test-journal-{i}",
            original_id=f"cursor-{i}",
            source="journal",
            host_id="test-local-host",
            hostname="laboratory",
            kind="auth_failure" if i < 5 else "auth_success",
            service="sshd",
            outcome="failure" if i < 5 else "success",
            user="test-user",
            src_ip="192.0.2.4",
            timestamp=(start + timedelta(seconds=i * 20)).isoformat(),
            message="Synthetic authorized test evidence",
            raw_record={"MESSAGE": "test record"},
        )
        for i in range(6)
    ]


def test_host_navigation_disabled_sources_and_small_bilingual_layout(
    tmp_path, monkeypatch
):
    app = gui()
    actions = []
    monkeypatch.setattr(
        host_service, "control", lambda *args, **kwargs: actions.append((args, kwargs))
    )
    controller = Controller(tmp_path)
    engine, window, errors = attach(controller)
    try:
        window.resize(1080, 720)
        QMetaObject.invokeMethod(
            visual(window.contentItem(), "nav-Eventos del sistema"), "clicked"
        )
        host_view = window.findChild(QObject, "host-view")
        assert host_view is not None
        assert not controller.host.live
        assert not (tmp_path / "live/host-events.sqlite3").exists()
        assert controller.host.events == []
        controller.changeMode("live")
        QMetaObject.invokeMethod(
            visual(window.contentItem(), "nav-Eventos del sistema"), "clicked"
        )
        wait_for(lambda: controller.host.ready)
        assert controller.host.config == DEFAULTS
        assert controller.host.events == [] and controller.host.correlations == []
        assert controller.host.hosts == []
        for language, expected in [
            ("es-419", "Leer eventos de journald (SSH y sudo)"),
            ("en-US", "Read journald events (SSH and sudo)"),
        ]:
            controller.setLanguage(language)
            host_view.setProperty("tab", 3)
            wait_for(
                lambda window=window: (
                    window.findChild(QObject, "host-enable-journal").property("text")
                    == expected
                )
            )
            assert not window.findChild(QObject, "host-enable-journal").property(
                "checked"
            )
            assert not window.findChild(QObject, "host-enable-audit").property(
                "checked"
            )
            assert not window.findChild(QObject, "host-enable-snort").property(
                "checked"
            )
            assert not window.findChild(QObject, "host-bind-snort").property("enabled")
            assert not window.findChild(QObject, "host-start").property("enabled")
            assert host_view.height() >= 300
            assert host_view.width() >= 800
            for tab in range(4):
                host_view.setProperty("tab", tab)
                app.processEvents()
                assert window.grabWindow().save(
                    str(tmp_path / f"host-{language}-{tab}.png")
                )
            assert window.findChild(QObject, "host-query").property("activeFocusOnTab")
        assert actions == [], "Opening the view must not start or stop any service"
        assert not errors, errors
    finally:
        window.close()
        del window, engine
        app.processEvents()
        controller.close()


def test_correlated_evidence_uses_existing_case_store_and_survives_retention(tmp_path):
    app = gui()
    store = HostEventStore(tmp_path / "live/host-events.sqlite3")
    store.ingest(fixture_events())
    correlation = store.correlations()[0]
    store.close()
    controller = Controller(tmp_path)
    engine, window, errors = attach(controller)
    try:
        controller.changeMode("live")
        QMetaObject.invokeMethod(
            visual(window.contentItem(), "nav-Eventos del sistema"), "clicked"
        )
        wait_for(lambda: controller.host.ready)
        assert controller.host.pagination["total"] == 6
        assert controller.host.hosts[0]["hostname"] == "laboratory"
        controller.host.selectCorrelation(correlation["id"])
        wait_for(lambda: len(controller.host.timeline) == 6)
        controller.setLanguage("en-US")
        controller.host.createCase(correlation["id"])
        wait_for(lambda: len(controller.host.caseTimeline) == 6)
        assert len(controller.cases) == 1
        case = controller.cases[0]
        assert case["event_id"] == "host-correlation:" + correlation["id"]
        assert case["title"] == correlation["title_en"]
        assert controller.caseDetail["id"] == case["id"]
        controller.saveCase("Reviewed source records", "investigating")
        controller.host.createCase(correlation["id"])
        wait_for(lambda: not controller.host.busy)
        assert len(controller.cases) == 1
        store = HostEventStore(tmp_path / "live/host-events.sqlite3")
        try:
            assert case["id"] in store.get_correlation(correlation["id"])["case_ids"]
            store.retain(days=1, max_events=1)
            assert len(store.correlation_events(correlation["id"])) == 6
        finally:
            store.close()
        controller.useDemo()
        assert controller.host.events == [] and controller.host.timeline == []
        assert (
            controller.host.caseTimeline == [] and not controller.host.caseHasEvidence
        )
        assert controller.cases == []
        controller.changeMode("live")
        controller.openCase(case["id"])
        wait_for(lambda: len(controller.host.caseTimeline) == 6)
        assert controller.caseDetail["notes"] == "Reviewed source records"
        assert not errors, errors
    finally:
        window.close()
        del window, engine
        app.processEvents()
        controller.close()


def test_pending_live_read_cannot_leak_into_replay(tmp_path, monkeypatch):
    app = gui()
    controller = Controller(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = controller.host._snapshot

    def slow_read(*args):
        entered.set()
        release.wait(3)
        return original(*args)

    monkeypatch.setattr(controller.host, "_snapshot", slow_read)
    try:
        controller.changeMode("live")
        controller.host.setVisible(True)
        wait_for(entered.is_set)
        controller.changeMode("replay")
        release.set()
        wait_for(lambda: controller.host._future is None)
        assert not controller.host.ready and not controller.host.live
        assert controller.host.events == [] and controller.host.correlations == []
        assert controller.host.config == {} and controller.host.status == {}
    finally:
        release.set()
        controller.close()
        app.processEvents()


def test_saved_snort_binding_does_not_follow_another_connected_file(
    tmp_path, monkeypatch
):
    app = gui()
    actions = []
    monkeypatch.setattr(
        host_service, "control", lambda *args, **kwargs: actions.append(args)
    )
    source_a, source_b = tmp_path / "local.json", tmp_path / "external.json"
    for source in (source_a, source_b):
        source.write_text('{"rule":"1:42:1","src_addr":"192.0.2.4","dst_port":22}\n')
    alerts = AlertStore(tmp_path / "live/alerts.sqlite3")
    try:
        first_id = alerts.ingest(source_a, "live")["source_id"]
        second_id = alerts.ingest(source_b, "live")["source_id"]
    finally:
        alerts.close()
    controller = Controller(tmp_path)
    try:
        controller.changeMode("live")
        controller._source = str(source_a)
        controller.host.setVisible(True)
        wait_for(lambda: controller.host.ready)
        controller.host.saveConfig(
            False, False, "/var/log/audit/audit.log", True, True, 30, 100000, False
        )
        wait_for(
            lambda: (
                host_service.load_config(tmp_path)["snort_source_id"] == first_id
                and not controller.host.busy
            )
        )
        controller._source = str(source_b)
        controller.host.saveConfig(
            False, False, "/var/log/audit/audit.log", True, False, 31, 100000, False
        )
        wait_for(
            lambda: (
                host_service.load_config(tmp_path)["retention_days"] == 31
                and not controller.host.busy
            )
        )
        assert host_service.load_config(tmp_path)["snort_source_id"] == first_id
        assert first_id != second_id
        assert actions == [], "Saving sources must not implicitly start a collector"
        emissions = []
        controller.host.eventsChanged.connect(lambda: emissions.append(True))
        monkeypatch.setattr(
            host_service,
            "health",
            lambda _: dict(state="stale", fresh=False, sources={}),
        )
        controller.host.refresh()
        wait_for(lambda: controller.host.status.get("state") == "stale")
        assert emissions == [], "Health refresh must not reset unchanged event rows"
    finally:
        controller.close()
        app.processEvents()
