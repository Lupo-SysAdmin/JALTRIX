import json
from pathlib import Path

from PySide6.QtCore import QObject, QPointF, Qt, QUrl, QEventLoop, QTimer, QEvent
from PySide6.QtGui import QGuiApplication, QMouseEvent
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle


def wait(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


from snort_soc.app import Controller
from snort_soc.core import demo_events


def test_desktop_navigation_filter_export_and_virtualization(tmp_path, monkeypatch):
    QQuickStyle.setStyle("Basic")
    app = QGuiApplication.instance() or QGuiApplication([])
    controller = Controller(tmp_path)
    engine = QQmlApplicationEngine()
    errors = []
    engine.warnings.connect(
        lambda warnings: errors.extend(w.toString() for w in warnings)
    )
    engine.rootContext().setContextProperty("soc", controller)
    engine.rootContext().setContextProperty("eventModel", controller.model)
    engine.load(
        QUrl.fromLocalFile(str(Path(__file__).parents[1] / "src/snort_soc/ui/Main.qml"))
    )
    assert engine.rootObjects()
    window = engine.rootObjects()[0]
    wait(200)
    search = window.findChild(QObject, "search")
    search.setProperty("text", "192.0.2.1")
    wait(30)
    assert 0 < controller.model.rowCount() < 240
    search.setProperty("text", "")
    controller.select(1)
    assert controller.selected["event_id"] == "demo-000001"
    controller.createCase()
    assert len(controller.cases) == 1

    def find_visual(item, name):
        if item.objectName() == name:
            return item
        for child in item.childItems():
            found = find_visual(child, name)
            if found is not None:
                return found
        return None

    nav = find_visual(window.contentItem(), "nav-Investigación / Casos")
    pos = nav.mapToScene(QPointF(nav.width() / 2, nav.height() / 2)).toPoint()
    for kind, buttons in [
        (QEvent.MouseButtonPress, Qt.LeftButton),
        (QEvent.MouseButtonRelease, Qt.NoButton),
    ]:
        event = QMouseEvent(
            kind, QPointF(pos), QPointF(pos), Qt.LeftButton, buttons, Qt.NoModifier
        )
        app.sendEvent(window, event)
    assert window.property("page") == "Investigación / Casos"
    selected_id = controller.selected["event_id"]
    controller.setLanguage("en-US")
    wait(30)
    assert nav.property("text") == "Investigation / Cases"
    assert controller.selected["event_id"] == selected_id
    assert controller.model.rowCount() == 240
    assert controller.settings.value("language") == "en-US"
    about = window.findChild(QObject, "about-button")
    pos = about.mapToScene(QPointF(about.width() / 2, about.height() / 2)).toPoint()
    for kind, buttons in [
        (QEvent.MouseButtonPress, Qt.LeftButton),
        (QEvent.MouseButtonRelease, Qt.NoButton),
    ]:
        app.sendEvent(
            window,
            QMouseEvent(
                kind, QPointF(pos), QPointF(pos), Qt.LeftButton, buttons, Qt.NoModifier
            ),
        )
    wait(30)
    dialog = window.findChild(QObject, "about-dialog")
    assert dialog.property("visible")
    from PySide6.QtCore import QMetaObject

    QMetaObject.invokeMethod(dialog, "close")
    assert "GNU GENERAL PUBLIC LICENSE" in controller.licenseText
    legal_button = window.findChild(QObject, "legal-button")
    QMetaObject.invokeMethod(dialog, "open")
    wait(20)
    pos = legal_button.mapToScene(
        QPointF(legal_button.width() / 2, legal_button.height() / 2)
    ).toPoint()
    for kind, buttons in [
        (QEvent.MouseButtonPress, Qt.LeftButton),
        (QEvent.MouseButtonRelease, Qt.NoButton),
    ]:
        app.sendEvent(
            window,
            QMouseEvent(
                kind, QPointF(pos), QPointF(pos), Qt.LeftButton, buttons, Qt.NoModifier
            ),
        )
    wait(20)
    legal = window.findChild(QObject, "legal-dialog")
    assert legal.property("visible")
    assert "INDEPENDENCE AND TRADEMARKS" in controller.legalInformation
    controller.setLanguage("es-419")
    wait(20)
    assert legal.property("title") == "Información legal y componentes"
    assert "INDEPENDENCIA Y MARCAS" in controller.legalInformation
    for index, component in enumerate(controller.legalComponents):
        text = controller.componentLicense(index)
        assert component["name"] in text and len(text) > 150
    assert "exclusively by the GPL V2" in controller.componentLicense(1)
    assert controller.componentLicense(-1) == ""
    QMetaObject.invokeMethod(legal, "close")
    QMetaObject.invokeMethod(dialog, "close")
    from PySide6.QtGui import QDesktopServices

    opened = []
    monkeypatch.setattr(
        QDesktopServices, "openUrl", lambda url: opened.append(url.toString()) or True
    )
    controller.openGithub()
    assert opened == ["https://github.com/Lupo-SysAdmin"]
    controller.setLanguage("es-419")
    assert nav.property("text") == "Investigación / Casos"

    output = tmp_path / "export.json"
    controller.export(QUrl.fromLocalFile(str(output)))
    assert len(json.loads(output.read_text())["events"]) == 240
    window.setProperty("page", "Dashboard")
    window.setWidth(1080)
    window.setHeight(720)
    wait(100)
    assert window.grabWindow().save(str(tmp_path / "small.png"))
    controller.events = demo_events(100_000)
    controller.minutes = 100_000
    controller.refresh()
    wait(100)
    view = window.findChild(QObject, "alerts")
    assert view.property("count") == 100_000
    # Only viewport delegates exist; the list does not instantiate 100k rows.
    assert len(view.property("contentItem").childItems()) < 100
    controller.loadLog(
        QUrl.fromLocalFile(
            str(Path(__file__).parent / "fixtures/snort3/alert_json-3.13.2.0.txt")
        ),
        False,
    )
    for _ in range(100):
        if not controller.busy:
            break
        wait(20)
    assert controller.mode == "replay"
    assert controller.model.rowCount() == 2
    assert all(event["mode"] == "replay" for event in controller.model.rows)
    assert controller.storedCount == 2
    csv_path = tmp_path / "alerts.csv"
    from snort_soc.snort import AlertStore

    test_store = AlertStore(tmp_path / "replay" / "alerts.sqlite3")
    event = dict(controller.model.rows[0], message='=HYPERLINK("example")')
    with test_store.db:
        test_store.db.execute(
            "UPDATE events SET data=? WHERE id=?",
            (json.dumps(event), event["event_id"]),
        )
    test_store.close()
    controller.export(QUrl.fromLocalFile(str(csv_path)))
    for _ in range(100):
        if not controller.busy:
            break
        wait(20)
    import csv

    with csv_path.open() as f:
        exported = list(csv.DictReader(f))
    assert exported[0]["message"].startswith("'=")
    assert csv_path.with_suffix(".csv.metadata.json").exists()
    controller.useDemo()
    assert controller.mode == "demo" and controller.model.rowCount() == 240
    from test_services import FakeManager

    fake_service = FakeManager()
    monkeypatch.setattr("snort_soc.app.ServiceManager", lambda: fake_service)
    controller.serviceAction("start")
    assert controller.service_future is None  # Demo must not change the host.
    controller.manageRealService()
    for _ in range(100):
        if controller.service_refresh_future is None:
            break
        wait(10)
    window.setProperty("page", "Servicio")
    wait(30)
    start_button = window.findChild(QObject, "start-service")
    assert start_button.property("enabled")
    # Background reads must neither disable controls nor notify unchanged state.
    from concurrent.futures import Future
    from copy import deepcopy

    updates, global_updates = [], []
    controller.serviceChanged.connect(lambda: updates.append(True))
    controller.changed.connect(lambda: global_updates.append(True))
    snapshot = deepcopy(controller._service)
    for _ in range(3):
        pending = Future()
        controller.service_refresh_future = pending
        assert not controller.service["busy"]
        wait(20)
        assert start_button.property("enabled")
        pending.set_result(deepcopy(snapshot))
        controller.pollService()
    assert not updates and not global_updates
    # A real external state change must still reach the service panel.
    pending = Future()
    controller.service_refresh_future = pending
    changed = deepcopy(snapshot)
    changed["units"][0]["boot"] = "enabled"
    pending.set_result(changed)
    controller.pollService()
    assert len(updates) == 1 and not global_updates
    pending = Future()
    controller.service_refresh_future = pending
    pending.set_result(snapshot)
    controller.pollService()
    pos = start_button.mapToScene(
        QPointF(start_button.width() / 2, start_button.height() / 2)
    ).toPoint()
    for kind, buttons in [
        (QEvent.MouseButtonPress, Qt.LeftButton),
        (QEvent.MouseButtonRelease, Qt.NoButton),
    ]:
        app.sendEvent(
            window,
            QMouseEvent(
                kind, QPointF(pos), QPointF(pos), Qt.LeftButton, buttons, Qt.NoModifier
            ),
        )
    for _ in range(100):
        if not controller.service["busy"]:
            break
        wait(10)
    assert controller.service["active"] == "active"
    boot = window.findChild(QObject, "service-autostart")
    pos = boot.mapToScene(QPointF(20, boot.height() / 2)).toPoint()
    for kind, buttons in [
        (QEvent.MouseButtonPress, Qt.LeftButton),
        (QEvent.MouseButtonRelease, Qt.NoButton),
    ]:
        app.sendEvent(
            window,
            QMouseEvent(
                kind, QPointF(pos), QPointF(pos), Qt.LeftButton, buttons, Qt.NoModifier
            ),
        )
    for _ in range(100):
        if not controller.service["busy"]:
            break
        wait(10)
    assert controller.service["boot"] == "enabled"
    assert boot.property("checked")
    controller.serviceAction("stop")
    for _ in range(100):
        if not controller.service["busy"]:
            break
        wait(10)
    assert (
        controller.service["active"] == "inactive"
        and controller.service["boot"] == "enabled"
    )
    for page in [
        "Topología",
        "Tráfico",
        "Correlación MITRE",
        "PCAP",
        "Respuesta / Firewall",
        "Reglas",
    ]:
        window.setProperty("page", page)
        wait(30)
    controller.useDemo()
    controller.saveMapping(
        "1:1000001:1",
        "T1046",
        "Network Service Discovery",
        "low",
        "Synthetic test annotation",
    )
    assert controller.mitreMappings
    controller.inspectCapture(
        QUrl.fromLocalFile(str(Path(__file__).parent / "fixtures/lab/benign.pcapng"))
    )
    for _ in range(100):
        if not controller.busy:
            break
        wait(20)
    assert controller.mode == "replay" and controller.captureInfo["packets"] == 3
    assert len(controller.packetRows) == 3
    assert (
        not controller.mapping_store.latest()
    )  # Demo annotations must not leak into replay/live.
    assert not errors, errors
    window.close()
    del view, nav, search, window
    del engine
    app.processEvents()
    controller.close()
