from pathlib import Path

import pytest
from PySide6.QtCore import QEventLoop, QTimer, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine

from jaltrix.app import Controller
from jaltrix.onboarding import probe_engine


def wait_ready(controller):
    for _ in range(400):
        loop = QEventLoop()
        QTimer.singleShot(10, loop.quit)
        loop.exec()
        if not controller.busy and controller._setup_future is None:
            return
    raise AssertionError("Setup did not finish")


@pytest.mark.parametrize(
    "banner,state",
    [
        ("Snort++ Version 3.13.2.0", "compatible"),
        ("Snort Version 2.9.20", "incompatible"),
        ("unrelated Version 3.1", "incompatible"),
    ],
)
def test_version_detection(tmp_path, banner, state):
    script = tmp_path / "snort"
    script.write_text("#!/bin/sh\nprintf '%s\\n' '" + banner + "'\n")
    script.chmod(0o700)
    assert probe_engine(script)["state"] == state
    assert probe_engine(None)["state"] == "missing"
    assert probe_engine(tmp_path / "missing")["state"] == "error"


def test_first_run_live_restore_and_missing_source(tmp_path, monkeypatch):
    app = QGuiApplication.instance() or QGuiApplication([])
    monkeypatch.setattr("jaltrix.onboarding.find_engine", lambda: None)
    controller = Controller(tmp_path / "data")
    controller.restoreStartup()
    wait_ready(controller)
    assert controller.showSetup and controller.mode == "live"
    assert controller.model.rowCount() == 0
    assert controller.setupInfo["state"] == "missing"
    assert controller.service_future is None
    source = tmp_path / "alerts.json"
    source.write_text('{"rule":"1:42:1","src_addr":"8.8.8.8"}\n')
    controller.loadLog(QUrl.fromLocalFile(str(source)), True)
    wait_ready(controller)
    assert controller.setupInfo["connected"] and controller.storedCount == 1
    controller.chooseReal()  # Service/boot controls must preserve connected alerts.
    assert controller.sourcePath == str(source) and controller.setupInfo["connected"]
    assert controller.settings.value("startup/mode") == "live"
    controller.close()
    restored = Controller(tmp_path / "data")
    restored.restoreStartup()
    wait_ready(restored)
    assert restored.mode == "live" and not restored.showSetup
    assert restored.sourcePath == str(source) and restored.storedCount == 1
    restored.close()
    source.unlink()
    missing = Controller(tmp_path / "data")
    missing.restoreStartup()
    wait_ready(missing)
    assert missing.mode == "live" and missing.showSetup
    assert not missing.setupInfo["connected"]
    assert all(event["mode"] != "demo" for event in missing.model.rows)
    missing.chooseDemo()
    assert missing.settings.value("startup/mode") == "demo"
    missing.close()
    demo = Controller(tmp_path / "data")
    demo.restoreStartup()
    assert not demo.showSetup and demo.mode == "demo"
    demo.close()
    app.processEvents()


def test_first_run_qml_languages_and_steps(tmp_path, monkeypatch):
    app = QGuiApplication.instance() or QGuiApplication([])
    monkeypatch.setattr("jaltrix.onboarding.find_engine", lambda: None)
    controller = Controller(tmp_path)
    controller.restoreStartup()
    engine = QQmlApplicationEngine()
    warnings = []
    engine.warnings.connect(
        lambda values: warnings.extend(v.toString() for v in values)
    )
    engine.rootContext().setContextProperty("soc", controller)
    engine.rootContext().setContextProperty("eventModel", controller.model)
    engine.load(
        QUrl.fromLocalFile(str(Path(__file__).parents[1] / "src/jaltrix/ui/Main.qml"))
    )
    window = engine.rootObjects()[0]
    try:
        wait_ready(controller)
        assert window.property("page") == "Inicio"
        setup = next(
            child
            for child in visual_children(window.contentItem())
            if child.objectName() == "setup-view"
        )
        for locale in ("es-419", "en-US"):
            controller.setLanguage(locale)
            window.resize(1080, 720)
            for step in (0, 1, 2):
                setup.setProperty("step", step)
                wait_ready(controller)
                assert setup.width() > 700 and setup.height() > 350
                assert window.grabWindow().save(
                    str(tmp_path / f"setup-{locale}-{step}.png")
                )
        assert not warnings, warnings
    finally:
        window.close()
        del window, engine
        app.processEvents()
        controller.close()


def visual_children(item):
    yield item
    for child in item.childItems():
        yield from visual_children(child)


def test_new_sensor_preserves_existing_profile(tmp_path, monkeypatch):
    from jaltrix import privileged

    config = tmp_path / "config"
    config.mkdir()
    keep = config / "sentinel"
    keep.write_text("keep")
    monkeypatch.setattr(privileged, "CONFIG", config)
    monkeypatch.setattr(privileged, "trusted", lambda path: None)
    with pytest.raises(ValueError, match="preserved"):
        privileged.initialize({}, "1000")
    assert keep.read_text() == "keep"
