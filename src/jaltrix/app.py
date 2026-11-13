import argparse
import csv
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Reproducible packages can retain identical mtimes across builds. Load the
# shipped QML instead of accepting a stale timestamp-based disk cache.
os.environ.setdefault("QML_DISABLE_DISK_CACHE", "1")

from PySide6.QtCore import (
    QAbstractListModel,
    QModelIndex,
    Property,
    Qt,
    QTimer,
    Signal,
    Slot,
    QUrl,
    QSettings,
    QLocale,
    QObject,
)
from PySide6.QtGui import QGuiApplication, QDesktopServices, QIcon, QImageReader
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle
from . import __version__
from .triage import TriageStore
from .advanced import AdvancedController
from . import continuous
import subprocess
from .localization import Translator
from .snort import AlertStore
from .response import ResponseStore
from .services import ServiceManager, manageable
from .integrations.edr import UnconfiguredEDR
from .engine import find_engine, replay, validate_draft
from .core import CaseStore, demo_events, filter_events, summarize
from .host_ui import HostController


class EventModel(QAbstractListModel):
    def __init__(self):
        super().__init__()
        self.rows = []

    def roleNames(self):
        return {Qt.UserRole + 1: b"event"}

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def data(self, index, role=Qt.DisplayRole):
        if (
            index.isValid()
            and 0 <= index.row() < len(self.rows)
            and role == Qt.UserRole + 1
        ):
            return self.rows[index.row()]
        return None

    def replace(self, rows):
        if self.rows == rows:
            return
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


class Controller(AdvancedController):
    changed = Signal()
    notice = Signal(str)
    languageChanged = Signal()
    caseOpened = Signal()
    serviceChanged = Signal()

    def __init__(self, data_dir):
        super().__init__()
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.data_dir = data_dir
        self.edr = UnconfiguredEDR()
        self._rule_result = {}
        self._case_detail = {}
        self._mode = "demo"
        self._source = ""
        self._pcap = {}
        self._status = "Datos de demostración"
        self._stored = 0
        self._page_offset = 0
        self._query_revision = 0
        self._matched = 0
        self._next_offset = 0
        self._paged = False
        self._facets = []
        self._last_alert = ""
        self._pcap = {}
        self.executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="snort-ingest"
        )
        self.future = None
        self.service_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="snort-service"
        )
        self.service_future = None
        self.service_refresh_future = None
        self.service_manager = None
        self._service = {"owner": "", "units": []}
        self._service_error = ""
        self.poller = QTimer(self)
        self.poller.setInterval(100)
        self.poller.timeout.connect(self.pollJob)
        self.poller.timeout.connect(self.pollService)
        self.poller.start()
        self.tail_timer = QTimer(self)
        self.tail_timer.setInterval(2000)
        self.tail_timer.timeout.connect(self.tailSource)
        self.settings = QSettings(str(data_dir / "settings.ini"), QSettings.IniFormat)
        saved_engine = self.settings.value("engine_path", "")
        if saved_engine:
            os.environ["JALTRIX_ENGINE"] = saved_engine
        locale = self.settings.value("language", "es-419")
        self.translator = Translator(
            locale if locale in ("es-419", "en-US") else "es-419"
        )
        self.events = demo_events()
        self.model = EventModel()
        self.triage_store = TriageStore(data_dir / "demo" / "triage.sqlite3")
        self.store = CaseStore(data_dir / "demo" / "cases.sqlite3")
        self.response_store = ResponseStore(data_dir / "demo" / "response.sqlite3")
        self._selected = self.events[0]
        self.query, self.severity, self.category, self.minutes = (
            "",
            "Todas",
            "Todas",
            1440,
        )
        self.initAdvanced()
        self.initSetup()
        self._host = HostController(self)
        self._host.notice.connect(self.notice.emit)
        self._host.caseCreated.connect(self.openCase)
        self.setupChanged.connect(self.changed.emit)
        self.refresh()

    @Property(QObject, constant=True)
    def host(self):
        return self._host

    @Property("QVariantMap", notify=serviceChanged)
    def service(self):
        units = self._service.get("units", [])
        unit = (
            units[0]
            if units
            else {
                "name": "jaltrix-sensor.service",
                "active": "unknown",
                "boot": "unknown",
                "load": "unknown",
            }
        )
        return dict(
            unit,
            manageable=manageable(self._service),
            error=self._service_error,
            busy=self.service_future is not None,
        )

    def runService(self, action=None, expected=None):
        if self.service_manager is None:
            self.service_manager = ServiceManager()
        return (
            self.service_manager.snapshot()
            if action is None
            else self.service_manager.apply(action, expected)
        )

    @Slot()
    def refreshService(self):
        if self.service_future is None and self.service_refresh_future is None:
            self.service_refresh_future = self.service_executor.submit(self.runService)

    @Slot()
    def manageRealService(self):
        if self.busy:
            return
        self.useDemo()  # Stop any previous follow; no network operations.
        self._source = ""
        self._status = "Servicio del sistema seleccionado"
        self.changeMode("live")
        self.refreshService()
        self.rememberSession("service")

    @Slot(str)
    def serviceAction(self, action):
        if self._mode == "demo" or self.service_future is not None:
            self.notice.emit(self.translate("El modo demo no modifica servicios."))
            return
        if action not in ("start", "stop", "enable", "disable"):
            return
        expected = self._service
        self._service_error = ""
        self.service_future = self.service_executor.submit(
            self.runService, action, expected
        )
        self.serviceChanged.emit()

    @Slot()
    def pollService(self):
        for attr in ("service_refresh_future", "service_future"):
            future = getattr(self, attr)
            if future is None or not future.done():
                continue
            before = self.service
            setattr(self, attr, None)
            # A queued action supersedes the preceding read-only snapshot.
            if attr == "service_refresh_future" and self.service_future is not None:
                continue
            previous_error = self._service_error
            try:
                self._service = future.result()
                self._service_error = ""
            except Exception as exc:
                self._service_error = str(exc)
                self._service = {"owner": "", "units": []}
                if self._service_error != previous_error or attr == "service_future":
                    self.notice.emit(self.translate(self._service_error))
            if self.service != before:
                self.serviceChanged.emit()

    @Slot()
    def followServiceLog(self):
        self.loadLog(QUrl.fromLocalFile("/var/log/jaltrix/alert_json.txt"), True)

    @Property("QVariantList", notify=changed)
    def proposals(self):
        return self.response_store.list()

    @Slot(str, str, str)
    def proposeResponse(self, kind, target, reason):
        try:
            self.response_store.propose(kind, target, reason)
            self.changed.emit()
            self.notice.emit(
                self.translate("Propuesta guardada; ningún cambio de red aplicado.")
            )
        except ValueError as exc:
            self.notice.emit(str(exc))

    @Slot(str)
    def activateException(self, proposal_id):
        try:
            self.response_store.activate_triage(
                proposal_id, self._selected.get("sid", "")
            )
            self.refresh()
        except ValueError as exc:
            self.notice.emit(str(exc))

    @Slot(str)
    def revokeProposal(self, proposal_id):
        self.response_store.revoke(proposal_id)
        self.refresh()

    @Property("QVariantMap", notify=changed)
    def edrCapabilities(self):
        return {
            key: {"available": cap.available, "reason": cap.reason}
            for key, cap in self.edr.discover_capabilities().items()
        }

    @Property(str, notify=changed)
    def enginePath(self):
        return str(find_engine() or "")

    @Slot(QUrl)
    def setEnginePath(self, url):
        path = Path(url.toLocalFile())
        if path.is_file() and os.access(path, os.X_OK):
            self.settings.setValue("engine_path", str(path.resolve()))
            self.settings.sync()
            os.environ["JALTRIX_ENGINE"] = str(path.resolve())
            self.changed.emit()
            self.refreshSetup()

    @Property("QVariantMap", notify=changed)
    def ruleResult(self):
        return self._rule_result

    @Slot(str)
    def validateRule(self, text):
        if not self.busy:
            self.future = self.executor.submit(
                lambda: {
                    "kind": "rule",
                    "validation": validate_draft(
                        text, self.data_dir / "rules" / "drafts"
                    ),
                }
            )
            self.changed.emit()

    @Property("QVariantMap", notify=changed)
    def caseDetail(self):
        return self._case_detail

    @Slot(str)
    def openCase(self, case_id):
        self._case_detail = next(
            (c for c in self.store.list() if c["id"] == case_id), {}
        )
        self._host.openCaseEvidence(self._case_detail.get("event_id", ""))
        self.changed.emit()
        if self._case_detail:
            self.caseOpened.emit()

    @Slot(str, str)
    def saveCase(self, notes, status):
        try:
            self.store.update(self._case_detail["id"], notes, status)
            self._case_detail = next(
                c for c in self.store.list() if c["id"] == self._case_detail["id"]
            )
            self.changed.emit()
            self.notice.emit(
                self.translate("Caso guardado: %1").replace(
                    "%1", self._case_detail["id"]
                )
            )
        except (ValueError, KeyError, OSError) as exc:
            self.notice.emit(str(exc))

    @Property("QVariantMap", notify=changed)
    def pcapInfo(self):
        return self._pcap

    @Property(str, notify=changed)
    def rulesPath(self):
        return self.settings.value("rules_path", "")

    @Slot(QUrl)
    def setRulesPath(self, url):
        path = url.toLocalFile()
        if path:
            self.settings.setValue("rules_path", path)
            self.settings.sync()
            self.changed.emit()

    def replayJob(self, pcap, rules):
        info = replay(pcap, rules, self.data_dir / "replay" / "runs")
        result = self.ingestJob(info["log_path"], "replay")
        result["pcap"] = info
        return result

    @Slot(QUrl)
    def replayPcap(self, url):
        if self.busy:
            return
        if not self.rulesPath:
            self.notice.emit(self.translate("Selecciona primero un archivo de reglas."))
            return
        self.tail_timer.stop()
        self._source = ""
        self._pcap = {}
        self._status = "Validando reglas y procesando PCAP…"
        self.changeMode("replay")
        self.future = self.executor.submit(
            self.replayJob, url.toLocalFile(), self.rulesPath
        )
        self.changed.emit()

    @Property(str, notify=changed)
    def mode(self):
        return self._mode

    @Property(str, notify=changed)
    def sourcePath(self):
        return self._source

    @Property(str, notify=changed)
    def ingestionStatus(self):
        return self._status

    @Property(int, notify=changed)
    def storedCount(self):
        return self._stored

    @Property(str, constant=True)
    def logoAsset(self):
        return (
            "app-logo.svg"
            if b"svg" in QImageReader.supportedImageFormats()
            else "app-logo.png"
        )

    @Property(str, constant=True)
    def version(self):
        return __version__

    @Property(bool, notify=changed)
    def busy(self):
        return self.future is not None

    def changeMode(self, mode):
        self._connected = False
        self._setup_message = ""
        self.setupChanged.emit()
        self.resetGeoSelection()
        self.category = "Todas"
        self._facets = []
        self._last_alert = ""
        self._operation_plan = {}
        self._operation_result = {}
        self._stored = 0
        self.triage_store.close()
        self.triage_store = TriageStore(self.data_dir / mode / "triage.sqlite3")
        self.mapping_store.close()
        from .enrichment import MappingStore

        self.mapping_store = MappingStore(self.data_dir / mode / "mappings.sqlite3")
        self._mode = mode
        self._case_detail = {}
        self._host.modeChanged()
        self._paged = False
        self._page_offset = 0
        self._matched = 0
        self.response_store.close()
        self.response_store = ResponseStore(self.data_dir / mode / "response.sqlite3")
        self.store.close()
        self.store = CaseStore(self.data_dir / mode / "cases.sqlite3", mode=mode)
        self.events = demo_events() if mode == "demo" else []
        self._selected = self.events[0] if self.events else self.emptySelection()
        self.refresh()

    @staticmethod
    def emptySelection():
        return dict(
            event_id="",
            message="Sin selección",
            severity="Sin información",
            sid="—",
            src="—",
            dst="—",
            protocol="—",
            timestamp="—",
            mode="replay",
            action="—",
            source="—",
            timestamp_confidence="unknown",
        )

    @Slot()
    def useDemo(self):
        if self.busy:
            return
        self.tail_timer.stop()
        self._source = ""
        self._pcap = {}
        self._status = "Datos de demostración"
        self._stored = 0
        self.changeMode("demo")
        self.rememberSession("demo")

    def queryJob(self, source, mode, ingest=False):
        revision = self._query_revision
        query, severity, minutes, offset, category = (
            self.query,
            self.severity,
            self.minutes,
            self._page_offset,
            self.category,
        )
        store = AlertStore(self.data_dir / mode / "alerts.sqlite3")
        try:
            state = continuous.health(self.data_dir)
            independent = (
                state.get("fresh")
                and state.get("source") == str(Path(source).resolve())
                and mode == "live"
            )
            source_id = store.source_id(source, mode)
            result = (
                store.ingest(source, mode)
                if ingest and not independent
                else dict(source_id=source_id, rejected=0, inserted=0, more=False)
            )
            page = store.query(
                mode,
                source_id=result["source_id"],
                query=query,
                severity=severity,
                minutes=minutes,
                offset=offset,
                category=category,
            )
            return dict(
                query_revision=revision,
                result=result,
                events=page["events"],
                page=page,
                count=store.count(mode, result["source_id"]),
                facets=store.categories(
                    mode, result["source_id"], query, severity, minutes
                ),
                last_alert=store.db.execute(
                    "SELECT max(timestamp) FROM events WHERE mode=? AND source_id=?",
                    (mode, result["source_id"]),
                ).fetchone()[0]
                or "",
            )
        finally:
            store.close()

    def ingestJob(self, source, mode):
        return self.queryJob(source, mode, True)

    @Property("QVariantMap", notify=changed)
    def pagination(self):
        return dict(
            offset=self._page_offset,
            matched=self._matched,
            next=self._next_offset,
            shown=len(self.events),
        )

    @Slot(int)
    def changePage(self, direction):
        if self.busy or self.mode == "demo" or not self._source:
            return
        self._page_offset = (
            self._next_offset if direction > 0 else max(0, self._page_offset - 500)
        )
        self.future = self.executor.submit(self.queryJob, self._source, self.mode)
        self.changed.emit()

    @Slot(QUrl, bool)
    def loadLog(self, url, follow):
        if self.busy:
            return
        source = url.toLocalFile()
        if not source:
            self.notice.emit(self.translate("Selecciona un archivo local."))
            return
        self.tail_timer.stop()
        self._source = source
        self._pcap = {}
        self._status = "Leyendo archivo…"
        self.changeMode("live" if follow else "replay")
        self.future = self.executor.submit(self.ingestJob, source, self._mode)
        self._connection_future = self.future
        self.changed.emit()
        if follow:
            self.tail_timer.start()

    @Slot()
    def tailSource(self):
        if not self.busy and self._source:
            self.future = self.executor.submit(self.ingestJob, self._source, self._mode)
            self._connection_future = self.future
            self.changed.emit()

    @Slot()
    def pollJob(self):
        if self.future is None or not self.future.done():
            return
        future, self.future = self.future, None
        try:
            result = future.result()
            if result.get("kind") == "export":
                self.notice.emit(
                    self.translate("Exportadas %1 alertas").replace(
                        "%1", str(result["count"])
                    )
                )
                self.changed.emit()
                return
            if self.advancedResult(result):
                return
            if result.get("kind") == "rule":
                self._rule_result = result["validation"]
                self.changed.emit()
                return
            if "pcap" in result:
                self._pcap = result["pcap"]
                self._source = self._pcap["log_path"]
            if (
                result.get("query_revision", self._query_revision)
                != self._query_revision
            ):
                self.future = self.executor.submit(
                    self.ingestJob, self._source, self.mode
                )
                self.changed.emit()
                return
            selected_id = self._selected.get("event_id")
            self.events = result["events"]
            self._facets = result.get("facets", [])
            self._last_alert = result.get("last_alert", "")
            if "page" in result:
                self._paged = True
                self._matched = result["page"]["matched"]
                self._page_offset = result["page"]["offset"]
                self._next_offset = result["page"]["next_offset"]
            self._stored = result["count"]
            self._selected = next(
                (e for e in self.events if e["event_id"] == selected_id),
                self._selected
                if self._geo_selected_id == selected_id
                else self.events[0]
                if self.events
                else self.emptySelection(),
            )
            stats = result["result"]
            self._status = (
                "Registros inválidos en cuarentena"
                if stats["rejected"]
                else "Registro parcial; esperando fin de línea"
                if stats["more"] and not stats["inserted"]
                else "Archivo leído; estado del sensor no verificado"
            )
            self.connectionResult(True)
            self.refresh()
            # Drain bounded batches on later event-loop turns; never block the GUI.
            if stats["more"] and stats["inserted"] + stats["rejected"] > 0:
                self.tailSource()
        except Exception as exc:
            reading = getattr(self, "_connection_future", None) is future
            if reading:
                self.connectionResult(False)
            self._status = "Error de lectura" if reading else "Operación fallida"
            self.changed.emit()
            self.notice.emit(self.translate(self._status) + ": " + str(exc))

    def close(self):
        self._host.close()
        self._geo_visible = False
        self._geo_executor.shutdown(wait=True, cancel_futures=True)
        self.advanced_timer.stop()
        self.mapping_store.close()
        self.triage_store.close()
        self.poller.stop()
        self.tail_timer.stop()
        self.executor.shutdown(wait=True, cancel_futures=True)
        if self.service_manager is not None and hasattr(self.service_manager, "cancel"):
            self.service_manager.cancel.cancel()
        self.service_executor.shutdown(wait=True, cancel_futures=True)
        self.store.close()
        self.response_store.close()

    @Property(str, notify=languageChanged)
    def language(self):
        return self.translator.locale

    @Slot(str)
    def setLanguage(self, locale):
        if locale not in ("es-419", "en-US"):
            return
        self.translator.locale = locale
        QLocale.setDefault(QLocale("en_US" if locale == "en-US" else "es_MX"))
        self.settings.setValue("language", locale)
        self.settings.sync()
        self.languageChanged.emit()
        if self.settings.status() != QSettings.NoError:
            self.notice.emit(
                "Language preference could not be saved / No se pudo guardar el idioma"
            )

    @Slot(str, result=str)
    def translate(self, value):
        return self.translator.text(value)

    @Property(str, constant=True)
    def licenseText(self):
        return (Path(__file__).parent / "LICENSE").read_text(encoding="utf-8")

    @Property(str, notify=languageChanged)
    def legalInformation(self):
        import platform, sqlite3, PySide6
        from PySide6.QtCore import qVersion

        try:
            import gi

            gi_version = gi.__version__
        except ImportError:
            gi_version = "—"
        info = json.loads(
            (Path(__file__).parent / "legal/information.json").read_text()
        )
        runtime = (
            "Versiones cargadas" if self.language == "es-419" else "Loaded versions"
        )
        baseline = (
            "Snort/LibDAQ: versiones de referencia del laboratorio; no acreditan el ejecutable seleccionado. Motor con dos parches locales de enlace/RPATH."
            if self.language == "es-419"
            else "Snort/LibDAQ: lab reference versions; not verification of the selected executable. Engine has two local linkage/RPATH patches."
        )
        return (
            info[self.language]
            + f"\n{runtime}: Python {platform.python_version()} · Qt {qVersion()} · PySide6 {PySide6.__version__} · PyGObject {gi_version} · SQLite {sqlite3.sqlite_version}\n\n{baseline}"
        )

    @Property("QVariantList", constant=True)
    def legalComponents(self):
        return json.loads((Path(__file__).parent / "legal/components.json").read_text())

    @Slot(int, result=str)
    def componentLicense(self, index):
        components = self.legalComponents
        if not 0 <= index < len(components):
            return ""
        item = components[index]
        return (
            item["name"]
            + "\n"
            + item["license"]
            + "\n"
            + item["url"]
            + "\n\n"
            + (Path(__file__).parent / "legal" / item["file"]).read_text()
        )

    @Slot(int)
    def openComponentSource(self, index):
        components = self.legalComponents
        if 0 <= index < len(components):
            QDesktopServices.openUrl(QUrl(components[index]["url"]))

    @Slot()
    def openGithub(self):
        if not QDesktopServices.openUrl(
            QUrl("https://github.com/Lupo-SysAdmin/JALTRIX")
        ):
            self.notice.emit(self.translate("No se pudo abrir el navegador."))

    @Property("QVariantMap", notify=changed)
    def selected(self):
        return self._selected

    @Property("QVariantMap", notify=changed)
    def summary(self):
        return self._summary

    @Property(str, notify=changed)
    def categorySelection(self):
        return self.category

    @Property(str, notify=changed)
    def lastSourceAlert(self):
        return self._last_alert

    @Property("QVariantList", notify=changed)
    def categoryTabs(self):
        if self.mode == "demo":
            from collections import Counter
            from .core import CATEGORIES

            counts = Counter(
                e["category"]
                for e in filter_events(
                    self.events, self.query, self.severity, "Todas", self.minutes
                )
            )
            groups = [dict(label=c, count=counts[c]) for c in CATEGORIES]
        else:
            groups = self._facets
        tabs = [dict(label="Todas", count=sum(c["count"] for c in groups)), *groups]
        if self.category not in {c["label"] for c in tabs}:
            tabs.append(dict(label=self.category, count=0))
        return tabs

    @Slot(str)
    def selectCategory(self, category):
        if category in {c["label"] for c in self.categoryTabs}:
            self.filter(self.query, self.severity, category, self.minutes)

    @Property("QVariantList", notify=changed)
    def cases(self):
        return self.store.list()

    @Property("QVariantMap", notify=changed)
    def selectedTriage(self):
        return self.triage_store.get(self._selected.get("event_id", ""))

    @Slot(int, str, str, str, bool)
    def saveTriage(self, revision, state, notes, tags, bookmark):
        if not self._selected.get("event_id"):
            return
        try:
            self.triage_store.save(
                self._selected["event_id"],
                revision,
                state,
                notes,
                [t.strip() for t in tags.split(",") if t.strip()],
                bookmark,
            )
            self.refresh()
            if self.model.rowCount():
                self.model.dataChanged.emit(
                    self.model.index(0),
                    self.model.index(self.model.rowCount() - 1),
                    [Qt.UserRole + 1],
                )
        except ValueError as exc:
            self.notice.emit(str(exc))

    @Property(str, notify=changed)
    def sensorStatus(self):
        if self._connected:
            return "Archivo de alertas conectado"
        return {
            "compatible": "Snort 3 compatible; conecta un archivo de alertas",
            "missing": "Snort no instalado",
            "incompatible": "Motor incompatible: se necesita Snort 3",
            "error": "No se pudo ejecutar el motor",
        }.get(self._setup_engine["state"], "Comprobando motor…")

    def refresh(self):
        rows = (
            self.events
            if self._paged
            else filter_events(
                self.events, self.query, self.severity, self.category, self.minutes
            )
        )
        saved_triage = self.triage_store.all()
        exceptions = self.response_store.exceptions()
        for row in rows:
            triage = saved_triage.get(
                row["event_id"], dict(state="new", bookmark=False, notes="", tags=[])
            )
            row["triage_exception"] = next(
                (
                    item["reason"]
                    for item in exceptions
                    if item["target"] == row["src"] and item["signature"] == row["sid"]
                ),
                None,
            )
            row["triage"] = triage["state"]
            row["bookmark"] = triage["bookmark"]
            row["notes"] = triage["notes"]
            row["tags"] = triage["tags"]
        self.model.replace(rows)
        self._summary = summarize(rows)
        self.invalidateGeo()
        self.advancedChanged.emit()
        self.changed.emit()

    @Slot(str, str, str, int)
    def filter(self, query, severity, category, minutes):
        self._query_revision += 1
        self.query, self.severity, self.category, self.minutes = (
            query,
            severity,
            category,
            minutes,
        )
        self._page_offset = 0
        if self.mode != "demo" and self._source and not self.busy:
            self.future = self.executor.submit(self.queryJob, self._source, self.mode)
            self.changed.emit()
        else:
            self.refresh()

    @Slot(int)
    def select(self, index):
        if 0 <= index < len(self.model.rows):
            self._geo_selected_id = ""
            self._selected = self.model.rows[index]
            self.changed.emit()

    @Slot()
    def createCase(self):
        try:
            if not self._selected.get("event_id"):
                return
            case_id = self.store.create(self._selected)
            self.changed.emit()
            self.notice.emit(self.translate("Caso guardado: %1").replace("%1", case_id))
        except Exception as exc:
            self.notice.emit(
                self.translate("No se pudo guardar el caso: %1").replace("%1", str(exc))
            )

    @Slot(QUrl)
    def export(self, url):
        if self._mode != "demo" and self._source:
            if self.busy:
                return
            from .reporting import export_query

            filters = dict(
                query=self.query,
                severity=self.severity,
                category=self.category,
                minutes=self.minutes,
            )
            metadata = dict(
                mode=self._mode,
                source=self._source,
                timezone="UTC",
                filters=filters,
                pcap=self._pcap or None,
                cases=self.store.list(),
            )
            self.future = self.executor.submit(
                export_query,
                self.data_dir,
                self._mode,
                self._source,
                filters,
                url.toLocalFile(),
                metadata,
            )
            self.changed.emit()
            return
        try:
            path = Path(url.toLocalFile())
            payload = dict(
                mode=self._mode,
                source="fixture determinista v1"
                if self._mode == "demo"
                else self._source,
                timezone="UTC",
                filters=dict(
                    query=self.query,
                    severity=self.severity,
                    category=self.category,
                    minutes=self.minutes,
                ),
                pcap=self._pcap or None,
                cases=self.store.list(),
                events=self.model.rows,
            )
            if path.suffix.lower() == ".csv":
                fields = [
                    "event_id",
                    "mode",
                    "timestamp",
                    "original_timestamp",
                    "timestamp_confidence",
                    "sid",
                    "src",
                    "src_port",
                    "dst",
                    "dst_port",
                    "protocol",
                    "message",
                    "severity",
                    "action",
                    "source",
                ]
                with path.open("w", encoding="utf-8", newline="") as stream:
                    writer = csv.DictWriter(stream, fieldnames=fields)
                    writer.writeheader()
                    for event in self.model.rows:
                        row = {}
                        for field in fields:
                            value = str(event.get(field) or "")
                            row[field] = (
                                "'" + value
                                if value.lstrip().startswith(("=", "+", "-", "@"))
                                else value
                            )
                        writer.writerow(row)
                metadata = dict(payload)
                metadata.pop("events")
                path.with_suffix(path.suffix + ".metadata.json").write_text(
                    json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            else:
                path.write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            self.notice.emit(
                self.translate("Exportadas %1 alertas").replace(
                    "%1", str(len(self.model.rows))
                )
            )
        except (OSError, ValueError) as exc:
            self.notice.emit(
                self.translate("Exportación fallida: %1").replace("%1", str(exc))
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--map", action="store_true", help="Open the offline threat map"
    )
    parser.add_argument(
        "--setup", action="store_true", help="Open the first-run setup assistant"
    )
    parser.add_argument("--screenshot", type=Path)
    parser.add_argument("--language", choices=["es-419", "en-US"])
    parser.add_argument("--about", action="store_true")
    parser.add_argument("--legal", action="store_true")
    parser.add_argument(
        "--service",
        action="store_true",
        help="Abrir controles del servicio real sin modificarlo",
    )
    parser.add_argument("--log", type=Path)
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--pcap", type=Path)
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument(
        "--quit-after", type=int, default=0, help="Milisegundos; usado para pruebas"
    )
    maintenance = parser.add_mutually_exclusive_group()
    maintenance.add_argument(
        "--migrate-system",
        action="store_true",
        help="Migrate the legacy managed sensor using native administrator authentication",
    )
    maintenance.add_argument(
        "--backup",
        type=Path,
        help="Create a private backup ZIP without opening the GUI",
    )
    maintenance.add_argument(
        "--restore",
        type=Path,
        help="Restore ZIP into a new --data-dir; never overwrites existing data",
    )
    args = parser.parse_args()
    if args.migrate_system:
        helper = Path("/usr/lib/jaltrix/jaltrix/migration.py")
        if not helper.is_file():
            parser.error(
                "Install the JALTRIX package before migrating the system sensor"
            )
        command = ["/usr/bin/python3", "-I", str(helper), "--system"]
        if os.geteuid() != 0:
            command = ["pkexec", "--disable-internal-agent", *command]
        sys.exit(subprocess.run(command).returncode)
    from .migration import user_data_dir

    try:
        data_dir = args.data_dir or user_data_dir()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    if args.backup or args.restore:
        from .backup import create_backup, restore_backup

        try:
            if args.restore and not args.data_dir:
                parser.error("--restore requires a new --data-dir")
            result = (
                create_backup(data_dir, args.backup)
                if args.backup
                else restore_backup(args.restore, data_dir)
            )
            print(json.dumps(result))
        except Exception as exc:
            parser.error(str(exc))
        return
    QQuickStyle.setStyle("Basic")
    app = QGuiApplication(sys.argv[:1])
    app.setApplicationName("JALTRIX")
    app.setDesktopFileName("io.github.LupoSysAdmin.Jaltrix")
    icon = QIcon(str(Path(__file__).parent / "ui/app-icon.svg"))
    icon.addFile(str(Path(__file__).parent / "ui/app-icon.png"))
    app.setWindowIcon(icon)
    app.setOrganizationName("Jan Herrera")
    controller = Controller(data_dir)
    if args.language:
        controller.setLanguage(args.language)
    app.installTranslator(controller.translator)
    if args.setup or not any(
        (
            args.log,
            args.pcap,
            args.service,
            args.screenshot,
        )
    ):
        controller.restoreStartup()
    if args.setup:
        controller.openSetup()
    engine = QQmlApplicationEngine()
    controller.languageChanged.connect(engine.retranslate)
    engine.rootContext().setContextProperty("soc", controller)
    engine.rootContext().setContextProperty("eventModel", controller.model)
    engine.load(QUrl.fromLocalFile(str(Path(__file__).parent / "ui/Main.qml")))
    if not engine.rootObjects():
        controller.close()
        sys.exit(1)
    if args.rules:
        controller.setRulesPath(QUrl.fromLocalFile(str(args.rules.resolve())))
    if args.pcap:
        controller.replayPcap(QUrl.fromLocalFile(str(args.pcap.resolve())))
    elif args.log:
        controller.loadLog(QUrl.fromLocalFile(str(args.log.resolve())), args.follow)
    if args.map:
        engine.rootObjects()[0].setProperty("page", "Mapa de amenazas")
    if args.service:
        engine.rootObjects()[0].setProperty("page", "Servicio")
        controller.manageRealService()
    if args.legal:
        engine.rootObjects()[0].setProperty("showLegal", True)
    if args.about:
        engine.rootObjects()[0].setProperty("showAbout", True)
    if args.screenshot:

        def capture(window=engine.rootObjects()[0]):
            if (
                controller.busy
                or controller.setupInfo["busy"]
                or (controller._geo_visible and controller.geoMap["busy"])
                or controller.service.get("busy")
                or controller.service_refresh_future is not None
            ):
                QTimer.singleShot(200, capture)
                return
            args.screenshot.parent.mkdir(parents=True, exist_ok=True)
            success = window.grabWindow().save(str(args.screenshot))
            print(f"Screenshot: {args.screenshot}; saved={success}", flush=True)
            app.exit(0 if success else 2)

        QTimer.singleShot(1800, capture)
    elif args.quit_after:
        QTimer.singleShot(args.quit_after, app.quit)
    code = app.exec()
    # Destroy QML bindings before their Python context objects.
    del engine
    controller.close()
    sys.exit(code)
