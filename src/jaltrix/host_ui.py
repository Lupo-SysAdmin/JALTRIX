"""Optional local Linux observability UI; never performs collection on the UI thread."""

import json
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QObject, Property, QTimer, QUrl, Signal, Slot

from .core import CaseStore
from .host_events import HostEventStore
from . import host_service
from .snort import AlertStore


class HostController(QObject):
    changed = Signal()
    configChanged = Signal()
    eventsChanged = Signal()
    hostsChanged = Signal()
    correlationsChanged = Signal()
    evidenceChanged = Signal()
    caseEvidenceChanged = Signal()
    notice = Signal(str)
    caseCreated = Signal(str)
    CASE_PREFIX = "host-correlation:"
    PAGE_SIZE = 100

    def __init__(self, controller):
        super().__init__(controller)
        self.controller = controller
        self.data_dir = controller.data_dir
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="host-ui")
        self._future = None
        self._operation = ""
        self._generation = 0
        self._visible = False
        self._pending_refresh = False
        self._pending_operation = None
        self._loaded = False
        self._config = {}
        self._state = {}
        self._events, self._hosts, self._correlations = [], [], []
        self._selected, self._timeline, self._case_timeline = {}, [], []
        self._case_id = ""
        self._case_error = ""
        self._error = ""
        self._query, self._source = "", ""
        self._offset, self._total = 0, 0
        self._poller = QTimer(self)
        self._poller.setInterval(100)
        self._poller.timeout.connect(self.poll)
        self._poller.start()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self.refresh)

    @Property(bool, notify=changed)
    def live(self):
        return self.controller.mode == "live"

    @Property(bool, notify=changed)
    def ready(self):
        return self.live and self._loaded

    @Property(bool, notify=changed)
    def busy(self):
        # Background reads must not disable controls or replace stable content.
        return (
            bool(self._pending_operation)
            or self._future is not None
            and self._operation != "snapshot"
        )

    @Property("QVariantMap", notify=configChanged)
    def config(self):
        return self._config if self.live else {}

    @Property("QVariantMap", notify=changed)
    def status(self):
        return self._state if self.live else {}

    @Property(str, notify=changed)
    def error(self):
        return self._error if self.live else ""

    @Property("QVariantList", notify=eventsChanged)
    def events(self):
        return self._events if self.live else []

    @Property("QVariantList", notify=hostsChanged)
    def hosts(self):
        return self._hosts if self.live else []

    @Property("QVariantList", notify=correlationsChanged)
    def correlations(self):
        return self._correlations if self.live else []

    @Property("QVariantMap", notify=evidenceChanged)
    def selected(self):
        return self._selected if self.live else {}

    @Property("QVariantList", notify=evidenceChanged)
    def timeline(self):
        return self._timeline if self.live else []

    @Property("QVariantList", notify=caseEvidenceChanged)
    def caseTimeline(self):
        return self._case_timeline if self.live else []

    @Property(bool, notify=changed)
    def caseHasEvidence(self):
        return self.live and bool(self._case_id)

    @Property(str, notify=caseEvidenceChanged)
    def caseEvidenceError(self):
        return self._case_error if self.live else ""

    @Property("QVariantMap", notify=changed)
    def pagination(self):
        return dict(
            offset=self._offset, total=self._total, next=self._offset + len(self.events)
        )

    def modeChanged(self):
        self._generation += 1
        self._loaded = False
        self._events, self._hosts, self._correlations = [], [], []
        self._selected, self._timeline, self._case_timeline = {}, [], []
        self._case_id, self._error, self._case_error = "", "", ""
        self._offset, self._total = 0, 0
        self._state, self._config = {}, {}
        self._pending_refresh = False
        self._pending_operation = None
        self._pending_case_id = ""
        self.changed.emit()
        self.configChanged.emit()
        self.eventsChanged.emit()
        self.hostsChanged.emit()
        self.correlationsChanged.emit()
        self.evidenceChanged.emit()
        self.caseEvidenceChanged.emit()
        if self.live and self._visible:
            self._refresh_timer.start()
            self.refresh()
        else:
            self._refresh_timer.stop()

    @Slot(bool)
    def setVisible(self, visible):
        self._visible = visible
        if visible and self.live:
            self._refresh_timer.start()
            self.refresh()
        else:
            self._refresh_timer.stop()

    def _submit(self, operation, function, *args):
        if not self.live:
            return False
        if self._future is not None:
            if operation == "snapshot":
                self._pending_refresh = True
            elif self._operation == "snapshot" and self._pending_operation is None:
                self._pending_operation = (operation, function, args)
                self.changed.emit()
                return True
            return False
        self._operation = operation
        self._job_generation = self._generation
        self._future = self._executor.submit(function, *args)
        if operation != "snapshot":
            self.changed.emit()
        return True

    def _snapshot(self, query, source, offset):
        config = host_service.load_config(self.data_dir)
        state = host_service.health(self.data_dir)
        state["capabilities"] = host_service.source_capabilities(config)
        store = HostEventStore(self.data_dir / "live" / "host-events.sqlite3")
        try:
            return dict(
                config=config,
                state=state,
                events=store.events(
                    query=query, source=source, limit=self.PAGE_SIZE, offset=offset
                ),
                total=store.count(query=query, source=source),
                hosts=store.hosts(),
                correlations=store.correlations(limit=100),
                offset=offset,
                query=query,
                source=source,
            )
        finally:
            store.close()

    @Slot()
    def refresh(self):
        self._submit(
            "snapshot", self._snapshot, self._query, self._source, self._offset
        )

    @Slot(str, str)
    def filter(self, query, source):
        if not self.live:
            return
        self._query, self._source = query[:512], source
        self._offset = 0
        self.refresh()

    @Slot(int)
    def changePage(self, delta):
        if not self.live:
            return
        offset = max(0, self._offset + delta * self.PAGE_SIZE)
        if offset and offset >= self._total:
            return
        self._offset = offset
        self.refresh()

    def _evidence(self, correlation_id):
        store = HostEventStore(self.data_dir / "live" / "host-events.sqlite3")
        try:
            return dict(
                requested_id=correlation_id,
                correlation=store.get_correlation(correlation_id) or {},
                events=store.correlation_events(correlation_id),
            )
        finally:
            store.close()

    @Slot(str)
    def selectCorrelation(self, correlation_id):
        self._submit("evidence", self._evidence, correlation_id)

    def openCaseEvidence(self, event_id):
        self._case_timeline = []
        self._case_error = ""
        self._case_id = (
            event_id[len(self.CASE_PREFIX) :]
            if self.live and event_id.startswith(self.CASE_PREFIX)
            else ""
        )
        self.caseEvidenceChanged.emit()
        self.changed.emit()
        # Queue a case read after a snapshot without cancelling another action.
        if self._case_id and not self._submit(
            "case-evidence", self._evidence, self._case_id
        ):
            self._pending_case_id = self._case_id

    def _create_case(self, correlation_id, language):
        store = HostEventStore(self.data_dir / "live" / "host-events.sqlite3")
        cases = CaseStore(self.data_dir / "live" / "cases.sqlite3", mode="live")
        try:
            # Keep retention from removing a correlation between case creation
            # in the existing CaseStore and pinning its original evidence.
            return store.create_case(correlation_id, cases, language)
        finally:
            cases.close()
            store.close()

    @Slot(str)
    def createCase(self, correlation_id):
        self._submit(
            "case", self._create_case, correlation_id, self.controller.language
        )

    def _save(self, config, source_path, bind_current, action):
        if config["snort_enabled"] and bind_current:
            # Bind precisely the user's current LIVE source, preserving migrated IDs.
            path = self.data_dir / "live" / "alerts.sqlite3"
            if not source_path or not path.is_file():
                raise ValueError("Connect an existing LIVE Snort alert source first")
            alerts = AlertStore(path)
            try:
                identity = alerts.source_id(source_path, "live")
                if not alerts.db.execute(
                    "SELECT 1 FROM sources WHERE id=? AND mode='live'", (identity,)
                ).fetchone():
                    raise ValueError("The selected Snort source has not been imported")
                config["snort_source_id"] = identity
            finally:
                alerts.close()
        elif not config["snort_enabled"]:
            config["snort_source_id"] = ""
        elif not config.get("snort_source_id"):
            raise ValueError("Explicitly bind a local Snort source first")
        saved = host_service.save_config(self.data_dir, config)
        if action == "start":
            host_service.control(self.data_dir, "start")
        return saved

    @Slot(bool, bool, str, bool, bool, int, int, bool)
    def saveConfig(
        self, journal, audit, audit_path, snort, bind_current, days, limit, start
    ):
        if not self.ready:
            return
        config = dict(
            self._config,
            journal_enabled=journal,
            audit_enabled=audit,
            audit_path=audit_path,
            snort_enabled=snort,
            snort_host_binding=snort,
            retention_days=days,
            max_events=limit,
        )
        self._submit(
            "config",
            self._save,
            config,
            self.controller.sourcePath,
            bind_current,
            "start" if start else "save",
        )

    @Slot()
    def stop(self):
        self._submit("stop", host_service.control, self.data_dir, "stop")

    @Slot(QUrl, result=str)
    def localPath(self, url):
        return url.toLocalFile() if url.isLocalFile() else ""

    @Slot("QVariantMap", result=str)
    def eventDetails(self, event):
        return json.dumps(event, ensure_ascii=False, indent=2, sort_keys=True)

    @Slot()
    def poll(self):
        if self._future is None or not self._future.done():
            return
        future, operation, generation = (
            self._future,
            self._operation,
            self._job_generation,
        )
        self._future, self._operation = None, ""
        changed = operation != "snapshot"
        try:
            result = future.result()
            if generation != self._generation or not self.live:
                return
            if operation == "snapshot":
                if (result["query"], result["source"], result["offset"]) != (
                    self._query,
                    self._source,
                    self._offset,
                ):
                    self._pending_refresh = True
                    return
                values = (
                    result["state"],
                    result["events"],
                    result["hosts"],
                    result["correlations"],
                    result["total"],
                )
                changed = (
                    not self._loaded
                    or bool(self._error)
                    or values
                    != (
                        self._state,
                        self._events,
                        self._hosts,
                        self._correlations,
                        self._total,
                    )
                )
                events_changed = self._events != result["events"]
                hosts_changed = self._hosts != result["hosts"]
                correlations_changed = self._correlations != result["correlations"]
                (
                    self._state,
                    self._events,
                    self._hosts,
                    self._correlations,
                    self._total,
                ) = values
                if events_changed:
                    self.eventsChanged.emit()
                if hosts_changed:
                    self.hostsChanged.emit()
                if correlations_changed:
                    self.correlationsChanged.emit()
                if not self._loaded or result["config"] != self._config:
                    self._config = result["config"]
                    self.configChanged.emit()
                self._loaded = True
                self._error = ""
            elif operation == "evidence":
                self._selected, self._timeline = result["correlation"], result["events"]
                self.evidenceChanged.emit()
            elif operation == "case-evidence":
                if result["requested_id"] != self._case_id:
                    return
                if result["correlation"].get("id") == self._case_id:
                    self._case_timeline = result["events"]
                    self.caseEvidenceChanged.emit()
                elif not result["correlation"]:
                    self._case_error = self.controller.translate(
                        "Evidencias del caso no disponibles"
                    )
                    self.caseEvidenceChanged.emit()
            elif operation == "case":
                self.caseCreated.emit(result)
                self._pending_refresh = True
            elif operation == "config":
                self._config = result
                self.configChanged.emit()
                self._pending_refresh = True
                self.notice.emit(
                    self.controller.translate("Configuración de fuentes guardada")
                )
            elif operation == "stop":
                self._pending_refresh = True
            if operation != "snapshot":
                self._error = ""
        except Exception as exc:
            if generation == self._generation and self.live:
                message = str(exc)
                changed = changed or self._error != message
                self._error = message
                if operation == "case-evidence":
                    self._case_error = message
                    self.caseEvidenceChanged.emit()
                if operation != "snapshot":
                    self.notice.emit(
                        self.controller.translate("Operación fallida") + ": " + message
                    )
        finally:
            if changed:
                self.changed.emit()
            pending_operation = self._pending_operation
            self._pending_operation = None
            if pending_operation:
                name, function, args = pending_operation
                self._submit(name, function, *args)
            pending_case = getattr(self, "_pending_case_id", "")
            self._pending_case_id = ""
            if pending_case and pending_case == self._case_id:
                if not self._submit("case-evidence", self._evidence, pending_case):
                    self._pending_case_id = pending_case
            if self._pending_refresh:
                self._pending_refresh = False
                self.refresh()

    def close(self):
        self._poller.stop()
        self._refresh_timer.stop()
        self._executor.shutdown(wait=True, cancel_futures=True)
