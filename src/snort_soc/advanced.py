"""Qt bindings for independently testable investigation and collector modules."""

from PySide6.QtCore import QObject, Property, Signal, Slot, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from . import capture, continuous
from .observations import topology, InterfaceSampler
from .enrichment import MappingStore, GeoDatabase
import getpass
from . import operations


class AdvancedController(QObject):
    advancedChanged = Signal()
    operationPlanned = Signal()
    ruleDraftReady = Signal(str)

    def initAdvanced(self):
        self._technical_log = ""
        self._operation_plan = {}
        self._operation_result = {}
        self.mapping_store = MappingStore(
            self.data_dir / self._mode / "mappings.sqlite3"
        )
        self.geo_database = None
        self._collector = continuous.health(self.data_dir)
        self._packet_bytes = {}
        self._packet_rows = []
        self._capture_info = {}
        self._packet_offset = 0
        self._traffic = {}
        self._traffic_history = []
        self._interface = ""
        self._sampler = InterfaceSampler()
        self.advanced_timer = QTimer(self)
        self.advanced_timer.setInterval(2000)
        self.advanced_timer.timeout.connect(self.updateAdvanced)
        self.advanced_timer.start()

    @Property("QVariantMap", notify=advancedChanged)
    def collector(self):
        return self._collector

    @Property("QVariantList", notify=advancedChanged)
    def observedEdges(self):
        return topology(self.model.rows)

    @Property("QVariantList", notify=advancedChanged)
    def interfaces(self):
        return self._sampler.interfaces()

    @Property("QVariantMap", notify=advancedChanged)
    def traffic(self):
        return self._traffic

    @Property("QVariantList", notify=advancedChanged)
    def trafficHistory(self):
        return self._traffic_history

    @Slot(str)
    def selectInterface(self, name):
        self._interface = name
        self._traffic_history = []
        self.updateAdvanced()

    @Slot()
    def updateAdvanced(self):
        before = dict(self._collector)
        self._collector = continuous.health(self.data_dir)
        if self._interface:
            try:
                self._traffic = self._sampler.sample(self._interface)
                if self._traffic.get("ready"):
                    self._traffic_history = (self._traffic_history + [self._traffic])[
                        -60:
                    ]
            except (OSError, ValueError) as exc:
                self._traffic = {"ready": False, "error": str(exc)}
        if before != self._collector or self._interface:
            self.advancedChanged.emit()

    @Slot()
    def startCollector(self):
        if self.busy or self.mode != "live" or not self.sourcePath:
            return
        self.future = self.executor.submit(
            lambda: dict(
                kind="collector",
                health=continuous.control(self.data_dir, self.sourcePath),
            )
        )
        self.changed.emit()

    @Slot()
    def stopCollector(self):
        if self.busy:
            return
        self.future = self.executor.submit(
            lambda: dict(
                kind="collector",
                health=continuous.control(self.data_dir, action="stop"),
            )
        )
        self.changed.emit()

    @Slot()
    def connectCollector(self):
        state = continuous.health(self.data_dir)
        if state.get("source"):
            self.loadLog(QUrl.fromLocalFile(state["source"]), True)

    @Property("QVariantList", notify=advancedChanged)
    def packetRows(self):
        return self._packet_rows

    @Property("QVariantMap", notify=advancedChanged)
    def captureInfo(self):
        return self._capture_info

    @Slot(QUrl)
    def inspectCapture(self, url):
        if self.busy:
            return
        path = url.toLocalFile()
        self.tail_timer.stop()
        self._source = ""
        self._pcap = {}
        self.changeMode("replay")

        def job():
            import shutil, uuid

            info = capture.inspect(path)
            folder = self.data_dir / "evidence" / uuid.uuid4().hex
            folder.mkdir(parents=True, mode=0o700)
            frozen = folder / (
                "capture.pcapng" if info["format"] == "PCAPNG" else "capture.pcap"
            )
            shutil.copyfile(info["path"], frozen)
            frozen.chmod(0o600)
            copied = capture.inspect(frozen)
            if copied["sha256"] != info["sha256"]:
                raise ValueError("Capture changed during import")
            info["imported_path"] = str(frozen)
            return dict(kind="capture", info=info, rows=capture.page(frozen), offset=0)

        self.future = self.executor.submit(job)
        self.changed.emit()

    @Slot(int, str)
    def packetPage(self, direction, query):
        if self.busy or not self._capture_info:
            return
        offset = max(0, self._packet_offset + direction * 200) if direction else 0
        info = dict(self._capture_info)
        self.future = self.executor.submit(
            lambda: dict(
                kind="capture",
                info=info,
                offset=offset,
                rows=capture.page(info["imported_path"], offset, query=query),
            )
        )
        self.changed.emit()

    @Slot()
    def openCapture(self):
        if self._capture_info:
            QDesktopServices.openUrl(
                QUrl.fromLocalFile(self._capture_info["imported_path"])
            )

    def advancedResult(self, result):
        kind = result.get("kind")
        if kind == "backup":
            self.notice.emit(
                self.translate("Copia de seguridad guardada: ") + result["path"]
            )
        elif kind == "collector":
            self._collector = result["health"]
        elif kind == "logs":
            self._technical_log = result["text"]
        elif kind == "operation":
            self._operation_result = result["result"]
            self._operation_plan = {}
            self.refreshService()
        elif kind == "geo":
            self.geo_database = result["database"]
        elif kind == "bytes":
            self._packet_bytes = result["bytes"]
        elif kind == "capture":
            self._packet_bytes = {}
            self._capture_info = result["info"]
            self._packet_rows = result["rows"]
            self._packet_offset = result["offset"]
        else:
            return False
        self.advancedChanged.emit()
        self.changed.emit()
        return True

    @Property("QVariantList", notify=advancedChanged)
    def mitreMappings(self):
        return self.mapping_store.summarize(self.model.rows)

    @Property("QVariantList", notify=advancedChanged)
    def geoLocations(self):
        if self.geo_database is None:
            return []
        locations = []
        for address in sorted({e["src"] for e in self.model.rows}):
            try:
                location = self.geo_database.lookup(address)
                if location:
                    locations.append(location)
            except ValueError:
                pass
        return locations

    @Slot(str, str, str, str, str)
    def saveMapping(self, signature, technique, title, confidence, reason):
        try:
            self.mapping_store.save(
                signature, technique, title, confidence, reason, getpass.getuser()
            )
            self.advancedChanged.emit()
        except ValueError as exc:
            self.notice.emit(str(exc))

    @Slot(QUrl)
    def loadGeoDatabase(self, url):
        if self.busy:
            return
        self.future = self.executor.submit(
            lambda: dict(kind="geo", database=GeoDatabase(url.toLocalFile()))
        )
        self.changed.emit()

    @Property(bool, notify=advancedChanged)
    def operationsAvailable(self):
        return operations.available()

    @Property(str, notify=advancedChanged)
    def operationPreview(self):
        import json

        return json.dumps(self._operation_plan, ensure_ascii=False, indent=2)

    @Property(str, notify=advancedChanged)
    def operationResult(self):
        import json

        return (
            json.dumps(self._operation_result, ensure_ascii=False, indent=2)
            if self._operation_result
            else ""
        )

    def planOperation(self, action, reason, **parameters):
        if self.busy or self.mode == "demo":
            return
        try:
            self._operation_plan = operations.prepare(action, reason, **parameters)
            self.advancedChanged.emit()
            self.operationPlanned.emit()
        except (OSError, ValueError) as exc:
            self.notice.emit(str(exc))

    @Slot(str, str, str)
    def planSensor(self, interface, network, reason):
        self.planOperation("configure", reason, interface=interface, network=network)

    @Slot(str, str)
    def planRules(self, rules, reason):
        self.planOperation("deploy_rules", reason, rules=rules)

    @Slot(str)
    def planRollback(self, reason):
        self.planOperation("rollback", reason)

    @Slot(str, str, int, str, str)
    def planFirewall(self, action, target, ttl, reason, scope):
        if action not in ("firewall_apply", "firewall_revoke", "firewall_status"):
            return
        self.planOperation(action, reason, scope=scope, target=target, ttl=ttl)

    @Slot()
    def confirmOperation(self):
        if not self._operation_plan or self.busy or self.mode == "demo":
            return
        request = dict(self._operation_plan)
        self.future = self.executor.submit(
            lambda: dict(kind="operation", result=operations.execute(request))
        )
        self.changed.emit()

    @Slot()
    def cancelOperation(self):
        self._operation_plan = {}
        self.advancedChanged.emit()

    @Slot(int)
    def configureRetention(self, days):
        import json

        if not 0 <= days <= 3650:
            return
        path = self.data_dir / "live/collector.json"
        try:
            value = json.loads(path.read_text())
            value["retention_days"] = days
            from .collector import atomic_json

            atomic_json(path, value)
            self.notice.emit(self.translate("Retención guardada"))
        except (OSError, ValueError) as exc:
            self.notice.emit(str(exc))

    @Slot()
    def inspectSelectedPacket(self):
        if self.busy or not self._pcap.get("imported_path"):
            return
        number = self._selected.get("raw_record", {}).get("pkt_num")
        if type(number) is not int or number < 1:
            return
        info = dict(self._pcap)
        self.future = self.executor.submit(
            lambda: dict(
                kind="capture",
                info=info,
                offset=number - 1,
                rows=capture.page(info["imported_path"], number - 1, 1),
            )
        )
        self.changed.emit()

    @Property(str, notify=advancedChanged)
    def technicalLog(self):
        return self._technical_log

    @Slot()
    def readTechnicalLog(self):
        if self.busy:
            return

        def job():
            import subprocess

            result = subprocess.run(
                [
                    "journalctl",
                    "--no-pager",
                    "-n",
                    "100",
                    "-o",
                    "short-iso",
                    "-u",
                    "snort-soc.service",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return dict(
                kind="logs", text=(result.stdout + "\n" + result.stderr)[-24000:]
            )

        self.future = self.executor.submit(job)
        self.changed.emit()

    @Slot(str, bool, str)
    def planFirewallPolicy(self, allowed, enabled, reason):
        self.planOperation(
            "configure_firewall", reason, allowed=allowed, enabled=enabled
        )

    @Property("QVariantMap", notify=advancedChanged)
    def packetBytes(self):
        return self._packet_bytes

    @Slot(int)
    def viewPacketBytes(self, number):
        if self.busy or not self._capture_info:
            return
        path = self._capture_info["imported_path"]
        self.future = self.executor.submit(
            lambda: dict(kind="bytes", bytes=capture.packet_bytes(path, number))
        )
        self.changed.emit()

    @Slot()
    def draftSelectedRule(self):
        import ipaddress, re, secrets

        if not self._selected.get("event_id"):
            return
        try:
            source = str(ipaddress.ip_address(self._selected["src"]))
            destination = str(ipaddress.ip_address(self._selected["dst"]))
            protocol = self._selected.get("protocol", "").lower()
            if protocol not in ("tcp", "udp", "icmp", "ip"):
                protocol = "ip"
            port = self._selected.get("dst_port")
            destination_port = (
                str(port)
                if protocol in ("tcp", "udp")
                and type(port) is int
                and 0 <= port <= 65535
                else "any"
            )
            message = re.sub(r"[^A-Za-z0-9 .,:/-]", "_", self._selected["message"])[
                :100
            ]
            sid = 1000000 + secrets.randbelow(1000000)
            text = f'alert {protocol} {source} any -> {destination} {destination_port} (msg:"JALTRIX review: {message}"; sid:{sid}; rev:1; priority:3;)'
            self.ruleDraftReady.emit(text)
        except ValueError as exc:
            self.notice.emit(str(exc))

    @Slot(QUrl)
    def backupData(self, destination):
        if self.busy:
            return
        from .backup import create_backup

        self.future = self.executor.submit(
            create_backup, self.data_dir, destination.toLocalFile()
        )
        self.changed.emit()
