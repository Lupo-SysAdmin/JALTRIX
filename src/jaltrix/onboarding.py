"""First-run discovery and remembered sessions; never installs or starts on discovery."""

from pathlib import Path
import re
import subprocess
import tempfile

from PySide6.QtCore import QObject, Property, Signal, Slot, QUrl
from PySide6.QtGui import QDesktopServices

from .engine import find_engine

GUIDES = {
    "install": "https://docs.snort.org/start/installation",
    "download": "https://www.snort.org/snort3",
    "logging": "https://docs.snort.org/start/alert_logging",
}


def probe_engine(path):
    result = dict(path=str(path or ""), state="missing", version="", detail="")
    if not path:
        return result
    try:
        # Bound both elapsed time and memory; this runs as the desktop user.
        with tempfile.TemporaryFile() as output:
            process = subprocess.run(
                [str(path), "-V"], stdout=output, stderr=subprocess.STDOUT, timeout=8
            )
            output.seek(0)
            text = output.read(16384).decode(errors="replace")
        version = re.search(r"Version\s+(\d+\.\d+(?:\.\d+)*)", text)
        result.update(version=version[1] if version else "", detail=text[-2000:])
        result["state"] = (
            "compatible"
            if process.returncode == 0
            and version
            and version[1].startswith("3.")
            and "Snort" in text
            else "incompatible"
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result.update(state="error", detail=str(exc))
    return result


def distribution():
    try:
        values = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
        return values.get("PRETTY_NAME", "Linux")
    except OSError:
        return "Linux"


class SetupController(QObject):
    setupChanged = Signal()
    setupRequested = Signal()

    def initSetup(self):
        self._show_setup = False
        self._setup_engine = dict(path="", state="checking", version="", detail="")
        self._setup_future = None
        self._setup_message = ""
        self._connected = False
        self._restore_pending = False
        self._distro = distribution()
        self.poller.timeout.connect(self.pollSetup)
        self.refreshSetup()

    @Property(bool, notify=setupChanged)
    def showSetup(self):
        return self._show_setup

    @Property("QVariantMap", notify=setupChanged)
    def setupInfo(self):
        return dict(
            self._setup_engine,
            busy=self._setup_future is not None,
            distro=self._distro,
            message=self._setup_message,
            connected=self._connected,
            profile_exists=Path("/etc/jaltrix").exists(),
        )

    @Slot()
    def refreshSetup(self):
        if self._setup_future is None:
            self._setup_future = self.service_executor.submit(
                probe_engine, find_engine()
            )
            self.setupChanged.emit()
        self.refreshService()

    def pollSetup(self):
        if self._setup_future is not None and self._setup_future.done():
            future, self._setup_future = self._setup_future, None
            self._setup_engine = future.result()
            self.setupChanged.emit()

    @Slot()
    def openSetup(self):
        self._show_setup = True
        self.refreshSetup()
        self.setupChanged.emit()
        self.setupRequested.emit()

    @Slot(str)
    def openSetupGuide(self, key):
        if key in GUIDES:
            QDesktopServices.openUrl(QUrl(GUIDES[key]))

    def rememberSession(self, mode, source=""):
        if (
            self.settings.value("startup/mode", "") == mode
            and self.settings.value("startup/source", "") == source
        ):
            return
        self.settings.setValue("startup/mode", mode)
        self.settings.setValue("startup/source", source)
        self.settings.sync()

    def restoreStartup(self):
        mode = self.settings.value("startup/mode", "")
        source = self.settings.value("startup/source", "")
        if mode == "demo":
            return
        if mode == "live" and source:
            self._restore_pending = True
            self.loadLog(QUrl.fromLocalFile(source), True)
            return
        if mode == "service":
            self.manageRealService()
        else:
            # Welcome screen has no simulated alerts behind it.
            self.changeMode("live")
            self._status = "Configuración pendiente"
        self._show_setup = True
        self.setupChanged.emit()

    @Slot()
    def chooseDemo(self):
        if self.busy:
            return
        self.useDemo()
        self._show_setup = False
        self.setupChanged.emit()

    @Slot()
    def chooseReal(self):
        if self.busy:
            return
        if self.mode != "live":
            self.manageRealService()
        elif not self._source:
            self.rememberSession("service")
        self._show_setup = True
        self.setupChanged.emit()

    @Slot(str, str, str)
    def planNewSensor(self, interface, network, rules):
        if self._setup_engine.get("state") != "compatible":
            return
        self.planOperation(
            "initialize",
            "Initial sensor setup",
            engine=self._setup_engine["path"],
            interface=interface,
            network=network,
            rules=rules,
        )

    def connectionResult(self, success):
        self._connected = success
        if success and self.mode == "live":
            self.rememberSession("live", self._source)
            self._setup_message = "Archivo conectado; recibir cero alertas no significa que el sensor esté fallando."
        elif not success:
            self._setup_message = "No se pudo leer el archivo. Revisa la ruta y los permisos; no se activará demo."
        if self._restore_pending:
            self._restore_pending = False
            if not success:
                self.openSetup()
        self.setupChanged.emit()
