import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

ApplicationWindow {
    id: win
    width: 1480; height: 920; minimumWidth: 1080; minimumHeight: 720
    visible: true; title: "JALTRIX · Jan Herrera · " + soc.mode.toUpperCase()
    color: "#090e19"
    property string page: soc.showSetup ? "Inicio" : "Dashboard"
    onPageChanged: soc.setGeoVisible(page === "Dashboard" || page === "Mapa de amenazas")
    Component.onCompleted: soc.setGeoVisible(true)
    property bool inspector: true
    property bool logsOpen: false
    property bool showLegal: false
    onShowLegalChanged: if (showLegal) legalDialog.open()
    property bool showAbout: false
    onShowAboutChanged: if (showAbout) aboutDialog.open()
    function tr(value) { const locale = soc.language; return soc.translate(String(value)); }
    property color muted: "#93a4bc"
    property color accent: "#a978ff"
    palette.window: "#111b2b"
    palette.text: "#e4eaf5"; palette.windowText: "#e4eaf5"; palette.buttonText: "#e4eaf5"
    palette.base: "#111b2b"; palette.button: "#1b2940"; palette.highlight: "#7043c3"
    font.family: "DejaVu Sans"; font.pixelSize: 13

    component Txt: Label { color: "#e4eaf5"; textFormat: Text.PlainText; elide: Text.ElideRight }
    component Panel: Rectangle { color: "#111b2b"; radius: 12; border.color: "#29374e" }
    component Btn: Button {
        id: b
        implicitHeight: 36
        background: Rectangle { radius: 6; color: b.highlighted ? "#53308b" : b.down ? "#654499" : b.hovered ? "#2d3b53" : "#1a2940"; border.color: b.activeFocus ? "#a978ff" : "#34435b" }
        contentItem: Txt { text: b.text; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter; opacity: b.enabled ? 1 : .4 }
    }
    function severityColor(value) { return value === "Crítica" ? "#ff7785" : value === "Alta" ? "#f5c76c" : value === "Media" ? "#a6bfff" : value === "Baja" ? "#5edab8" : "#93a4bc"; }
    function applyFilters() { soc.filter(search.text, ["Todas", "Crítica", "Alta", "Media", "Baja"][severity.currentIndex], soc.categorySelection, interval.currentIndex === 0 ? 15 : interval.currentIndex === 1 ? 60 : 1440) }
    FileDialog { id: backupDialog; title: win.tr("Guardar copia de seguridad"); fileMode: FileDialog.SaveFile; nameFilters: ["ZIP (*.zip)"]; defaultSuffix: "zip"; onAccepted: soc.backupData(selectedFile) }
    FileDialog { id: exportDialog; title: win.tr("Exportar alertas"); fileMode: FileDialog.SaveFile; nameFilters: ["JSON (*.json)"]; defaultSuffix: "json"; onAccepted: soc.export(selectedFile) }
    FileDialog { id: engineDialog; title: win.tr("Seleccionar ejecutable Snort"); fileMode: FileDialog.OpenFile; onAccepted: soc.setEnginePath(selectedFile) }
    FileDialog { id: geoDialog; title: win.tr("Base GeoIP local"); fileMode: FileDialog.OpenFile; nameFilters: ["CSV (*.csv)"]; onAccepted: soc.loadGeoDatabase(selectedFile) }
    FileDialog { id: inspectCaptureDialog; title: win.tr("Explorar captura"); fileMode: FileDialog.OpenFile; nameFilters: ["PCAP / PCAPNG (*.pcap *.pcapng *.cap)"]; onAccepted: soc.inspectCapture(selectedFile) }
    FileDialog { id: pcapDialog; title: win.tr("Seleccionar PCAP para reproducción offline"); fileMode: FileDialog.OpenFile; nameFilters: ["PCAP / PCAPNG (*.pcap *.cap *.pcapng)"]; onAccepted: soc.replayPcap(selectedFile) }
    FileDialog { id: rulesDialog; title: win.tr("Seleccionar reglas locales"); fileMode: FileDialog.OpenFile; nameFilters: ["Snort rules (*.rules)"]; onAccepted: soc.setRulesPath(selectedFile) }
    property bool followFile: false
    FileDialog { id: logDialog; title: win.tr("Seleccionar alertas JSON de Snort"); fileMode: FileDialog.OpenFile; nameFilters: ["Snort JSON (*.txt *.json *.jsonl)", "All files (*)"]; onAccepted: soc.loadLog(selectedFile, win.followFile) }
    FileDialog { id: csvDialog; title: win.tr("Exportar CSV"); fileMode: FileDialog.SaveFile; nameFilters: ["CSV (*.csv)"]; defaultSuffix: "csv"; onAccepted: soc.export(selectedFile) }
    Shortcut { sequence: "Ctrl+K"; onActivated: search.forceActiveFocus() }
    Shortcut { sequence: "Ctrl+Q"; context: Qt.ApplicationShortcut; onActivated: win.close() }
    Connections { target: soc; function onSetupRequested() { win.page="Inicio"; } }
    Connections { target: soc; function onGeoAlertOpened() { win.inspector=true; win.page="Alertas"; } }
    Connections { target: soc; function onCaseOpened() { caseNotes.text = soc.caseDetail.notes; caseStatus.currentIndex = ["new", "investigating", "resolved", "closed"].indexOf(soc.caseDetail.status); caseDialog.open(); } function onNotice(message) { toast.text = message; toast.visible = true; toastTimer.restart() } }
    Timer { interval: 5000; repeat: true; running: (win.page === "Servicio" || win.page === "Inicio") || soc.mode !== "demo"; onTriggered: soc.refreshService() }
    Timer { id: toastTimer; interval: 5000; onTriggered: toast.visible = false }


    Connections { target: soc; function onRuleDraftReady(text) { ruleEditor.text=text; win.page="Reglas"; } }
    Connections { target: soc; function onOperationPlanned() { operationDialog.open() } }
    Dialog {
        id: operationDialog; title: win.tr("Confirmar operación administrada"); modal: true; anchors.centerIn: parent
        width: Math.min(900,win.width-60); height: Math.min(700,win.height-60); background: Panel { }
        contentItem: ColumnLayout {
            Txt { text: win.tr("Revisa destino, cambios y justificación. El sistema solicitará autorización y verificará el resultado."); Layout.fillWidth: true; wrapMode: Text.WordWrap }
            ScrollView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                TextArea { text: soc.operationPreview; readOnly: true; wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText; color: "#e4eaf5" }
            }
            RowLayout {
                Btn { highlighted:true; text: win.tr("Confirmar y autorizar"); onClicked: { operationDialog.close(); soc.confirmOperation(); } }
                Btn { text: win.tr("Cancelar"); onClicked: { soc.cancelOperation(); operationDialog.close(); } }
            }
        }
        onRejected: soc.cancelOperation()
    }
    Dialog {
        id: retentionDialog; title: win.tr("Retención de alertas LIVE"); modal: true; anchors.centerIn: parent; width: 600; background: Panel { }
        contentItem: ColumnLayout { spacing: 14
            Txt { text: win.tr("El recolector eliminará alertas antiguas según su fecha de ingesta. Conserva las vinculadas a casos. 0 desactiva la limpieza. No elimina PCAP ni cuarentena."); Layout.fillWidth: true; wrapMode: Text.WordWrap }
            SpinBox { id: retentionDays; from: 0; to: 3650; value: 0; editable: true }
            RowLayout {
                Btn { text: win.tr("Confirmar retención en días"); onClicked: { soc.configureRetention(retentionDays.value); retentionDialog.close(); } }
                Btn { text: win.tr("Cancelar"); onClicked: retentionDialog.close() }
            }
        }
    }
    Dialog {
        id: triageDialog; title: win.tr("Investigar alerta"); modal: true; anchors.centerIn: parent; width: Math.min(680,win.width-80); height: 520; background: Panel { }
        property int revision: 0
        onOpened: { revision=soc.selectedTriage.revision; triageNotes.text=soc.selectedTriage.notes; triageTags.text=soc.selectedTriage.tags.join(", "); triageBookmark.checked=soc.selectedTriage.bookmark; triageState.currentIndex=["new","investigating","resolved","false_positive"].indexOf(soc.selectedTriage.state); }
        contentItem: ColumnLayout {
            Txt { text: soc.selected.sid+" · "+soc.selected.message; Layout.fillWidth: true; elide: Text.ElideRight }
            ComboBox { id: triageState; model: ["new","investigating","resolved","false_positive"]; displayText: win.tr(currentText) }
            TextField { id: triageTags; placeholderText: win.tr("Etiquetas separadas por coma"); Layout.fillWidth: true }
            CheckBox { id: triageBookmark; text: win.tr("Marcar alerta") }
            ScrollView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                TextArea { id: triageNotes; wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText; color: "#e4eaf5"; placeholderText: win.tr("Notas de investigación") }
            }
            RowLayout {
                Btn { text: win.tr("Guardar"); onClicked: { soc.saveTriage(triageDialog.revision,triageState.currentText,triageNotes.text,triageTags.text,triageBookmark.checked); triageDialog.close(); } }
                Btn { text: win.tr("Cerrar"); onClicked: triageDialog.close() }
            }
        }
    }
    Dialog {
        id: caseDialog; anchors.centerIn: parent; width: Math.min(680, win.width-80); height: 500; modal: true
        title: soc.caseDetail.id || ""; background: Panel { }
        contentItem: ColumnLayout {
            Txt { text: soc.caseDetail.title || ""; Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 18 }
            ComboBox { id: caseStatus; model: ["new", "investigating", "resolved", "closed"]; displayText: win.tr(currentText); delegate: ItemDelegate { required property string modelData; text: win.tr(modelData) } }
            ScrollView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                TextArea { id: caseNotes; placeholderText: win.tr("Notas de investigación"); wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText; selectByMouse: true; color: "#e4eaf5" }
            }
            RowLayout { Btn { text: win.tr("Guardar"); onClicked: { soc.saveCase(caseNotes.text, caseStatus.currentText); caseDialog.close(); } } Btn { text: win.tr("Cerrar"); onClicked: caseDialog.close() } }
        }
    }
    Dialog {
        id: aboutDialog; objectName: "about-dialog"; anchors.centerIn: parent; width: Math.min(600, win.width - 80); modal: true
        title: win.tr("Acerca de"); padding: 24
        background: Panel { }
        contentItem: ColumnLayout {
            spacing: 18
            RowLayout {
                spacing: 14
                Image { source: soc.logoAsset; Layout.preferredWidth: 140; Layout.preferredHeight: 140; fillMode: Image.PreserveAspectFit; onStatusChanged: if (status === Image.Error) source = "app-logo.png" }
                Txt { text: "JALTRIX · " + soc.version; font.pixelSize: 24; font.bold: true }
            }
            Txt { text: win.tr("Desarrollador") + ": Jan Herrera"; font.pixelSize: 18; color: win.accent }
            Txt { text: "Copyright © 2026 Jan Herrera · GPL-3.0-or-later" }
            Txt { text: win.tr("Aplicación independiente para Snort 3. Snort, Qt y PySide6 conservan sus autores y licencias."); Layout.fillWidth: true; wrapMode: Text.WordWrap }
            Txt { text: win.tr("Sin garantía. Consulta el texto completo de la licencia."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
            RowLayout {
                Btn { objectName: "github-button"; text: win.tr("Abrir mi GitHub"); onClicked: soc.openGithub() }
                Btn { objectName: "license-button"; text: win.tr("Licencia del proyecto"); onClicked: licenseDialog.open() }
            }
            Btn { objectName: "legal-button"; text: win.tr("Información legal y componentes"); onClicked: legalDialog.open() }
            Btn { text: win.tr("Cerrar"); onClicked: aboutDialog.close() }
        }
    }
    Dialog {
        id: sensorConfigDialog; title: win.tr("Perfil de captura administrado"); modal: true; anchors.centerIn: parent; width: Math.min(650,win.width-80); background: Panel { }
        contentItem: ColumnLayout { spacing: 12
            Txt { text: win.tr("Solo modifica /etc/jaltrix. Reinicia el sensor si está activo. Valida antes de aplicar y restaura ante fallos."); Layout.fillWidth: true; wrapMode: Text.WordWrap }
            ComboBox { id: sensorInterface; model: soc.interfaces }
            TextField { id: homeNetwork; placeholderText: "HOME_NET: 192.168.1.0/24,2001:db8::/32"; Layout.fillWidth: true }
            TextField { id: sensorReason; placeholderText: win.tr("Justificación"); Layout.fillWidth: true }
            Btn { text: win.tr("Previsualizar configuración"); enabled: !soc.busy; onClicked: { sensorConfigDialog.close(); soc.planSensor(sensorInterface.currentText,homeNetwork.text,sensorReason.text); } }
            Btn { text: win.tr("Cerrar"); onClicked: sensorConfigDialog.close() }
        }
    }
    Dialog {
        id: licenseDialog; objectName: "license-dialog"; anchors.centerIn: parent; width: Math.min(820, win.width - 80); height: Math.min(650, win.height - 80); modal: true
        title: "GPL-3.0-or-later · Jan Herrera"; background: Panel { }
        contentItem: ColumnLayout {
            ScrollView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                TextArea { text: soc.licenseText; readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText; font.pixelSize: 12; color: "#e4eaf5" }
            }
            Btn { text: win.tr("Cerrar"); onClicked: licenseDialog.close() }
        }
    }

    Dialog {
        id: legalDialog; objectName: "legal-dialog"; anchors.centerIn: parent
        width: Math.min(920, win.width - 60); height: Math.min(760, win.height - 60)
        modal: true; title: win.tr("Información legal y componentes"); background: Panel { }
        contentItem: ColumnLayout {
            TabBar {
                id: legalTabs; Layout.fillWidth: true
                TabButton { text: win.tr("Información legal") }
                TabButton { text: win.tr("Componentes y licencias") }
            }
            ScrollView { visible: legalTabs.currentIndex === 0; Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                TextArea { objectName: "legal-information"; text: soc.legalInformation; readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText; color: "#e4eaf5"; font.pixelSize: 13 }
            }
            ColumnLayout { visible: legalTabs.currentIndex === 1; Layout.fillWidth: true; Layout.fillHeight: true
                ComboBox { id: componentChoice; objectName: "legal-component"; Layout.fillWidth: true; model: soc.legalComponents; textRole: "name" }
                ScrollView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                    TextArea { objectName: "component-license"; text: soc.componentLicense(componentChoice.currentIndex); readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText; color: "#e4eaf5"; font.pixelSize: 12 }
                }
                Btn { text: win.tr("Abrir fuente del componente"); onClicked: soc.openComponentSource(componentChoice.currentIndex) }
            }
            Btn { text: win.tr("Cerrar"); onClicked: legalDialog.close() }
        }
    }

    ColumnLayout {
        anchors.fill: parent; spacing: 0
        Rectangle {
            Layout.fillWidth: true; Layout.preferredHeight: 76; color: "#0d1422"
            RowLayout {
                anchors.fill: parent; anchors.margins: 20; spacing: 14
                Image { Layout.preferredWidth: 42; Layout.preferredHeight: 42; source: "app-icon.png"; sourceSize.width: 84; sourceSize.height: 84 }
                ColumnLayout { spacing: 3; Txt { text: win.tr("JALTRIX"); font.pixelSize: 19; font.bold: true } Txt { text: win.tr("Jan Herrera  /  Consola para Snort 3"); color: win.muted; font.pixelSize: 11 } }
                Item { Layout.fillWidth: true }
                TextField { id: search; objectName: "search"; Layout.preferredWidth: Math.min(340, win.width * .20); placeholderText: win.tr("Buscar IP, firma, SID…   Ctrl+K"); selectByMouse: true; onTextChanged: win.applyFilters(); Accessible.name: win.tr("Buscar alertas") }
                Btn { objectName: "language-es"; text: "ES"; implicitWidth: 38; highlighted: soc.language === "es-419"; onClicked: soc.setLanguage("es-419"); ToolTip.visible: hovered; ToolTip.text: "Español latinoamericano" }
                Btn { objectName: "language-en"; text: "EN"; implicitWidth: 38; highlighted: soc.language === "en-US"; onClicked: soc.setLanguage("en-US"); ToolTip.visible: hovered; ToolTip.text: "American English" }
                Btn { objectName: "about-button"; text: win.tr("Acerca de"); onClicked: aboutDialog.open() }
            }
        }
        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 30; color: "#302448"; Txt { anchors.centerIn: parent; text: win.tr(soc.mode === "demo" ? "DATOS DE DEMOSTRACIÓN  ·  Fixture del 09 nov 2026, UTC  ·  Sin captura ni cambios de red" : soc.mode === "live" && !soc.sourcePath ? "CONFIGURACIÓN DEL SENSOR · Conecta un archivo para ver alertas reales" : soc.mode === "live" ? "LECTURA DE ARCHIVO  ·  Sin captura propia  ·  Salud del sensor no verificada" : "REPRODUCCIÓN / IMPORTACIÓN  ·  Alertas reales del archivo seleccionado"); color: "#d7bdff"; font.pixelSize: 12 } }
        RowLayout {
            Layout.fillWidth: true; Layout.fillHeight: true; spacing: 0
            Rectangle {
                Layout.preferredWidth: 194; Layout.fillHeight: true; color: "#0d1422"
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: 12; spacing: 5
                    Image { objectName: "main-brand-logo"; source: soc.logoAsset; Layout.fillWidth: true; Layout.preferredHeight: win.height < 830 ? 100 : 156; fillMode: Image.PreserveAspectFit; Accessible.name: "JALTRIX"; onStatusChanged: if (status === Image.Error) source = "app-logo.png" }
                    Repeater {
                        model: ["Dashboard", "Alertas", "Investigación / Casos", "Tráfico", "PCAP", "Reglas", "Mapa de amenazas", "Topología", "Correlación MITRE", "Respuesta / Firewall", "EDR / Endpoints", "Reportes", "Servicio", "Configuración"]
                        delegate: Button {
                            required property string modelData
                            property bool ready: ["Dashboard", "Alertas", "Investigación / Casos", "Tráfico", "Mapa de amenazas", "Topología", "Correlación MITRE", "PCAP", "Reglas", "Respuesta / Firewall", "EDR / Endpoints", "Reportes", "Servicio", "Configuración"].indexOf(modelData) >= 0
                            Layout.fillWidth: true; implicitHeight: win.height < 830 ? 24 : 31; enabled: ready
                            text: win.tr(modelData); objectName: "nav-" + modelData; hoverEnabled: true
                            background: Rectangle { radius: 7; color: win.page === modelData ? "#53308b" : parent.hovered ? "#1c2940" : "transparent" }
                            contentItem: Txt { text: parent.text; leftPadding: 10; verticalAlignment: Text.AlignVCenter; opacity: parent.enabled ? 1 : .35; font.pixelSize: 12 }
                            ToolTip.visible: hovered; ToolTip.text: ready ? win.tr(modelData) : win.tr("Pendiente de implementación; no disponible en este hito")
                            onClicked: { win.page = modelData; if (modelData === "Servicio") soc.refreshService(); }
                        }
                    }
                    Item { Layout.fillHeight: true }
                    Panel { Layout.fillWidth: true; implicitHeight: 78; ColumnLayout { anchors.fill: parent; anchors.margins: 12; Txt { text: soc.mode === "demo" ? win.tr("●  MODO DEMO") : "●  " + soc.mode.toUpperCase(); color: "#c29aff" } Txt { text: soc.mode === "demo" ? win.tr("Datos simulados") : win.tr(soc.service.active); color: win.muted; font.pixelSize: 11 } Txt { text: soc.mode === "demo" ? win.tr("Sin alertas reales") : win.tr("Servicio del sensor"); color: win.muted; font.pixelSize: 11 } } }
                }
            }
            ColumnLayout {
                Layout.fillWidth: true; Layout.fillHeight: true; Layout.margins: 18; spacing: 14
                RowLayout { Layout.fillWidth: true; Txt { text: win.tr(win.page); font.pixelSize: 24; font.bold: true } Item { Layout.fillWidth: true } Txt { text: "LOCAL  /  " + soc.mode.toUpperCase(); color: win.muted; font.pixelSize: 11 } }
                Panel {
                    Layout.fillWidth: true; implicitHeight: statusFlow.implicitHeight+16
                    Flow {
                        id: statusFlow; anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: 8; spacing: 8
                        Repeater {
                            model: [
                                {label:"Sensor local", value:soc.mode === "demo" ? "DEMO" : win.tr(soc.service.active), tint:soc.mode !== "demo" && soc.service.active === "active" ? "#46d99b" : "#a69abf", tip:"Estado del servicio local; no confirma captura de paquetes."},
                                {label:"Modo", value:soc.mode.toUpperCase(), tint:"#c29aff", tip:"DEMO, lectura LIVE o importación REPLAY."},
                                {label:"Interfaz configurada", value:soc.mode === "demo" ? "—" : soc.configuredInterface, tint:"#35d5df", tip:"Interfaz del perfil local; no es una confirmación de captura."},
                                {label:"Recolector", value:soc.mode === "demo" ? "—" : win.tr(soc.collector.fresh ? soc.collector.state : "unavailable"), tint:soc.mode !== "demo" && soc.collector.fresh ? "#46d99b" : "#93a4bc", tip:"Recolector independiente del usuario; no es el motor de captura."},
                                {label:"Última alerta UTC", value:soc.lastSourceAlert ? soc.lastSourceAlert.slice(11,19) : "—", tint:"#b8c4d7", tip:soc.lastSourceAlert || "Sin tiempo de alerta disponible para esta fuente."}
                            ]
                            delegate: Rectangle {
                                required property var modelData
                                width: statusText.implicitWidth+24; height: 26; radius: 5; color:"#172235"
                                Rectangle { x:8; anchors.verticalCenter: parent.verticalCenter; width:5; height:5; radius:3; color:modelData.tint }
                                Txt { id:statusText; x:18; anchors.verticalCenter: parent.verticalCenter; text:win.tr(modelData.label)+": "+modelData.value; color:modelData.tint; font.pixelSize:11 }
                                HoverHandler { id:statusHover }
                                ToolTip.visible: statusHover.hovered; ToolTip.text:win.tr(modelData.tip)
                            }
                        }
                    }
                }
                SetupView {
                    controller:soc; visible:win.page==="Inicio"; Layout.fillWidth:true; Layout.fillHeight:true
                    onEngineRequested:engineDialog.open()
                    onLogRequested: { win.followFile=true; logDialog.open(); }
                    onProfileRequested:sensorConfigDialog.open()
                    onRulesRequested:win.page="Reglas"
                    onDashboardRequested:win.page="Dashboard"
                }
                ColumnLayout {
                    visible: win.page === "Dashboard" || win.page === "Alertas"
                    Layout.fillWidth: true; Layout.fillHeight: true; spacing: 14
                    RowLayout {
                        Layout.fillWidth: true; spacing: 12
                        Repeater {
                            model: [{label:"Alertas filtradas", value:soc.summary.total, tint:"#b78aff"}, {label: soc.mode === "demo" ? "Críticas · demo" : "Críticas", value:soc.summary.critical, tint:"#ff6c79"}, {label: soc.mode === "demo" ? "Casos demo guardados" : "Casos guardados", value:soc.cases.length, tint:"#f5c76c"}, {label:"Fuentes en la consulta", value:soc.summary.sources, tint:"#35d5df"}]
                            delegate: Panel {
                                required property var modelData
                                Layout.fillWidth: true; implicitHeight: 88
                                Rectangle { width: 3; height: 42; radius: 2; x: 14; y: 23; color: modelData.tint }
                                ColumnLayout { anchors.fill: parent; anchors.margins: 16; anchors.leftMargin: 29; spacing: 3; Txt { text: win.tr(modelData.label); color: win.muted; font.pixelSize: 11 } Txt { text: modelData.value; font.pixelSize: 28; font.bold: true; color: modelData.tint } }
                            }
                        }
                    }
                    RowLayout { Layout.fillWidth:true; spacing:8
                    Flickable {
                        id: categoryFlick
                        Layout.fillWidth: true; Layout.preferredHeight: 40; clip:true
                        contentWidth: categoryRow.implicitWidth; contentHeight: height; boundsBehavior:Flickable.StopAtBounds
                        Row {
                            id: categoryRow; spacing:7
                            Repeater { model:soc.categoryTabs
                                delegate: Btn {
                                    id: categoryButton
                                    required property var modelData
                                    objectName:"category-"+modelData.label
                                    text:win.tr(modelData.label)+" ("+modelData.count+")"
                                    highlighted:soc.categorySelection === modelData.label
                                    implicitWidth:Math.min(240,Math.max(80,contentItem.implicitWidth+22))
                                    implicitHeight:32
                                    Accessible.name:text
                                    onActiveFocusChanged: if (activeFocus) { if (x < categoryFlick.contentX) categoryFlick.contentX=x; else if (x+width > categoryFlick.contentX+categoryFlick.width) categoryFlick.contentX=x+width-categoryFlick.width; }
                                    ToolTip {
                                        id:categoryTip; visible:categoryButton.hovered; width:300
                                        text:win.tr(modelData.label)+" · "+win.tr(soc.mode === "demo" ? "Categorías de demostración" : "Clasificación original de Snort")
                                        background:Rectangle {color:"#1b2940"; border.color:"#607089"; radius:5}
                                        contentItem:Text {text:categoryTip.text; textFormat:Text.PlainText; color:"#e4eaf5"; wrapMode:Text.WordWrap; font.pixelSize:11}
                                    }
                                    onClicked:soc.selectCategory(modelData.label)
                                }
                            }
                        }
                        ScrollBar.horizontal: ScrollBar { policy:ScrollBar.AsNeeded }
                    }
                        ComboBox { id: severity; implicitWidth:180; displayText: win.tr("Severidad")+": "+win.tr(currentText); delegate: ItemDelegate { required property string modelData; width: parent.width; text: win.tr(modelData) } model: ["Todas", "Crítica", "Alta", "Media", "Baja"]; onActivated: win.applyFilters(); Accessible.name: win.tr("Severidad") }
                        ComboBox { id: interval; displayText: win.tr(currentText); delegate: ItemDelegate { required property string modelData; width: parent.width; text: win.tr(modelData) } model: ["15 minutos", "1 hora", "24 horas"]; currentIndex: 2; onActivated: win.applyFilters(); Accessible.name: win.tr("Intervalo de la demostración") }
                        Btn { text: win.inspector ? win.tr("Ocultar inspector") : win.tr("Ver inspector"); onClicked: win.inspector = !win.inspector }
                    }
                    RowLayout {
                        visible: soc.mode !== "demo"; Layout.fillWidth: true
                        Btn { text: win.tr("Anterior"); enabled: !soc.busy && soc.pagination.offset > 0; onClicked: soc.changePage(-1) }
                        Txt { text: soc.pagination.offset + " — " + soc.pagination.next + " / " + soc.pagination.matched + " · " + win.tr("Tabla paginada; mapa y exportación: consulta completa"); Layout.fillWidth: true; color: win.muted; font.pixelSize: 11 }
                        Btn { text: win.tr("Siguiente"); enabled: !soc.busy && soc.pagination.next < soc.pagination.matched; onClicked: soc.changePage(1) }
                    }
                    RowLayout {
                        Layout.fillWidth: true; Layout.fillHeight: true; Layout.minimumHeight: 260; spacing: 12
                        ColumnLayout { Layout.fillWidth:true; Layout.fillHeight:true; spacing:14
                        Panel {
                            Layout.fillWidth: true; Layout.fillHeight: true
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 12; spacing: 8
                                Txt { text: win.tr("ALERTAS DE DETECCIÓN  ·  ") + soc.summary.total; font.bold: true; font.pixelSize: 12 }
                                RowLayout { Layout.fillWidth: true; spacing: 12; Txt { text: win.tr("HORA UTC"); Layout.preferredWidth: 65; color: win.muted; font.pixelSize: 10 } Txt { text: win.tr("SEVERIDAD"); Layout.preferredWidth: 78; color: win.muted; font.pixelSize: 10 } Txt { text: win.tr("FIRMA / ORIGEN → DESTINO"); Layout.fillWidth: true; color: win.muted; font.pixelSize: 10 } }
                                ListView {
                                    id: alerts; objectName: "alerts"; Layout.fillWidth: true; Layout.fillHeight: true; clip: true; model: eventModel; spacing: 3; reuseItems: true
                                    ScrollBar.vertical: ScrollBar {}
                                    delegate: ItemDelegate {
                                        required property var event
                                        required property int index
                                        width: ListView.view.width; height: 45
                                        Accessible.name: event.time + win.tr(" ") + event.severity + win.tr(" ") + event.message
                                        background: Rectangle { radius: 6; color: soc.selected.event_id === event.event_id ? "#322449" : index % 2 ? "#142035" : "#111b2b"; border.color: soc.selected.event_id === event.event_id ? "#9f6de4" : "transparent" }
                                        contentItem: RowLayout {
                                            spacing: 12
                                            Txt { text: event.time; font.pixelSize: 11; Layout.preferredWidth: 65 }
                                            Rectangle { Layout.preferredWidth:78; Layout.preferredHeight:22; radius:4; color:"#172133"; border.color:win.severityColor(event.severity)
                                                Txt { anchors.fill:parent; anchors.margins:3; text:win.tr(event.severity); color:win.severityColor(event.severity); font.pixelSize:10; horizontalAlignment:Text.AlignHCenter; verticalAlignment:Text.AlignVCenter }
                                            }
                                            ColumnLayout { Layout.fillWidth: true; spacing: 4; Txt { text: event.mode === "demo" ? win.tr(event.message) : event.message; Layout.fillWidth: true; font.pixelSize: 12 } Txt { text: event.src + win.tr(" → ") + event.dst + win.tr("   ·   ") + event.sid; Layout.fillWidth: true; color: win.muted; font.pixelSize: 10 } }
                                        }
                                        onClicked: soc.select(index)
                                    }
                                    Txt { anchors.centerIn: parent; visible: alerts.count === 0; text: win.tr("No hay alertas con estos filtros"); color: win.muted }
                                }
                                Txt { text: win.tr(soc.mode === "demo" ? "Selección conservada al filtrar · Datos sintéticos · UTC" : "Selección conservada al filtrar · UTC cuando está disponible"); color: win.muted; font.pixelSize: 10 }
                            }
                        }
                    RowLayout {
                        visible: win.page === "Dashboard" && win.height >= 830
                        Layout.fillWidth: true; Layout.preferredHeight: 154; Layout.maximumHeight: 154; Layout.minimumHeight: 154; spacing: 12
                        Panel {
                            Layout.fillWidth: true; Layout.fillHeight: true
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 14
                                Txt { text: win.tr("Alertas por intervalo · página actual"); font.pixelSize: 12 }
                                Row {
                                    Layout.fillWidth: true; Layout.fillHeight: true; spacing: 2
                                    Repeater { model: soc.summary.series; delegate: Item { required property var modelData; width: Math.min(32, Math.max(2, (parent.width - 2*soc.summary.series.length) / Math.max(1,soc.summary.series.length))); height: parent.height; Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: Math.max(1, modelData.count / Math.max(1, soc.summary.peak) * (parent.height-6)); color: "#9d6ae8"; radius: 2 } HoverHandler { id: barHover } ToolTip.visible: barHover.hovered; ToolTip.text: modelData.minute + " UTC: " + modelData.count } }
                                }
                                Txt { text: win.tr("Intervalos de ") + soc.summary.bin_minutes + win.tr(" min · tráfico no medido"); color: win.muted; font.pixelSize: 10 }
                            }
                        }
                        Panel { Layout.preferredWidth: 220; Layout.fillHeight: true; ColumnLayout { anchors.fill: parent; anchors.margins: 14; spacing: 5; Txt { text: win.tr(soc.mode === "demo" ? "Fuentes más frecuentes · demo" : "Fuentes más frecuentes"); font.pixelSize: 12 } Repeater { model: soc.summary.top; delegate: RowLayout { required property var modelData; Layout.fillWidth: true; Txt { text: modelData.ip; color: win.muted; font.pixelSize: 11 } Item { Layout.fillWidth: true } Txt { text: modelData.count + win.tr(" alertas"); color: "#35d5df"; font.pixelSize: 11 } } } } }
                        Panel {
                            Layout.preferredWidth: Math.min(350,(win.width-270)*0.35); Layout.fillHeight:true
                            ColumnLayout {
                                anchors.fill:parent; anchors.margins:10; spacing:5
                                RowLayout { Layout.fillWidth:true; Txt { text:win.tr("Mapa de amenazas"); Layout.fillWidth:true; font.pixelSize:12 } Btn { text:win.tr("Explorar"); implicitHeight:26; onClicked:win.page="Mapa de amenazas" } }
                                WorldMap { controller:soc; compact:true; Layout.fillWidth:true; Layout.fillHeight:true; onMarkerSelected:key => { win.page="Mapa de amenazas"; soc.selectGeoMarker(key); } }
                                Txt { text:win.tr(soc.mode === "demo" ? "DEMO · Ubicaciones simuladas" : "IP públicas · GeoIP local"); color:win.muted; font.pixelSize:10 }
                            }
                        }
                    }
                        }
                        Panel {
                            visible: win.inspector; Layout.preferredWidth: win.width < 1250 ? 290 : 330; Layout.fillHeight: true
                            ScrollView {
                                anchors.fill: parent; anchors.margins: 16; contentWidth: availableWidth; clip: true
                                ColumnLayout {
                                    width: parent.width; spacing: 12
                                    Txt { text: win.tr("INSPECTOR DEL EVENTO"); font.bold: true; color: win.accent; font.pixelSize: 12 }
                                    Txt { text: soc.selected.mode === "demo" ? win.tr(soc.selected.message) : soc.selected.message; Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 17; font.bold: true }
                                    Txt { text: win.tr(soc.selected.severity) + " · " + (soc.mode === "demo" ? win.tr("  ·  Acción simulada") : soc.selected.action); color:win.severityColor(soc.selected.severity) }
                                    Btn { text: win.tr(soc.mode === "demo" ? "Abrir / crear caso demo" : "Abrir / crear caso"); enabled: !!soc.selected.event_id; objectName: "create-case"; highlighted:true; Layout.fillWidth: true; onClicked: soc.createCase() }
                                    Rectangle { Layout.fillWidth: true; height: 1; color: "#304057" }
                                    Repeater { model: ["Firma|" + soc.selected.sid, "Origen|" + soc.selected.src, "Destino|" + soc.selected.dst, "Protocolo|" + soc.selected.protocol, "Fecha UTC|" + (soc.selected.timestamp || "—"), "Estado|" + soc.selectedTriage.state, "Procedencia|" + (soc.mode === "demo" ? "Fixture determinista v1" : soc.selected.source), "Prioridad Snort|" + (soc.selected.priority === undefined ? "—" : soc.selected.priority), "Tiempo original|" + (soc.selected.original_timestamp || "—"), "Confianza temporal|" + (soc.selected.timestamp_confidence || "demo")]
                                        delegate: ColumnLayout { required property string modelData; Layout.fillWidth: true; spacing: 2; Txt { text: win.tr(modelData.split('|')[0]); color: win.muted; font.pixelSize: 10 } Txt { text: win.tr(modelData.split('|')[1]); Layout.fillWidth: true; font.pixelSize: 12 } }
                                    }
                                    Txt { text: win.tr("EVIDENCIA"); color: win.muted; font.pixelSize: 10 }
                                    Txt { text: soc.pcapInfo.sha256 ? "PCAP SHA-256: " + soc.pcapInfo.sha256 : win.tr("Sin PCAP ni payload asociado.\nMITRE ATT&CK: sin mapeo."); Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 12 }
                                    Txt { text: win.tr(soc.selectedTriage.state); color: win.accent }
                                    Txt { text: soc.selected.triage_exception ? win.tr("Excepción de triage: ")+soc.selected.triage_exception : ""; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                                    Btn { text: win.tr("Investigar alerta"); enabled: !!soc.selected.event_id; Layout.fillWidth: true; onClicked: triageDialog.open() }
                                    Flow { Layout.fillWidth: true; spacing: 6
                                        Btn { text: "PCAP"; onClicked: win.page = "PCAP" }
                                        Btn { text: win.tr("Paquete asociado"); enabled: !!soc.pcapInfo.imported_path && !!soc.selected.raw_record && !!soc.selected.raw_record.pkt_num; onClicked: { soc.inspectSelectedPacket(); win.page="PCAP"; } }
                                        Btn { text: win.tr("Crear regla"); onClicked: soc.draftSelectedRule() }
                                        Btn { text: "Allowlist / Blocklist"; onClicked: win.page = "Respuesta / Firewall" }
                                        Btn { objectName: "send-firewall"; text: win.tr("Enviar a firewall"); enabled: soc.mode !== "demo" && !!soc.selected.event_id && soc.operationsAvailable; onClicked: { responseTarget.text=soc.selected.src; win.page="Respuesta / Firewall"; } }
                                        Btn { text: win.tr("Aislar host"); enabled: soc.edrCapabilities.isolate.available }
                                    }
                                }
                            }
                        }
                    }
                }
                GeoView { visible:win.page === "Mapa de amenazas"; controller:soc; Layout.fillWidth:true; Layout.fillHeight:true; onImportRequested:geoDialog.open() }
                Panel {
                    visible: win.page === "Investigación / Casos"; Layout.fillWidth: true; Layout.fillHeight: true
                    ColumnLayout { anchors.fill: parent; anchors.margins: 24; spacing: 16; Txt { text: win.tr(soc.mode === "demo" ? "Casos locales de demostración" : "Casos locales"); font.pixelSize: 20 } Txt { text: win.tr("Persisten al cerrar la aplicación. Abre o crea un caso desde el inspector."); color: win.muted; Layout.fillWidth: true; wrapMode: Text.WordWrap } ListView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; model: soc.cases; spacing: 10; delegate: Panel { required property var modelData; width: ListView.view.width; height: 80; MouseArea { anchors.fill: parent; onClicked: soc.openCase(modelData.id); cursorShape: Qt.PointingHandCursor } ColumnLayout { anchors.fill: parent; anchors.margins: 14; Txt { text: modelData.id + win.tr(" · ") + modelData.title } Txt { text: modelData.event_id + win.tr(" · ") + modelData.created_at; color: win.muted; font.pixelSize: 11 } } } Txt { visible: soc.cases.length === 0; anchors.centerIn: parent; text: win.tr(soc.mode === "demo" ? "Todavía no hay casos demo" : "Todavía no hay casos"); color: win.muted } } }
                }
                Panel {
                    visible: win.page === "PCAP"; Layout.fillWidth: true; Layout.fillHeight: true
                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: 24; spacing: 16
                        Txt { text: win.tr("Reproducción offline con Snort 3"); font.pixelSize: 22 }
                        Txt { text: win.tr("Se valida la configuración y se procesa una copia del PCAP. No se captura tráfico ni se modifica el servicio del sistema."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        Txt { text: win.tr("Reglas: ") + (soc.rulesPath || "—"); Layout.fillWidth: true; wrapMode: Text.WrapAnywhere }
                        RowLayout {
                            enabled: !soc.busy
                            Btn { text: win.tr("Seleccionar reglas…"); onClicked: rulesDialog.open() }
                            Btn { text: win.tr("Explorar captura"); onClicked: inspectCaptureDialog.open() }
                            Btn { text: win.tr("Procesar PCAP…"); enabled: !!soc.rulesPath; onClicked: pcapDialog.open() }
                        }
                        Txt { text: win.tr(soc.ingestionStatus); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.accent }
                        Txt { text: soc.pcapInfo.sha256 ? "SHA-256: " + soc.pcapInfo.sha256 + "\n" + win.tr("Paquetes: ") + soc.pcapInfo.packets + "\n" + soc.pcapInfo.path : win.tr("Sin PCAP importado"); Layout.fillWidth: true; wrapMode: Text.WrapAnywhere }
                        Txt { text: win.tr("PCAP/PCAPNG hasta 1 GiB. Replay sin verificación de checksum. PCAPNG con timestamps y un único tipo de enlace."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        RowLayout {
                            Btn { text: win.tr("Ver alertas"); onClicked: win.page = "Alertas" }
                            Btn { text: win.tr("Abrir copia en aplicación externa"); enabled: !!soc.captureInfo.imported_path; onClicked: soc.openCapture() }
                        }
                        Txt { text: soc.captureInfo.sha256 ? soc.captureInfo.format + " · " + soc.captureInfo.packets + " · SHA-256: " + soc.captureInfo.sha256 : ""; Layout.fillWidth: true; elide: Text.ElideMiddle }
                        RowLayout {
                            TextField { id: packetSearch; placeholderText: win.tr("Buscar paquete por IP, puerto o protocolo"); Layout.fillWidth: true; onAccepted: soc.packetPage(0,text) }
                            Btn { text: win.tr("Buscar"); enabled: !soc.busy; onClicked: soc.packetPage(0,packetSearch.text) }
                            Btn { text: "←"; enabled: !soc.busy; onClicked: soc.packetPage(-1,packetSearch.text) }
                            Btn { text: "→"; enabled: !soc.busy && soc.packetRows.length === 200; onClicked: soc.packetPage(1,packetSearch.text) }
                        }
                        ListView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; model: soc.packetRows
                            delegate: Btn { required property var modelData; width: ListView.view.width; height: 32; onClicked: soc.viewPacketBytes(modelData.number); text: "#"+modelData.number+" · "+modelData.timestamp+" · "+modelData.protocol+" · "+modelData.src+":"+(modelData.src_port || "—")+" → "+modelData.dst+":"+(modelData.dst_port || "—")+" · "+modelData.captured+" B" }
                        }
                        ScrollView { visible: !!soc.packetBytes.hex; Layout.fillWidth: true; Layout.preferredHeight: 100; clip: true
                            TextArea { text: "#"+(soc.packetBytes.number || "")+" · "+(soc.packetBytes.shown || 0)+" / "+(soc.packetBytes.captured || 0)+" B\n"+(soc.packetBytes.hex || ""); readOnly: true; selectByMouse: true; wrapMode: TextEdit.WrapAnywhere; textFormat: TextEdit.PlainText; color: "#93a4bc"; font.family: "monospace" }
                        }
                    }
                }
                Panel {
                    visible: win.page === "Topología"; Layout.fillWidth: true; Layout.fillHeight: true
                    ColumnLayout { anchors.fill: parent; anchors.margins: 24; spacing: 14
                        Txt { text: win.tr("Conexiones observadas"); font.pixelSize: 22 }
                        Txt { text: win.tr("Relaciones origen/destino de las alertas de la página actual. No descubre equipos, rutas ni infraestructura."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        Canvas {
                            Layout.fillWidth: true; Layout.preferredHeight: 210
                            property var edges: soc.observedEdges
                            onEdgesChanged: requestPaint()
                            onWidthChanged: requestPaint()
                            onPaint: {
                                var ctx=getContext("2d"); ctx.reset(); var nodes=[]; var positions={};
                                for (var i=0;i<edges.length;i++) { if (nodes.indexOf(edges[i].src)<0 && nodes.length<24) nodes.push(edges[i].src); if (nodes.indexOf(edges[i].dst)<0 && nodes.length<24) nodes.push(edges[i].dst); }
                                for (i=0;i<nodes.length;i++) { var angle=2*Math.PI*i/Math.max(1,nodes.length); positions[nodes[i]]={x:width/2+Math.cos(angle)*(width/2-105),y:height/2+Math.sin(angle)*(height/2-25)}; }
                                ctx.strokeStyle="#315569"; ctx.lineWidth=1;
                                for (i=0;i<edges.length;i++) { var a=positions[edges[i].src]; var b=positions[edges[i].dst]; if(a && b) {ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();} }
                                ctx.font="11px sans-serif";ctx.textAlign="center";
                                for(i=0;i<nodes.length;i++){var point=positions[nodes[i]];ctx.fillStyle="#35d5df";ctx.beginPath();ctx.arc(point.x,point.y,5,0,Math.PI*2);ctx.fill();ctx.fillStyle="#e4eaf5";ctx.fillText(nodes[i],point.x,point.y-9);}
                            }
                        }
                        Txt { text: win.tr("Grafo: hasta 24 IP; lista: hasta 200 relaciones de la página actual."); color: win.muted; font.pixelSize: 10 }
                        Btn { text:win.tr("Abrir mapa de amenazas"); onClicked:win.page="Mapa de amenazas" }
                        ListView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; model: soc.observedEdges
                            delegate: Panel { required property var modelData; width: ListView.view.width; height: 52
                                Txt { anchors.centerIn: parent; text: modelData.src + "  →  " + modelData.dst + "    ·    " + modelData.protocol + "    ·    " + modelData.alerts + " " + win.tr("alertas") }
                            }
                        }
                    }
                }
                Panel {
                    visible: win.page === "Correlación MITRE"; Layout.fillWidth: true; Layout.fillHeight: true
                    ColumnLayout { anchors.fill: parent; anchors.margins: 24; spacing: 12
                        Txt { text: win.tr("Mapeos ATT&CK del analista"); font.pixelSize: 22 }
                        Txt { text: win.tr("Asociación heurística versionada por gid:sid:rev. No confirma ejecución ni compromiso. Verifica el identificador en MITRE ATT&CK."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        RowLayout {
                            TextField { id: mappingSignature; text: soc.selected.sid; placeholderText: "gid:sid:rev" }
                            TextField { id: mappingTechnique; placeholderText: "Txxxx / Txxxx.xxx" }
                            ComboBox { id: mappingConfidence; model: ["low","medium","high"]; displayText: win.tr(currentText) }
                        }
                        TextField { id: mappingTitle; placeholderText: win.tr("Nombre de técnica verificado"); Layout.fillWidth: true }
                        TextField { id: mappingReason; placeholderText: win.tr("Evidencia y justificación del mapeo"); Layout.fillWidth: true }
                        Btn { text: win.tr("Guardar revisión del mapeo"); onClicked: soc.saveMapping(mappingSignature.text,mappingTechnique.text,mappingTitle.text,mappingConfidence.currentText,mappingReason.text) }
                        ListView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; model: soc.mitreMappings; spacing: 8
                            delegate: Panel { required property var modelData; width: ListView.view.width; height: 110
                                ColumnLayout { anchors.fill: parent; anchors.margins: 12
                                    Txt { text: modelData.technique+" · "+modelData.title+" · "+modelData.alerts+" · "+win.tr(modelData.confidence); Layout.fillWidth: true }
                                    Txt { text: modelData.signature+" · rev "+modelData.revision+" · "+modelData.actor; color: win.muted }
                                    Txt { text: modelData.reason; Layout.fillWidth: true; elide: Text.ElideRight }
                                    Txt { text: modelData.url; color: win.accent }
                                }
                            }
                        }
                    }
                }
                Panel {
                    visible: win.page === "Tráfico"; Layout.fillWidth: true; Layout.fillHeight: true
                    ColumnLayout { anchors.fill: parent; anchors.margins: 24; spacing: 18
                        Txt { text: win.tr("Tráfico de interfaz local"); font.pixelSize: 22 }
                        Txt { text: win.tr("Contadores del sistema: incluyen tráfico ajeno a Snort. No acreditan captura ni protección del sensor."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        ComboBox { model: soc.interfaces; currentIndex: -1; displayText: currentIndex < 0 ? win.tr("Seleccionar interfaz") : currentText; onActivated: soc.selectInterface(currentText) }
                        Txt { text: soc.traffic.ready ? "RX: " + soc.traffic.rx_mbps.toFixed(3) + " Mbps · " + soc.traffic.rx_pps.toFixed(1) + " pkt/s\nTX: " + soc.traffic.tx_mbps.toFixed(3) + " Mbps · " + soc.traffic.tx_pps.toFixed(1) + " pkt/s" : win.tr("Esperando dos muestras válidas"); font.pixelSize: 22; color: "#35d5df" }
                        Txt { text: soc.traffic.source || soc.traffic.error || ""; color: win.muted }
                        ListView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; model: soc.trafficHistory
                            delegate: Txt { required property var modelData; width: ListView.view.width; height: 26; text: modelData.interface+" · RX "+modelData.rx_mbps.toFixed(3)+" Mbps · TX "+modelData.tx_mbps.toFixed(3)+" Mbps · Δ "+modelData.seconds.toFixed(2)+" s" }
                        }
                    }
                }
                Panel {
                    visible: win.page === "Servicio"; Layout.fillWidth: true; Layout.fillHeight: true
                    ScrollView {
                        id: serviceScroll; anchors.fill: parent; anchors.margins: 24; clip: true; contentWidth: availableWidth
                    ColumnLayout {
                        width: serviceScroll.availableWidth; spacing: 16
                        Txt { text: win.tr("Servicio del sensor"); font.pixelSize: 22 }
                        Txt { text: "jaltrix-sensor.service"; font.pixelSize: 17; color: win.accent }
                        Txt { text: win.tr("Perfil administrado en /etc/jaltrix. Revisa interfaz, HOME_NET y reglas. La interfaz lo solo observa tráfico local."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        Btn { objectName: "manage-real-service"; visible: soc.mode === "demo"; text: win.tr("Administrar servicio real"); onClicked: soc.manageRealService() }
                        Btn { text: win.tr("Configurar interfaz y HOME_NET"); enabled: soc.mode !== "demo" && soc.operationsAvailable && !soc.busy; onClicked: sensorConfigDialog.open() }
                        Txt { objectName: "service-status"; text: win.tr("Estado: ") + win.tr(soc.service.active) + " · " + win.tr("Arranque: ") + win.tr(soc.service.boot); font.pixelSize: 18 }
                        RowLayout {
                            enabled: soc.mode !== "demo" && !soc.service.busy && soc.service.manageable
                            Btn { objectName: "start-service"; text: win.tr("Iniciar servicio"); enabled: soc.service.active !== "active"; onClicked: soc.serviceAction("start") }
                            Btn { objectName: "stop-service"; text: win.tr("Detener servicio"); enabled: soc.service.active === "active"; onClicked: soc.serviceAction("stop") }
                        }
                        CheckBox {
                            objectName: "service-autostart"; text: win.tr("Iniciar con el sistema")
                            checked: soc.service.boot === "enabled"
                            enabled: soc.mode !== "demo" && !soc.service.busy && soc.service.manageable
                            nextCheckState: function() { return checkState }
                            onClicked: soc.serviceAction(soc.service.boot === "enabled" ? "disable" : "enable")
                        }
                        Txt { text: win.tr("Detener no cambia el arranque automático. La interfaz solicita autorización al sistema y verifica el resultado."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        RowLayout {
                            Btn { text: win.tr("Actualizar estado"); enabled: !soc.service.busy; onClicked: soc.refreshService() }
                            Btn { text: win.tr("Ver alertas del servicio"); enabled: soc.mode !== "demo" && !soc.busy; onClicked: { soc.followServiceLog(); win.page = "Alertas"; } }
                        }
                        Txt { text: win.tr(soc.service.error); Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; color: "#f5c76c" }
                        Txt { text: win.tr("Recolector independiente") + ": " + win.tr(soc.collector.fresh ? soc.collector.state : "Sin conexión"); font.pixelSize: 17 }
                        Txt { text: win.tr("Continúa al cerrar la ventana. Inicio automático al iniciar sesión; no equivale al servicio de captura."); wrapMode: Text.WordWrap; Layout.fillWidth: true; color: win.muted }
                        RowLayout {
                            Btn { text: win.tr("Iniciar recolector"); enabled: !soc.busy && soc.mode === "live" && !!soc.sourcePath; onClicked: soc.startCollector() }
                            Btn { text: win.tr("Detener recolector"); enabled: !soc.busy && soc.collector.fresh; onClicked: soc.stopCollector() }
                            Btn { text: win.tr("Retención"); enabled: !!soc.collector.source; onClicked: retentionDialog.open() }
                            Btn { text: win.tr("Conectar a recolector"); enabled: !soc.busy && !!soc.collector.source; onClicked: soc.connectCollector() }
                        }
                        Txt { text: soc.collector.error || soc.collector.source || ""; wrapMode: Text.WrapAnywhere; Layout.fillWidth: true; color: win.muted }
                    }
                    }
                }
                Panel {
                    visible: win.page === "Respuesta / Firewall"; Layout.fillWidth: true; Layout.fillHeight: true
                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: 24; spacing: 12
                        Txt { text: win.tr("Propuestas de respuesta"); font.pixelSize: 22 }
                        Txt { text: win.tr("Las propuestas no bloquean. Elige laboratorio o este host. El host requiere política de destinos autorizada; protege IP locales, gateway y DNS."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: "#f5c76c" }
                        RowLayout {
                            ComboBox { id: firewallScope; model: ["lab","host"] }
                            ComboBox { id: responseKind; model: ["blocklist", "allowlist"] }
                            TextField { id: responseTarget; placeholderText: "IP"; text: soc.selected.src === "—" ? "" : soc.selected.src; Layout.fillWidth: true }
                        }
                        RowLayout {
                            TextField { id: firewallAllowed; placeholderText: win.tr("Destinos permitidos: CIDR separados por coma"); Layout.fillWidth: true }
                            CheckBox { id: enableHostFirewall; text: win.tr("Habilitar respuesta en este host") }
                            Btn { text: win.tr("Previsualizar política"); enabled: soc.operationsAvailable && soc.mode !== "demo" && !soc.busy; onClicked: soc.planFirewallPolicy(firewallAllowed.text,enableHostFirewall.checked,responseReason.text) }
                        }
                        TextField { id: responseReason; placeholderText: win.tr("Motivo de la propuesta"); Layout.fillWidth: true }
                        RowLayout {
                            Btn { text: win.tr("Guardar propuesta"); onClicked: soc.proposeResponse(responseKind.currentText, responseTarget.text, responseReason.text) }
                            SpinBox { id: firewallTtl; from: 1; to: 3600; value: 60; editable: true }
                            Txt { text: "TTL (s)" }
                            Btn { text: win.tr("Previsualizar bloqueo"); enabled: soc.operationsAvailable && soc.mode !== "demo" && !soc.busy; onClicked: soc.planFirewall("firewall_apply",responseTarget.text,firewallTtl.value,responseReason.text,firewallScope.currentText) }
                        }
                        RowLayout {
                            Btn { text: win.tr("Verificar bloqueo"); enabled: soc.operationsAvailable && soc.mode !== "demo" && !soc.busy; onClicked: soc.planFirewall("firewall_status",responseTarget.text,firewallTtl.value,responseReason.text,firewallScope.currentText) }
                            Btn { text: win.tr("Retirar bloqueo"); enabled: soc.operationsAvailable && soc.mode !== "demo" && !soc.busy; onClicked: soc.planFirewall("firewall_revoke",responseTarget.text,firewallTtl.value,responseReason.text,firewallScope.currentText) }
                        }
                        Txt { text: soc.operationResult; Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted; font.pixelSize: 11 }
                        ListView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; model: soc.proposals; spacing: 10
                            delegate: Panel { required property var modelData; width: ListView.view.width; height: 94
                                RowLayout { anchors.fill: parent; anchors.margins: 12
                                    ColumnLayout { Layout.fillWidth: true
                                        Txt { text: modelData.kind + " · " + modelData.target + " · " + win.tr(modelData.state) }
                                        Txt { text: modelData.reason; Layout.fillWidth: true; color: win.muted }
                                        Txt { text: modelData.expires; color: win.muted; font.pixelSize: 10 }
                                    }
                                    Btn { text: win.tr("Anotar excepción para firma seleccionada"); visible: modelData.kind === "allowlist"; enabled: modelData.state === "CANDIDATE" && !!soc.selected.event_id; onClicked: soc.activateException(modelData.id) }
                                    Btn { text: win.tr("Revocar"); enabled: modelData.state === "CANDIDATE" || modelData.state === "ACTIVE_TRIAGE"; onClicked: soc.revokeProposal(modelData.id) }
                                }
                            }
                        }
                    }
                }
                Panel {
                    visible: win.page === "Reglas"; Layout.fillWidth: true; Layout.fillHeight: true
                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: 24; spacing: 12
                        Txt { text: win.tr("Borrador de regla local"); font.pixelSize: 22 }
                        Txt { text: win.tr("El borrador se valida de forma aislada. Desplegar requiere previsualización y autorización; conserva copia para restaurar."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        ScrollView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                            TextArea { id: ruleEditor; text: 'alert udp any any -> any 9999 (msg:"JALTRIX benign offline lab marker"; content:"SNORT_SOC_LAB"; sid:1000001; rev:1; priority:2;)'; wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText; selectByMouse: true; color: "#e4eaf5"; font.family: "monospace" }
                        }
                        RowLayout {
                            Btn { text: win.tr("Guardar borrador y validar"); enabled: !soc.busy; onClicked: soc.validateRule(ruleEditor.text) }
                            Btn { text: win.tr("Previsualizar despliegue"); enabled: !soc.busy && soc.mode !== "demo" && soc.operationsAvailable; onClicked: soc.planRules(ruleEditor.text,ruleReason.text) }
                            Btn { text: win.tr("Restaurar perfil anterior"); enabled: !soc.busy && soc.mode !== "demo" && soc.operationsAvailable; onClicked: soc.planRollback(ruleReason.text) }
                        }
                        TextField { id: ruleReason; placeholderText: win.tr("Justificación"); Layout.fillWidth: true }
                        Txt { text: soc.ruleResult.rules_path ? win.tr(soc.ruleResult.valid ? "Regla válida" : "Regla rechazada") + "\n" + soc.ruleResult.rules_path : ""; Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; color: win.accent }
                        ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 140; clip: true
                            TextArea { text: soc.ruleResult.output || ""; readOnly: true; wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText; color: "#93a4bc"; font.pixelSize: 11 }
                        }
                    }
                }
                Panel {
                    visible: win.page === "EDR / Endpoints"; Layout.fillWidth: true; Layout.fillHeight: true
                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: 24; spacing: 16
                        Txt { text: "EDR / Endpoints"; font.pixelSize: 22 }
                        Txt { text: win.tr("Proveedor no configurado"); color: "#f5c76c"; font.pixelSize: 18 }
                        Txt { text: win.tr("El aislamiento y la restauración requieren un proveedor EDR con endpoints administrados y capacidades verificadas."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        RowLayout { Btn { text: win.tr("Aislar host"); enabled: soc.edrCapabilities.isolate.available } Btn { text: win.tr("Restaurar conectividad"); enabled: soc.edrCapabilities.restore.available } }
                        Item { Layout.fillHeight: true }
                    }
                }
                Panel {
                    visible: win.page === "Reportes" || win.page === "Configuración"; Layout.fillWidth: true; Layout.fillHeight: true
                    ColumnLayout { anchors.fill: parent; anchors.margins: 28; spacing: 18
                        Txt { text: win.page === "Reportes" ? win.tr("Exportación con procedencia") : win.tr("Entorno y capacidades"); font.pixelSize: 22 }
                        Txt { text: win.tr("Motor: ") + win.tr(soc.sensorStatus) + "\n" + win.tr(soc.ingestionStatus) + "\n" + soc.sourcePath; Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; color: win.muted; lineHeight: 1.5 }
                        Txt { text: win.tr("Registros guardados: ") + (soc.mode === "demo" ? soc.summary.total : soc.storedCount) + (soc.mode === "demo" ? "" : win.tr(" · Consultas paginadas de 500 registros")); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }
                        Btn { text: win.tr("Asistente de configuración"); visible:win.page === "Configuración"; onClicked:soc.openSetup() }
                        Btn { text: win.tr("Guardar copia de seguridad"); visible: win.page === "Configuración"; enabled: !soc.busy; onClicked: backupDialog.open() }
                        RowLayout { visible: win.page === "Configuración"
                            Btn { text: win.tr("Seleccionar motor…"); enabled: !soc.busy; onClicked: engineDialog.open() }
                            Txt { text: soc.enginePath || "—"; Layout.fillWidth: true; elide: Text.ElideMiddle }
                        }
                        RowLayout { visible: win.page === "Configuración"; enabled: !soc.busy
                            Btn { text: win.tr("Importar alert_json…"); onClicked: { win.followFile = false; logDialog.open(); } }
                            Btn { text: win.tr("Seguir archivo en vivo…"); onClicked: { win.followFile = true; logDialog.open(); } }
                            Btn { text: win.tr("Volver a demo"); onClicked: soc.useDemo() }
                        }
                        Txt { visible: win.page === "Configuración"; text: win.tr("Epoch o zona horaria explícita; si faltan, el tiempo queda desconocido."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: win.muted }

                        RowLayout { visible: win.page === "Reportes"; Btn { text: win.tr("Guardar JSON…"); onClicked: exportDialog.open() } Btn { text: win.tr("Exportar CSV"); onClicked: csvDialog.open() } }
                        Txt { visible: win.page === "Configuración"; text: win.tr("Plataformas objetivo\nKali · Parrot · Ubuntu · Fedora · Arch Linux\nLa compatibilidad se publicará por versión probada."); color: win.muted; lineHeight: 1.6 }
                        Item { Layout.fillHeight: true }
                    }
                }
                Panel {
                    Layout.fillWidth: true; Layout.preferredHeight: win.logsOpen ? 180 : 42
                    ColumnLayout { anchors.fill: parent; anchors.margins: 6
                        RowLayout {
                            Btn { text: win.tr("Registro del sensor") + (win.logsOpen ? " ▾" : " ▸"); onClicked: { win.logsOpen=!win.logsOpen; if(win.logsOpen) soc.readTechnicalLog(); } }
                            Btn { visible: win.logsOpen; text: win.tr("Actualizar estado"); enabled: !soc.busy; onClicked: soc.readTechnicalLog() }
                            Item { Layout.fillWidth: true }
                            Txt { text: "Jan Herrera · JALTRIX " + soc.version; color: win.muted; font.pixelSize: 10 }
                        }
                        ScrollView { visible: win.logsOpen; Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                            TextArea { text: soc.technicalLog; readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText; color: "#93a4bc"; font.pixelSize: 11 }
                        }
                    }
                }
            }
        }
    }
    Label { id: toast; visible: false; anchors.bottom: parent.bottom; anchors.horizontalCenter: parent.horizontalCenter; anchors.bottomMargin: 32; padding: 16; color: "#ffffff"; textFormat: Text.PlainText; background: Rectangle { color: "#58398a"; radius: 9 } }
}
