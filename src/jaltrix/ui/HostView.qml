import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

Rectangle {
    id: root; objectName: "host-view"
    required property var controller
    readonly property var host: controller.host
    property int tab: 0
    color: "#111b2b"; radius: 12; border.color: "#29374e"
    onVisibleChanged: host.setVisible(visible)
    Component.onCompleted: host.setVisible(visible)
    function tr(value) { const locale = controller.language; return controller.translate(String(value)); }
    function stateLabel(value) {
        return tr(({disabled:"Desactivada",stopped:"Detenido",running:"En ejecución",active:"En ejecución",idle:"Sin eventos nuevos",ok:"Disponible",available:"Disponible",ready:"Disponible",unavailable:"No disponible",missing:"Fuente ausente",permission_denied:"Permiso denegado",denied:"Permiso denegado",error:"Error de lectura",stale:"Sin actualización reciente",unknown:"Sin verificar",starting:"Iniciando",degraded:"Una o más fuentes tienen problemas",partial_access:"Acceso parcial",following:"Seguimiento activo",reading_existing_log:"Leyendo registro existente",cursor_unavailable:"Posición del registro no disponible",invalid_records:"Registros no válidos"})[value] || value || "Sin verificar");
    }
    function correlationText(correlation, field) { return controller.language === "en-US" ? (correlation[field+"_en"] || correlation[field] || "") : (correlation[field] || ""); }
    function eventKind(value) {
        return tr(({auth_failure:"Autenticación fallida",auth_success:"Autenticación correcta",privilege_use:"Uso de privilegios",file_change:"Operación sobre archivo",process_exec:"Ejecución de proceso",service_change:"Cambio de servicio",network_alert:"Alerta de red",system_event:"Evento del sistema"})[value] || value || "");
    }
    function utcTime(value) {
        if (!value) return tr("Hora desconocida");
        const time=new Date(value);
        return isNaN(time.getTime()) ? String(value) : time.toISOString().slice(0,19).replace("T"," ")+" UTC";
    }
    function eventLine(event) {
        return [utcTime(event.timestamp), event.source || "", eventKind(event.kind || event.event_type), event.user || "", event.src_ip || event.src || "", event.file_path || event.path || ""].filter(Boolean).join(" · ");
    }
    function sourceState(name, enabled) {
        if (!enabled) return tr("Desactivada");
        const source = (host.status.sources || {})[name] || {};
        const capability = ((host.status.capabilities || {})[name]) || {};
        if (name === "audit" && capability.exists === false) return tr("Fuente ausente");
        if (name === "audit" && capability.readable === false) return tr("Permiso denegado");
        if (source.state === "permission_denied" || source.state === "error") return stateLabel(source.state);
        if (host.status.state === "stopped") return tr("Detenido");
        if (host.status.fresh === false && host.status.state !== "stopped") return tr("Sin actualización reciente");
        if (source.backlog) return tr("Procesando historial pendiente");
        return stateLabel(source.state);
    }
    function loadConfig() {
        journal.checked = host.config.journal_enabled || false;
        audit.checked = host.config.audit_enabled || false;
        auditPath.text = host.config.audit_path || "/var/log/audit/audit.log";
        snort.checked = host.config.snort_enabled || false;
        bindCurrent.checked = false;
        retention.value = host.config.retention_days || 30;
        limit.value = host.config.max_events || 100000;
    }
    function save(start) { host.saveConfig(journal.checked, audit.checked, auditPath.text, snort.checked, bindCurrent.checked, retention.value, limit.value, start); }
    function revealFocus(scroll, content, item) {
        if (!visible || !item) return;
        let ancestor=item;
        while (ancestor && ancestor!==content) ancestor=ancestor.parent;
        if (!ancestor) return;
        const point=item.mapToItem(scroll,0,0);
        if (point.y<0) scroll.contentItem.contentY+=point.y;
        else if (point.y+item.height>scroll.availableHeight) scroll.contentItem.contentY+=point.y+item.height-scroll.availableHeight;
    }
    Connections { target: root.host; function onConfigChanged() { root.loadConfig(); } }
    Connections { target:root.Window.window; function onActiveFocusItemChanged() {
        const item=root.Window.window.activeFocusItem;
        root.revealFocus(sourcesScroll,sourcesContent,item);
        root.revealFocus(evidenceScroll,evidenceContent,item);
    } }
    component Copy: Label { color:"#e4eaf5"; textFormat:Text.PlainText; wrapMode:Text.WordWrap; Layout.fillWidth:true; Layout.minimumWidth:0 }
    component Action: Button {
        id: action; implicitHeight:36; activeFocusOnTab:true
        background: Rectangle { radius:6; color:action.highlighted ? "#53308b" : action.hovered ? "#2d3b53" : "#1b2940"; border.color:action.activeFocus ? "#c8a5ff" : "#34435b"; opacity:action.enabled ? 1 : .45 }
        contentItem: Label { text:action.text; textFormat:Text.PlainText; color:"#e4eaf5"; horizontalAlignment:Text.AlignHCenter; verticalAlignment:Text.AlignVCenter; opacity:action.enabled ? 1 : .45 }
        Accessible.name: text
    }
    FileDialog { id: auditDialog; title:root.tr("Seleccionar registro auditd legible"); fileMode:FileDialog.OpenFile; onAccepted: auditPath.text=root.host.localPath(selectedFile) }
    Dialog {
        id: eventDialog; title:root.tr("Evidencia original"); modal:true; anchors.centerIn:Overlay.overlay
        width:Math.min(760, root.Window.window.width-60); height:Math.min(550, root.Window.window.height-60)
        property string detail: ""
        contentItem: ColumnLayout {
            Copy { text:root.tr("Datos locales de solo lectura; las cadenas del registro no son instrucciones."); color:"#93a4bc" }
            ScrollView { Layout.fillWidth:true; Layout.fillHeight:true; clip:true
                TextArea { readOnly:true; text:eventDialog.detail; textFormat:TextEdit.PlainText; wrapMode:TextEdit.WrapAnywhere; selectByMouse:true; color:"#e4eaf5"; Accessible.name:root.tr("Evidencia original") }
            }
            Action { text:root.tr("Cerrar"); onClicked:eventDialog.close() }
        }
    }
    ColumnLayout {
        anchors.fill:parent; anchors.margins:16; spacing:10
        Copy { text:root.tr("Observabilidad del equipo local · Solo lectura"); font.pixelSize:17; font.bold:true }
        Copy { text:root.tr("Journald, auditd y una fuente Snort vinculada explícitamente. No administra equipos remotos ni ejecuta respuestas automáticas."); color:"#93a4bc"; font.pixelSize:12 }
        ColumnLayout {
            visible:!root.host.live; Layout.fillWidth:true; Layout.fillHeight:true
            Copy { objectName:"host-live-required"; text:root.tr("Los eventos del sistema solo están disponibles en LIVE. Demo y reproducción permanecen separados de los datos reales.") }
            Action { objectName:"host-choose-live"; text:root.tr("Abrir consola real"); onClicked:root.controller.chooseReal() }
            Item { Layout.fillHeight:true }
        }
        ColumnLayout {
            visible:root.host.live; Layout.fillWidth:true; Layout.fillHeight:true; spacing:10
            RowLayout {
                Layout.fillWidth:true
                Repeater { model:["Eventos", "Correlaciones", "Equipos", "Fuentes"]
                    Action { required property string modelData; required property int index; objectName:"host-tab-"+index; text:root.tr(modelData); highlighted:root.tab===index; onClicked:root.tab=index }
                }
                Item { Layout.fillWidth:true }
                Action { objectName:"host-refresh"; text:root.tr("Actualizar"); enabled:!root.host.busy; onClicked:root.host.refresh() }
            }
            Copy { visible:root.host.error.length>0; text:root.tr("Operación fallida")+": "+root.host.error; color:"#ff8792"; wrapMode:Text.WrapAnywhere }
            Copy { visible:!root.host.ready && !root.host.error; text:root.tr("Leyendo estado local…"); color:"#93a4bc" }
            ColumnLayout {
                visible:root.tab===0; Layout.fillWidth:true; Layout.fillHeight:true
                RowLayout {
                    Layout.fillWidth:true
                    TextField { id:query; objectName:"host-query"; Layout.fillWidth:true; placeholderText:root.tr("Buscar usuario, IP o ruta"); selectByMouse:true; Accessible.name:placeholderText; onAccepted:root.host.filter(text, ["", "journal", "audit", "snort"][source.currentIndex]) }
                    ComboBox { id:source; objectName:"host-source-filter"; implicitWidth:190; Layout.minimumWidth:180; model:[root.tr("Todas las fuentes"), "journald", "auditd", "Snort"]; Accessible.name:root.tr("Fuente de eventos"); onActivated:root.host.filter(query.text, ["", "journal", "audit", "snort"][currentIndex]) }
                    Action { text:root.tr("Buscar"); onClicked:root.host.filter(query.text, ["", "journal", "audit", "snort"][source.currentIndex]) }
                }
                ListView {
                    id:eventList; objectName:"host-events"; Layout.fillWidth:true; Layout.fillHeight:true; clip:true; spacing:4; model:root.host.events
                    ScrollBar.vertical:ScrollBar {}
                    delegate:ItemDelegate {
                        required property var modelData; width:ListView.view.width; height:76; activeFocusOnTab:true
                        background:Rectangle { radius:5; color:parent.hovered ? "#24314b" : "#172235"; border.color:parent.activeFocus ? "#c8a5ff" : "transparent" }
                        contentItem:ColumnLayout {
                            Copy { text:root.eventLine(modelData); font.pixelSize:11; maximumLineCount:2; elide:Text.ElideRight }
                            Copy { text:modelData.message || modelData.kind || ""; color:"#93a4bc"; maximumLineCount:1; elide:Text.ElideRight }
                        }
                        Accessible.name:root.eventLine(modelData)
                        onClicked:{ eventDialog.detail=root.host.eventDetails(modelData); eventDialog.open(); }
                    }
                    Copy { objectName:"host-empty"; anchors.centerIn:parent; width:parent.width-24; horizontalAlignment:Text.AlignHCenter; visible:eventList.count===0; text:root.tr("No hay eventos con estos filtros. Configura fuentes y permisos en Fuentes; cero eventos no confirma ausencia de actividad."); color:"#93a4bc" }
                }
                RowLayout {
                    Layout.fillWidth:true
                    Action { text:root.tr("Anterior"); enabled:root.host.pagination.offset>0; onClicked:root.host.changePage(-1) }
                    Copy { text:root.host.pagination.offset+" — "+root.host.pagination.next+" / "+root.host.pagination.total; horizontalAlignment:Text.AlignHCenter; color:"#93a4bc" }
                    Action { text:root.tr("Siguiente"); enabled:root.host.pagination.next<root.host.pagination.total; onClicked:root.host.changePage(1) }
                }
            }
            RowLayout {
                visible:root.tab===1; Layout.fillWidth:true; Layout.fillHeight:true; spacing:12
                ColumnLayout {
                    Layout.preferredWidth:root.width*.38; Layout.fillHeight:true
                    Copy { text:root.tr("Hasta 100 correlaciones recientes"); color:"#93a4bc"; font.pixelSize:12 }
                    ListView {
                        id:correlationList; objectName:"host-correlations"; Layout.fillWidth:true; Layout.fillHeight:true; model:root.host.correlations; clip:true; spacing:5
                        ScrollBar.vertical:ScrollBar {}
                        delegate:ItemDelegate {
                            required property var modelData; width:ListView.view.width; height:94; activeFocusOnTab:true
                            background:Rectangle { radius:5; color:root.host.selected.id===modelData.id ? "#322449" : "#172235"; border.color:parent.activeFocus ? "#c8a5ff" : "transparent" }
                            contentItem:ColumnLayout { Copy { text:root.correlationText(modelData,"title"); maximumLineCount:2; elide:Text.ElideRight } Copy { text:root.utcTime(modelData.timestamp)+" · "+(modelData.event_ids || []).length+" "+root.tr("evidencias"); color:"#93a4bc"; font.pixelSize:11; maximumLineCount:2; elide:Text.ElideRight } }
                            onClicked:root.host.selectCorrelation(modelData.id)
                        }
                        Copy { anchors.centerIn:parent; width:parent.width-16; visible:correlationList.count===0; text:root.tr("Sin correlaciones. Se requieren eventos compatibles con identidad, resultado y tiempo conocidos."); horizontalAlignment:Text.AlignHCenter; color:"#93a4bc" }
                    }
                }
                ScrollView {
                    id:evidenceScroll; Layout.fillWidth:true; Layout.fillHeight:true; clip:true; contentWidth:availableWidth
                    ColumnLayout {
                        id:evidenceContent
                        width:evidenceScroll.availableWidth; spacing:10
                        Copy { text:root.host.selected.title ? root.correlationText(root.host.selected,"title") : root.tr("Selecciona una correlación para revisar su explicación y la secuencia de evidencias."); font.bold:true }
                        Copy { visible:!!root.host.selected.id; text:root.tr("Regla")+": "+(root.host.selected.rule_id || "")+" · "+(root.host.selected.window_seconds || 0)+" s"; color:"#93a4bc"; font.pixelSize:11 }
                        Copy { text:root.host.selected.explanation ? root.correlationText(root.host.selected,"explanation") : ""; wrapMode:Text.WordWrap }
                        Copy { visible:!!root.host.selected.id; text:root.tr("Correlación de indicios; requiere investigación y no prueba por sí sola una intrusión."); color:"#f5c76c" }
                        Action { objectName:"host-create-case"; visible:!!root.host.selected.id; enabled:!root.host.busy; text:root.tr("Crear / abrir caso y conservar evidencias"); onClicked:root.host.createCase(root.host.selected.id) }
                        Copy { visible:!!root.host.selected.id; text:root.tr("Secuencia de evidencias · UTC"); font.bold:true }
                        Repeater { model:root.host.timeline
                            Action { required property var modelData; Layout.fillWidth:true; implicitHeight:66; text:root.eventLine(modelData)+"\n"+(modelData.message || ""); contentItem:Copy { text:parent.text; font.pixelSize:11; maximumLineCount:3; elide:Text.ElideRight } onClicked:{ eventDialog.detail=root.host.eventDetails(modelData); eventDialog.open(); } }
                        }
                    }
                }
            }
            ScrollView {
                id:hostsScroll; visible:root.tab===2; Layout.fillWidth:true; Layout.fillHeight:true; clip:true; contentWidth:availableWidth
                ColumnLayout {
                    width:hostsScroll.availableWidth; spacing:12
                    Copy { text:root.tr("Inventario local observado"); font.pixelSize:18; font.bold:true }
                    Copy { text:root.tr("Solo aparecen identidades presentes en los eventos de este equipo. Esta versión no descubre ni administra agentes remotos."); color:"#93a4bc" }
                    Copy { visible:root.host.hosts.length===0; text:root.tr("Sin equipos observados. Activa una fuente local para registrar evidencia.") }
                    Repeater { model:root.host.hosts
                        Frame { required property var modelData; Layout.fillWidth:true
                            contentItem:ColumnLayout {
                                Copy { text:modelData.hostname || root.tr("Equipo local"); font.bold:true }
                                Copy { text:root.tr("Identidad")+": "+modelData.host_id; wrapMode:Text.WrapAnywhere; font.pixelSize:11; color:"#93a4bc" }
                                Copy { text:root.tr("Eventos")+": "+modelData.event_count+" · "+root.tr("Fuentes")+": "+(modelData.sources || []).join(", ") }
                                Copy { text:root.tr("Primera / última observación UTC")+": "+root.utcTime(modelData.first_seen)+" / "+root.utcTime(modelData.last_seen); font.pixelSize:11 }
                            }
                        }
                    }
                }
            }
            ScrollView {
                id:sourcesScroll; visible:root.tab===3; Layout.fillWidth:true; Layout.fillHeight:true; clip:true; contentWidth:availableWidth
                ColumnLayout {
                    id:sourcesContent; width:sourcesScroll.availableWidth; spacing:12; enabled:root.host.ready && !root.host.busy
                    Copy { text:root.tr("Fuentes desactivadas por defecto"); font.pixelSize:18; font.bold:true }
                    Copy { objectName:"host-service-state"; text:root.tr("Recolector local de usuario")+": "+root.stateLabel(root.host.status.state); color:"#35d5df" }
                    Copy { text:root.tr("Lee registros accesibles con tus permisos. No instala auditd, cambia reglas, concede permisos ni modifica el sistema. El recolector es independiente del sensor Snort."); color:"#93a4bc" }
                    CheckBox { id:journal; objectName:"host-enable-journal"; text:root.tr("Leer eventos de journald (SSH y sudo)"); Layout.fillWidth:true; Accessible.name:text }
                    Copy { text:root.tr("Estado de journald")+": "+root.sourceState("journal",root.host.config.journal_enabled); color:"#93a4bc" }
                    Copy { text:root.tr("Solo historial accesible de los últimos 15 minutos de journald en el primer inicio; después se conserva la posición de lectura."); color:"#93a4bc"; font.pixelSize:12 }
                    CheckBox { id:audit; objectName:"host-enable-audit"; text:root.tr("Leer un registro auditd existente"); Layout.fillWidth:true; Accessible.name:text }
                    RowLayout {
                        Layout.fillWidth:true
                        TextField { id:auditPath; objectName:"host-audit-path"; Layout.fillWidth:true; selectByMouse:true; Accessible.name:root.tr("Ruta del registro auditd") }
                        Action { text:root.tr("Seleccionar archivo…"); onClicked:auditDialog.open() }
                    }
                    Copy { text:root.tr("Estado de auditd")+": "+root.sourceState("audit",root.host.config.audit_enabled); color:"#93a4bc" }
                    Copy { text:root.tr("Las operaciones sobre authorized_keys solo estarán disponibles si auditd ya registra esos archivos; no confirman cambios de contenido. Un archivo ausente o sin permiso se muestra como problema de la fuente."); color:"#93a4bc"; font.pixelSize:12 }
                    CheckBox { id:snort; objectName:"host-enable-snort"; text:root.tr("Correlacionar alertas Snort del equipo local"); Layout.fillWidth:true; Accessible.name:text }
                    CheckBox { id:bindCurrent; objectName:"host-bind-snort"; enabled:snort.checked && !!root.controller.sourcePath; text:root.tr("Confirmo que el archivo Snort actual pertenece a este equipo"); Layout.fillWidth:true; Accessible.name:text }
                    Copy { text:root.tr("Archivo actual")+": "+(root.controller.sourcePath || root.tr("Sin archivo conectado")); wrapMode:Text.WrapAnywhere; color:"#93a4bc"; font.pixelSize:11 }
                    Copy { text:root.tr("Vinculación guardada")+": "+(root.host.config.snort_source_id || root.tr("Ninguna")); wrapMode:Text.WrapAnywhere; color:"#93a4bc"; font.pixelSize:11 }
                    Copy { text:root.tr("No vincules registros de sensores externos. Cambiar el archivo conectado no reasigna la vinculación guardada; se requiere marcar la confirmación y guardar."); color:"#f5c76c"; font.pixelSize:12 }
                    Copy { text:root.tr("Estado de Snort vinculado")+": "+root.sourceState("snort",root.host.config.snort_enabled); color:"#93a4bc" }
                    Repeater { model:["journal", "audit", "snort"]
                        Copy { required property string modelData; readonly property var sourceState:(root.host.status.sources || {})[modelData] || {}; visible:!!sourceState.error; text:modelData+": "+(sourceState.error || ""); color:"#ff8792"; wrapMode:Text.WrapAnywhere }
                    }
                    RowLayout {
                        Layout.fillWidth:true
                        Copy { text:root.tr("Retención (días)") }
                        SpinBox { id:retention; objectName:"host-retention"; from:1; to:365; value:30; editable:true; Accessible.name:root.tr("Retención (días)") }
                        Copy { text:root.tr("Máximo de eventos") }
                        SpinBox { id:limit; objectName:"host-limit"; from:1000; to:1000000; stepSize:1000; value:100000; editable:true; implicitWidth:150; Accessible.name:root.tr("Máximo de eventos") }
                    }
                    Copy { text:root.tr("Las evidencias vinculadas a casos se conservan aunque superen la retención. Revisa el espacio disponible."); color:"#93a4bc"; font.pixelSize:12 }
                    Flow {
                        Layout.fillWidth:true; spacing:8
                        Action { objectName:"host-save"; text:root.tr("Guardar fuentes"); onClicked:root.save(false) }
                        Action { objectName:"host-start"; highlighted:true; enabled:journal.checked || audit.checked || snort.checked; text:root.tr("Guardar e iniciar recolector"); onClicked:root.save(true) }
                        Action { objectName:"host-stop"; text:root.tr("Detener recolector"); onClicked:root.host.stop() }
                    }
                    Copy { text:root.tr("Iniciar también habilita el recolector al iniciar sesión; detenerlo deshabilita ese arranque de usuario."); color:"#93a4bc"; font.pixelSize:12 }
                    Copy { text:root.tr("Cerrar la ventana no detiene el recolector. Usa Detener recolector para detener la lectura."); color:"#93a4bc"; font.pixelSize:12 }
                }
            }
        }
    }
}
