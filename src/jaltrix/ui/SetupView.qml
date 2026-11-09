import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root; objectName:"setup-view"
    required property var controller
    signal engineRequested()
    signal logRequested()
    signal profileRequested()
    signal rulesRequested()
    signal dashboardRequested()
    property int step: 0
    color: "#111b2b"; radius: 12; border.color: "#29374e"
    function tr(value) { const locale = controller.language; return controller.translate(value); }
    component Copy: Label { color: "#e4eaf5"; textFormat: Text.PlainText; wrapMode: Text.WordWrap; Layout.fillWidth: true }
    component Action: Button {
        id: action; implicitHeight:38; Layout.maximumWidth:root.width-60
        background: Rectangle { radius:6; color:action.highlighted ? "#53308b" : action.hovered ? "#2d3b53" : "#1b2940"; border.color:action.activeFocus ? "#a978ff" : "#34435b"; opacity:action.enabled ? 1 : 0.45 }
        contentItem: Label { text:action.text; color:"#e4eaf5"; textFormat:Text.PlainText; horizontalAlignment:Text.AlignHCenter; verticalAlignment:Text.AlignVCenter; opacity:action.enabled ? 1 : 0.45 }
    }
    ColumnLayout {
        anchors.fill: parent; anchors.margins: 22; spacing: 14
        Copy { text: root.tr("Bienvenido a JALTRIX"); font.pixelSize: 24; font.bold: true }
        Copy { text: root.tr("Conecta un sensor real o explora la demostración. Snort 3 se instala por separado."); color: "#93a4bc" }
        RowLayout {
            Repeater { model: ["1 · Motor", "2 · Sensor", "3 · Alertas"]
                Action { required property int index; required property string modelData; text:root.tr(modelData); highlighted:root.step===index; onClicked:root.step=index }
            }
            Item { Layout.fillWidth:true }
            Action { objectName:"setup-demo"; text:root.tr("Explorar demostración"); enabled:!controller.busy; onClicked: { controller.chooseDemo(); root.dashboardRequested(); } }
        }
        ScrollView {
            id: scroll; Layout.fillWidth: true; Layout.fillHeight: true; clip:true; contentWidth:availableWidth
            ColumnLayout {
                width:scroll.availableWidth; spacing:14
                ColumnLayout {
                    visible:root.step===0; Layout.fillWidth:true; spacing:12
                    Copy { text:root.tr("Motor Snort 3"); font.pixelSize:19; font.bold:true }
                    Copy { text:controller.setupInfo.distro; color:"#93a4bc" }
                    Copy { objectName:"setup-engine-status"; text:root.tr(controller.setupInfo.busy ? "Comprobando motor…" : ({missing:"Snort no encontrado",compatible:"Snort 3 compatible",incompatible:"Motor incompatible: se necesita Snort 3",error:"No se pudo ejecutar el motor"})[controller.setupInfo.state] || "Comprobando motor…") + (controller.setupInfo.version ? " · " + controller.setupInfo.version : ""); color:controller.setupInfo.state==="compatible" ? "#46d99b" : "#f5c76c" }
                    Copy { text:controller.setupInfo.path || "—"; wrapMode:Text.WrapAnywhere; color:"#93a4bc" }
                    RowLayout {
                        Action { text:root.tr("Seleccionar motor…"); enabled:!controller.setupInfo.busy; onClicked:root.engineRequested() }
                        Action { objectName:"setup-detect"; text:root.tr("Volver a detectar"); enabled:!controller.setupInfo.busy; onClicked:controller.refreshSetup() }
                    }
                    Copy { text:root.tr("¿Ya tienes Snort? Selecciona su ejecutable y verifica la versión. No reemplazamos su configuración ni iniciamos otro sensor automáticamente.") }
                    Copy { text:root.tr("Si falta: consulta la guía oficial, instala Snort 3 y LibDAQ para tu distribución y vuelve a detectar. Un paquete llamado snort puede ser Snort 2; el asistente comprueba la versión.") }
                    Copy { text:root.tr("Verifica en una terminal: snort -V y snort --daq-list. Para crear el servicio de JALTRIX se requiere afpacket, systemd, Polkit y el paquete acl. Instala el motor en /usr o /opt con permisos de administrador."); color:"#93a4bc" }
                    RowLayout {
                        Action { text:root.tr("Guía oficial de instalación"); onClicked:controller.openSetupGuide("install") }
                        Action { text:root.tr("Descargas de Snort 3"); onClicked:controller.openSetupGuide("download") }
                    }
                    Copy { text:root.tr("Puedes conectar alertas de un sensor externo aunque el motor no esté instalado en este equipo."); color:"#35d5df" }
                    Action { objectName:"setup-real"; highlighted:true; text:root.tr("Configurar sensor real"); enabled:!controller.busy; onClicked: { controller.chooseReal(); root.step=1; } }
                    Copy { visible:controller.setupInfo.state==="error" || controller.setupInfo.state==="incompatible"; text:controller.setupInfo.detail; wrapMode:Text.WrapAnywhere; color:"#f5c76c" }
                }
                ColumnLayout {
                    visible:root.step===1; Layout.fillWidth:true; spacing:12
                    Copy { text:root.tr("Elige cómo conectar el sensor"); font.pixelSize:19; font.bold:true }
                    Copy { text:root.tr("Sensor existente o externo: conserva su servicio y sus reglas; conecta un archivo alert_json que puedas leer. JALTRIX solo administra su propio servicio.") }
                    Action { text:root.tr("Conectar sensor existente"); highlighted:true; onClicked: { controller.chooseReal(); root.step=2; } }
                    Copy { text:root.tr("Servicio de JALTRIX") + ": " + root.tr(controller.service.load) + " · " + root.tr(controller.service.active); color:"#35d5df" }
                    ColumnLayout {
                        visible:controller.service.load==="loaded"; Layout.fillWidth:true
                        Copy { text:root.tr("Perfil existente conservado. Revisa la interfaz, HOME_NET y las reglas antes de iniciar.") }
                        Action { text:root.tr("Configurar interfaz y HOME_NET"); enabled:!controller.busy; onClicked: { controller.chooseReal(); root.profileRequested(); } }
                        Action { text:root.tr("Revisar reglas"); onClicked: { controller.chooseReal(); root.rulesRequested(); } }
                    }
                    ColumnLayout {
                        visible:controller.service.load!=="loaded"; Layout.fillWidth:true; spacing:10
                        Copy { text:root.tr("Crear un sensor nuevo de JALTRIX"); font.bold:true }
                        Copy { text:root.tr("Se crearán un servicio y archivos propios. El motor y las configuraciones existentes se conservan. La creación requiere autorización del sistema y deja el servicio detenido.") }
                        Copy { visible:controller.setupInfo.profile_exists; text:root.tr("Ya existe /etc/jaltrix: no se sobrescribirá. Revisa esa instalación o conecta su archivo de alertas."); color:"#f5c76c" }
                        ComboBox { id:iface; model:controller.interfaces; currentIndex:-1; displayText:currentIndex<0 ? root.tr("Seleccionar interfaz") : currentText; Layout.fillWidth:true }
                        TextField { id:network; placeholderText:root.tr("HOME_NET en CIDR, por ejemplo 192.168.1.0/24"); Layout.fillWidth:true }
                        Copy { text:root.tr("Pega tus reglas locales de Snort 3. Se validarán antes de crear el servicio. No se incluye una colección de reglas de protección."); color:"#f5c76c" }
                        ScrollView { Layout.fillWidth:true; Layout.preferredHeight:125; clip:true
                            TextArea { id:rules; placeholderText:root.tr("Reglas locales (.rules)"); wrapMode:TextEdit.Wrap; textFormat:TextEdit.PlainText; selectByMouse:true }
                        }
                        Action { highlighted:true; text:root.tr("Revisar y crear servicio"); enabled:!controller.busy && !controller.setupInfo.busy && controller.setupInfo.state==="compatible" && !controller.setupInfo.profile_exists && iface.currentIndex>=0 && network.text.length>0 && rules.text.length>0 && controller.operationsAvailable; onClicked: { controller.chooseReal(); controller.planNewSensor(iface.currentText,network.text,rules.text); } }
                    }
                    Action { text:root.tr("Continuar a alertas"); onClicked:root.step=2 }
                }
                ColumnLayout {
                    visible:root.step===2; Layout.fillWidth:true; spacing:12
                    Copy { text:root.tr("Conectar alertas y elegir el arranque"); font.pixelSize:19; font.bold:true }
                    Copy { text:root.tr("Servicio de JALTRIX") + ": " + root.tr(controller.service.active) }
                    RowLayout {
                        enabled:controller.service.manageable && !controller.service.busy && !controller.busy
                        Action { text:root.tr("Iniciar servicio"); enabled:controller.service.active!=="active"; onClicked: { controller.chooseReal(); controller.serviceAction("start"); } }
                        Action { text:root.tr("Detener servicio"); enabled:controller.service.active==="active"; onClicked: { controller.chooseReal(); controller.serviceAction("stop"); } }
                    }
                    CheckBox { text:root.tr("Iniciar con el sistema"); checked:controller.service.boot==="enabled"; enabled:controller.service.manageable && !controller.service.busy && !controller.busy; nextCheckState:function() { return checkState }; onClicked: { controller.chooseReal(); controller.serviceAction(controller.service.boot==="enabled" ? "disable" : "enable"); } }
                    Copy { text:root.tr("Iniciar ahora y arrancar con el sistema son decisiones independientes. Cerrar JALTRIX no detiene el sensor."); color:"#93a4bc" }
                    RowLayout {
                        Action { objectName:"setup-service-log"; text:root.tr("Conectar alertas de JALTRIX"); enabled:!controller.busy && controller.service.load==="loaded"; onClicked:controller.followServiceLog() }
                        Action { objectName:"setup-other-log"; text:root.tr("Seleccionar alert_json existente…"); enabled:!controller.busy; onClicked:root.logRequested() }
                    }
                    Action { text:root.tr("Cómo configurar alert_json"); onClicked:controller.openSetupGuide("logging") }
                    Copy { text:controller.sourcePath || root.tr("Todavía no hay un archivo de alertas conectado."); wrapMode:Text.WrapAnywhere }
                    Copy { text:root.tr(controller.setupInfo.message); color:controller.setupInfo.connected ? "#46d99b" : "#f5c76c" }
                    Copy { text:root.tr("La conexión se recordará al abrir la aplicación. Si el archivo desaparece o pierde permisos, verás el problema; no se sustituirá por datos demo."); color:"#93a4bc" }
                    Copy { text:root.tr(controller.service.error); color:"#ff7785" }
                    Action { objectName:"setup-finish"; highlighted:true; text:root.tr("Abrir consola real"); enabled:controller.mode==="live" && controller.setupInfo.connected && !controller.busy; onClicked:root.dashboardRequested() }
                }
            }
        }
    }
}
