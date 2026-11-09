import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root
    required property var controller
    property var stats: controller.geoMap
    signal importRequested()
    color: "#111b2b"; radius: 12; border.color: "#29374e"
    function tr(value) { const locale = controller.language; return controller.translate(value); }
    component TextLabel: Label { color: "#e4eaf5"; textFormat: Text.PlainText; elide: Text.ElideRight }
    component Action: Button {
        implicitHeight: 32
        background: Rectangle { radius: 6; color: parent.highlighted ? "#53308b" : parent.hovered ? "#2d3b53" : "#1a2940"; border.color: parent.activeFocus ? "#a978ff" : "#34435b" }
        contentItem: TextLabel { text: parent.text; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter; opacity: parent.enabled ? 1 : 0.4 }
    }
    ColumnLayout {
        anchors.fill: parent; anchors.margins: 16; spacing: 10
        RowLayout {
            Layout.fillWidth: true
            TextLabel { text: root.tr("Mapa de amenazas"); font.pixelSize: 20; font.bold: true; Layout.fillWidth: true }
            Action { text: root.tr("Base GeoIP local"); enabled: !controller.busy; onClicked: root.importRequested() }
            Action { text: root.tr("Todos los países"); highlighted: !root.stats.selection_country; onClicked: controller.selectGeoCountry("") }
        }
        TextLabel { text: root.tr(controller.mode === "demo" ? "DEMO · Ubicaciones simuladas; no representan actividad real." : "IP de origen · Ubicación aproximada; no identifica al atacante."); color: controller.mode === "demo" ? "#d7bdff" : "#93a4bc"; Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 11 }
        RowLayout {
            Layout.fillWidth: true
            TextLabel { objectName: "geo-totals"; text: root.stats.located+" / "+root.stats.total+" "+root.tr("alertas ubicadas")+" · "+root.stats.unlocated+" "+root.tr("sin ubicación")+" · "+root.tr("Consulta completa"); color: "#35d5df"; Layout.fillWidth: true; font.pixelSize: 11 }
            TextLabel { visible: root.stats.busy; text: root.tr("Actualizando mapa…"); color: "#f5c76c"; font.pixelSize: 11 }
        }
        TextLabel { visible: !!root.stats.error; text: root.stats.error || ""; color: "#ff7785"; Layout.fillWidth: true; wrapMode: Text.WordWrap }
        TextLabel { visible: !root.stats.configured && controller.mode !== "demo"; text: root.tr("Importa un CSV GeoIP para ubicar las IP públicas. Las IP privadas y desconocidas no se colocan en el mapa."); Layout.fillWidth: true; wrapMode: Text.WordWrap; color: "#f5c76c" }
        RowLayout {
            Layout.fillWidth: true; Layout.preferredHeight: Math.max(170,Math.min(320,root.height*0.45)); Layout.maximumHeight: Layout.preferredHeight; spacing: 12
            WorldMap { objectName:"world-map"; Layout.fillWidth: true; Layout.minimumWidth:300; Layout.preferredWidth:600; Layout.fillHeight: true; controller: root.controller; stats: root.stats; onMarkerSelected: key => controller.selectGeoMarker(key) }
            ColumnLayout {
                Layout.preferredWidth:195; Layout.minimumWidth:180; Layout.maximumWidth:195; Layout.fillWidth:false; Layout.fillHeight:true
                TextLabel { text: root.tr("Países · % de alertas ubicadas"); font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                ListView {
                    id: countriesView; objectName: "geo-countries"; Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 5; model: root.stats.countries
                    ScrollBar.vertical: ScrollBar {}
                    delegate: ItemDelegate {
                        required property var modelData
                        objectName: "geo-country-"+modelData.country
                        width: ListView.view.width; height: 56
                        Accessible.name: modelData.country+" · "+modelData.alerts+" "+root.tr("alertas")
                        background: Rectangle { radius: 6; color: parent.modelData.country === root.stats.selection_country ? "#39294e" : "#19253a"; border.color: parent.activeFocus ? "#b78aff" : "#35435b" }
                        contentItem: ColumnLayout {
                            spacing: 3
                            RowLayout { TextLabel { text: modelData.country; font.bold: true } Item { Layout.fillWidth: true } TextLabel { text: modelData.alerts+" · "+modelData.percent+"%"; color: "#d7bdff"; font.pixelSize: 11 } }
                            Rectangle { Layout.fillWidth: true; height: 3; radius: 2; color: "#2b354d"; Rectangle { width: parent.width*modelData.percent/100; height: 3; radius: 2; color: "#aa71ee" } }
                            TextLabel { text: modelData.sources+" IP"; color: "#93a4bc"; font.pixelSize: 10 }
                        }
                        onClicked: controller.selectGeoCountry(modelData.country)
                    }
                    TextLabel { anchors.centerIn: parent; visible: countriesView.count === 0; text: root.tr("Sin ubicaciones"); color: "#93a4bc" }
                }
            }
        }
        TextLabel { visible: root.stats.hidden_markers > 0; text: root.tr("Marcadores visibles limitados a los 1000 más frecuentes. Los totales y las alertas incluyen todos."); Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 10; color: "#f5c76c" }
        RowLayout {
            Layout.fillWidth: true
            TextLabel { text: root.tr("Explorar alertas")+" · "+(root.stats.selection_country || root.tr("Todos los países"))+(root.stats.selection_marker ? " · "+root.tr("Marcador seleccionado") : ""); Layout.fillWidth: true; font.bold: true }
            TextLabel { text: root.stats.offset+"–"+root.stats.next+" / "+root.stats.matched; color: "#93a4bc"; font.pixelSize: 11 }
            Action { text: "←"; Accessible.name: root.tr("Anterior"); enabled: !root.stats.busy && root.stats.offset > 0; onClicked: controller.geoPage(-1) }
            Action { text: "→"; Accessible.name: root.tr("Siguiente"); enabled: !root.stats.busy && root.stats.next < root.stats.matched; onClicked: controller.geoPage(1) }
        }
        ListView {
            id: geoEvents; objectName: "geo-events"; Layout.fillWidth: true; Layout.fillHeight: true; Layout.minimumHeight: 60; clip: true; model: root.stats.events; spacing: 3
            ScrollBar.vertical: ScrollBar {}
            delegate: ItemDelegate {
                required property var modelData
                objectName: "geo-event-"+modelData.event_id
                width: ListView.view.width; height: 48; enabled: !root.stats.busy
                background: Rectangle { radius: 5; color: parent.hovered ? "#2b2643" : "#172237"; border.color: parent.activeFocus ? "#a978ff" : "transparent" }
                contentItem: ColumnLayout {
                    spacing: 2
                    TextLabel { text: modelData.src+" → "+modelData.dst+" · "+root.tr(modelData.severity)+" · "+modelData.time; Layout.fillWidth: true; color: "#c4a4ff"; font.pixelSize: 11 }
                    TextLabel { text: controller.mode === "demo" ? root.tr(modelData.message) : modelData.message; Layout.fillWidth: true; font.pixelSize: 12 }
                }
                onClicked: controller.openGeoAlert(modelData.event_id)
            }
            TextLabel { visible: geoEvents.count === 0; anchors.centerIn: parent; text: root.tr("Sin alertas geolocalizadas con estos filtros"); color: "#93a4bc" }
        }
        TextLabel { text: root.tr("Selecciona un país o marcador; pulsa una alerta para abrir su inspector."); Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 10; color: "#93a4bc" }
    }
}
