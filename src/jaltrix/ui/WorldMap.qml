import QtQuick
import QtQuick.Controls

Rectangle {
    id: root
    required property var controller
    property var stats: controller.geoMap
    property bool compact: false
    property real zoom: 1
    signal markerSelected(string key)
    color: "#0c1424"; radius: 10; clip: true
    border.color: "#2e3b53"
    function tr(value) { const locale = controller.language; return controller.translate(value); }
    Flickable {
        id: viewport
        anchors.fill: parent; anchors.margins: 1; clip: true
        property real baseWidth: Math.min(width, height*2)
        contentWidth: Math.max(width, baseWidth*root.zoom)
        contentHeight: Math.max(height, baseWidth*root.zoom/2)
        boundsBehavior: Flickable.StopAtBounds
        interactive: !root.compact && root.zoom > 1
        Item {
            id: world
            width: viewport.baseWidth*root.zoom; height: width/2
            x: (viewport.contentWidth-width)/2; y: (viewport.contentHeight-height)/2
            Image { anchors.fill: parent; source: "world-land.svg"; fillMode: Image.Stretch; sourceSize.width: 1440; sourceSize.height: 720 }
            Canvas {
                anchors.fill: parent
                onWidthChanged: requestPaint()
                onPaint: {
                    var c=getContext("2d"); c.reset(); c.strokeStyle="#22304a"; c.lineWidth=0.5;
                    for(var i=1;i<12;i++){c.beginPath();c.moveTo(width*i/12,0);c.lineTo(width*i/12,height);c.stroke();}
                    for(i=1;i<6;i++){c.beginPath();c.moveTo(0,height*i/6);c.lineTo(width,height*i/6);c.stroke();}
                }
            }
            Repeater {
                model: root.stats.markers || []
                delegate: Button {
                    id: markerButton
                    required property var modelData
                    objectName: "geo-marker-"+modelData.key
                    width: root.compact ? 18 : 28; height: width
                    x: Math.max(0,Math.min(world.width-width,modelData.x*world.width-width/2))
                    y: Math.max(0,Math.min(world.height-height,modelData.y*world.height-height/2))
                    hoverEnabled: true
                    Accessible.name: modelData.country+" · "+modelData.alerts+" "+root.tr("alertas")
                    background: Rectangle {
                        radius: width/2
                        color: markerButton.down ? "#b44bce" : markerButton.hovered || markerButton.activeFocus ? "#975ac0" : "#653967"
                        border.width: root.stats.selection_marker === markerButton.modelData.key ? 2 : 1
                        border.color: root.stats.selection_marker === markerButton.modelData.key ? "#ffffff" : "#fd82dc"
                        Rectangle { anchors.centerIn: parent; width: root.compact ? 6 : 10; height: width; radius: width/2; color: markerButton.modelData.critical > 0 ? "#ff657e" : "#f78ad9" }
                    }
                    contentItem: Item {}
                    ToolTip {
                        id: markerTip; visible: markerButton.hovered || markerButton.activeFocus; width: 300
                        text: modelData.country+" · "+modelData.alerts+" "+root.tr("alertas")+" · "+modelData.sources+" IP\n"+modelData.latitude+", "+modelData.longitude+"\n"+root.tr(modelData.source)
                        background: Rectangle { color:"#1b2940"; border.color:"#607089"; radius:5 }
                        contentItem: Text { text:markerTip.text; textFormat:Text.PlainText; color:"#e4eaf5"; wrapMode:Text.WordWrap; font.pixelSize:11 }
                    }
                    onClicked: root.markerSelected(modelData.key)
                }
            }
        }
    }
    Label { visible: !root.compact; anchors.left: parent.left; anchors.bottom: parent.bottom; anchors.margins: 8; text: "Natural Earth · "+root.tr("Sin consultas externas"); color: "#9faec4"; font.pixelSize: 10 }
    Row {
        visible: !root.compact; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: 8; spacing: 4
        Repeater {
            model: ["−", "+", "↺"]
            delegate: Button {
                required property string modelData
                width: 32; height: 30; text: modelData
                Accessible.name: modelData === "+" ? root.tr("Acercar mapa") : modelData === "−" ? root.tr("Alejar mapa") : root.tr("Restablecer mapa")
                onClicked: { root.zoom = modelData === "+" ? Math.min(4,root.zoom+0.5) : modelData === "−" ? Math.max(1,root.zoom-0.5) : 1; viewport.returnToBounds(); }
            }
        }
    }
}
