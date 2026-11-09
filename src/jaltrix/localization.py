"""Qt-compatible catalog. es-419 is the source language; en-US is explicit."""

from PySide6.QtCore import QTranslator

EN_US = {
    "Ubicación sintética de demostración": "Synthetic demo location",
    "Mapa de amenazas": "Threat map",
    "Todos los países": "All countries",
    "DEMO · Ubicaciones simuladas; no representan actividad real.": "DEMO · Simulated locations; these do not represent real activity.",
    "IP de origen · Ubicación aproximada; no identifica al atacante.": "Source IP · Approximate location; it does not identify an attacker.",
    "alertas ubicadas": "located alerts",
    "sin ubicación": "not located",
    "Consulta completa": "Entire query",
    "Actualizando mapa…": "Updating map…",
    "Importa un CSV GeoIP para ubicar las IP públicas. Las IP privadas y desconocidas no se colocan en el mapa.": "Import a GeoIP CSV to locate public IPs. Private and unknown IPs are not placed on the map.",
    "Países · % de alertas ubicadas": "Countries · % of located alerts",
    "Sin ubicaciones": "No locations",
    "Marcadores visibles limitados a los 1000 más frecuentes. Los totales y las alertas incluyen todos.": "Markers are limited to the 1,000 most frequent. Totals and alerts include all locations.",
    "Explorar alertas": "Explore alerts",
    "Marcador seleccionado": "Selected marker",
    "Sin alertas geolocalizadas con estos filtros": "No geolocated alerts match these filters",
    "Selecciona un país o marcador; pulsa una alerta para abrir su inspector.": "Select a country or marker; click an alert to open its inspector.",
    "Sin consultas externas": "No external queries",
    "Acercar mapa": "Zoom in",
    "Alejar mapa": "Zoom out",
    "Restablecer mapa": "Reset map",
    "Explorar": "Explore",
    "DEMO · Ubicaciones simuladas": "DEMO · Simulated locations",
    "IP públicas · GeoIP local": "Public IPs · Local GeoIP",
    "Abrir mapa de amenazas": "Open threat map",
    "Categorías de demostración": "Demonstration categories",
    "Clasificación original de Snort": "Original Snort classification",
    "Sensor local": "Local sensor",
    "Modo": "Mode",
    "Interfaz configurada": "Configured interface",
    "Recolector": "Collector",
    "Última alerta UTC": "Last alert UTC",
    "Estado del servicio local; no confirma captura de paquetes.": "Local service status; this does not confirm packet capture.",
    "DEMO, lectura LIVE o importación REPLAY.": "DEMO, LIVE file reading or REPLAY import.",
    "Interfaz del perfil local; no es una confirmación de captura.": "Local profile interface; this does not confirm packet capture.",
    "Recolector independiente del usuario; no es el motor de captura.": "Independent user collector; this is not the capture engine.",
    "Sin tiempo de alerta disponible para esta fuente.": "No alert time is available for this source.",
    "Dashboard": "Dashboard",
    "Alertas": "Alerts",
    "Investigación / Casos": "Investigation / Cases",
    "Tráfico": "Traffic",
    "PCAP": "PCAP",
    "Reglas": "Rules",
    "Topología": "Topology",
    "Correlación MITRE": "MITRE Mapping",
    "Respuesta / Firewall": "Response / Firewall",
    "EDR / Endpoints": "EDR / Endpoints",
    "Reportes": "Reports",
    "Configuración": "Settings",
    "Todas": "All",
    "Crítica": "Critical",
    "Alta": "High",
    "Media": "Medium",
    "Baja": "Low",
    "Web": "Web",
    "SSH": "SSH",
    "DNS": "DNS",
    "Malware": "Malware",
    "Escaneo": "Scanning",
    "15 minutos": "15 minutes",
    "1 hora": "1 hour",
    "24 horas": "24 hours",
    "Jan Herrera  /  Consola para Snort 3": "Jan Herrera  /  Console for Snort 3",
    "Buscar IP, firma, SID…   Ctrl+K": "Search IP, signature, SID…   Ctrl+K",
    "Buscar alertas": "Search alerts",
    "ESPACIO DE TRABAJO": "WORKSPACE",
    "Pendiente de implementación; no disponible en este hito": "Not implemented yet; unavailable in this milestone",
    "●  MODO DEMO": "●  DEMO MODE",
    "Captura desactivada": "Capture disabled",
    "Motor no conectado": "Engine not connected",
    "LOCAL  /  DEMOSTRACIÓN": "LOCAL  /  DEMONSTRATION",
    "Interfaz: —     Reglas cargadas: —     Paquetes/s: —": "Interface: —     Loaded rules: —     Packets/s: —",
    "Alertas filtradas": "Filtered alerts",
    "Críticas · demo": "Critical · demo",
    "Casos demo guardados": "Saved demo cases",
    "Fuentes en la consulta": "Sources in query",
    "Severidad": "Severity",
    "Categoría": "Category",
    "Intervalo de la demostración": "Demonstration time range",
    "Ocultar inspector": "Hide inspector",
    "Ver inspector": "Show inspector",
    "ALERTAS DE DETECCIÓN  ·  ": "DETECTION ALERTS  ·  ",
    "HORA UTC": "UTC TIME",
    "SEVERIDAD": "SEVERITY",
    "FIRMA / ORIGEN → DESTINO": "SIGNATURE / SOURCE → DESTINATION",
    "No hay alertas con estos filtros": "No alerts match these filters",
    "Selección conservada al filtrar · Datos sintéticos · UTC": "Selection retained while filtering · Synthetic data · UTC",
    "INSPECTOR DEL EVENTO": "EVENT INSPECTOR",
    "  ·  Acción simulada": "  ·  Simulated action",
    "Firma": "Signature",
    "Origen": "Source",
    "Destino": "Destination",
    "Protocolo": "Protocol",
    "Fecha UTC": "UTC date",
    "Estado": "Status",
    "Nuevo": "New",
    "Procedencia": "Provenance",
    "Fixture determinista v1": "Deterministic fixture v1",
    "EVIDENCIA": "EVIDENCE",
    "Sin PCAP ni payload asociado.\nMITRE ATT&CK: sin mapeo.": "No associated PCAP or payload.\nMITRE ATT&CK: no mapping.",
    "Abrir / crear caso demo": "Open / create demo case",
    "PCAP · Firewall · EDR · Allowlist\nBlocklist · Crear regla\nNo disponibles en este hito": "PCAP · Firewall · EDR · Allowlist\nBlocklist · Create rule\nUnavailable in this milestone",
    "Alertas por intervalo · página actual": "Alerts per interval · current page",
    "Intervalos de ": "Intervals of ",
    " min · tráfico no medido": " min · traffic not measured",
    "Fuentes más frecuentes · demo": "Most frequent sources · demo",
    " alertas": " alerts",
    "Casos locales de demostración": "Local demonstration cases",
    "Persisten al cerrar la aplicación. Abre o crea un caso desde el inspector.": "Saved when you close the application. Open or create a case from the inspector.",
    "Todavía no hay casos demo": "No demo cases yet",
    "Exportación con procedencia": "Export with provenance",
    "Entorno y capacidades": "Environment and capabilities",
    "Exporta la consulta actual: ": "Export the current query: ",
    " alertas demo.\nIncluye filtros, zona horaria y origen de los registros.": " demo alerts.\nIncludes filters, time zone, and record provenance.",
    "Motor: ": "Engine: ",
    "\nModo actual: demostración aislada\nCaptura: desactivada\nRespuesta activa: no implementada\nIdioma: español\nAlmacenamiento: directorio XDG del usuario, separado por modo": "\nCurrent mode: isolated demonstration\nCapture: disabled\nActive response: not implemented\nLanguage: American English\nStorage: user XDG directory, separated by mode",
    "Guardar JSON…": "Save JSON…",
    "Plataformas objetivo\nKali · Parrot · Ubuntu · Fedora · Arch Linux\nLa compatibilidad se publicará por versión probada.": "Target platforms\nKali · Parrot · Ubuntu · Fedora · Arch Linux\nCompatibility will be published per tested version.",
    "SOLO LECTURA DE RED   /   Ninguna integración externa activa                                     Jan Herrera · Desarrollo 0.3": "READ-ONLY NETWORK   /   No active external integrations                                     Jan Herrera · Development 0.3",
    "Snort no instalado": "Snort not installed",
    "Instalado; conexión no configurada": "Installed; connection not configured",
    "Solicitud web de laboratorio": "Lab web request",
    "Intentos SSH de laboratorio": "Lab SSH attempts",
    "Consulta DNS de laboratorio": "Lab DNS query",
    "Firma sintética de laboratorio": "Synthetic lab signature",
    "Conexiones repetidas de laboratorio": "Repeated lab connections",
    "DATOS DE DEMOSTRACIÓN  ·  Fixture del 09 nov 2026, UTC  ·  Sin captura ni cambios de red": "DEMONSTRATION DATA  ·  November 9, 2026 fixture, UTC  ·  No capture or network changes",
    "Exportar alertas de demostración": "Export demonstration alerts",
    "Acerca de": "About",
    "Cerrar": "Close",
    "Desarrollador": "Developer",
    "Licencia del proyecto": "Project license",
    "Abrir mi GitHub": "Open my GitHub",
    "Español latinoamericano": "Latin American Spanish",
    "Inglés estadounidense": "American English",
    "Aplicación independiente para Snort 3. Snort, Qt y PySide6 conservan sus autores y licencias.": "Independent application for Snort 3. Snort, Qt, and PySide6 retain their authors and licenses.",
    "Sin garantía. Consulta el texto completo de la licencia.": "No warranty. See the full license text.",
    "Caso guardado: %1": "Case saved: %1",
    "No se pudo guardar el caso: %1": "Could not save case: %1",
    "Exportadas %1 alertas": "Exported %1 alerts",
    "Exportación fallida: %1": "Export failed: %1",
    "No se pudo abrir el navegador.": "Could not open the browser.",
}


class Translator(QTranslator):
    def __init__(self, locale="es-419"):
        super().__init__()
        self.locale = locale

    def isEmpty(self):
        return False

    def translate(self, context, sourceText, disambiguation=None, n=-1):
        if sourceText not in EN_US:
            return None
        return (
            EN_US[sourceText]
            if self.locale == "en-US"
            else ES_419.get(sourceText, sourceText)
        )

    def text(self, value):
        return (
            EN_US.get(value, value)
            if self.locale == "en-US"
            else ES_419.get(value, value)
        )


EN_US.update(
    {
        "Datos de demostración": "Demonstration data",
        "Sin selección": "No selection",
        "Sin información": "No information",
        "Selecciona un archivo local.": "Select a local file.",
        "Leyendo archivo…": "Reading file…",
        "Registros inválidos en cuarentena": "Invalid records quarantined",
        "Archivo leído; estado del sensor no verificado": "File read; sensor state not verified",
        "Error de lectura": "Read error",
        "Importar alert_json…": "Import alert_json…",
        "Seguir archivo en vivo…": "Follow live log…",
        "Volver a demo": "Return to demo",
        "Seleccionar alertas JSON de Snort": "Select Snort JSON alerts",
        "LECTURA DE ARCHIVO  ·  Sin captura propia  ·  Salud del sensor no verificada": "LOG FILE MODE  ·  No application capture  ·  Sensor health not verified",
        "REPRODUCCIÓN / IMPORTACIÓN  ·  Alertas reales del archivo seleccionado": "REPLAY / IMPORT  ·  Real alerts from the selected file",
        "Registros guardados: ": "Stored records: ",
        " · Vista limitada a 10.000 registros recientes": " · View limited to 10,000 recent records",
        "Críticas": "Critical",
        "Casos guardados": "Saved cases",
        "Abrir / crear caso": "Open / create case",
        "Casos locales": "Local cases",
        "Todavía no hay casos": "No cases yet",
        "Fuentes más frecuentes": "Most frequent sources",
        "Selección conservada al filtrar · UTC cuando está disponible": "Selection retained while filtering · UTC when available",
        "Acción reportada: ": "Reported action: ",
        "Tiempo: ": "Time: ",
        "Prioridad Snort: ": "Snort priority: ",
        "unknown": "unknown",
        "Epoch o zona horaria explícita; si faltan, el tiempo queda desconocido.": "Epoch or explicit time zone; otherwise event time remains unknown.",
    }
)
EN_US.update(
    {
        "Selecciona primero un archivo de reglas.": "Select a rules file first.",
        "Validando reglas y procesando PCAP…": "Validating rules and processing PCAP…",
        "Seleccionar PCAP para reproducción offline": "Select PCAP for offline replay",
        "Seleccionar reglas locales": "Select local rules",
        "Reproducción offline con Snort 3": "Offline replay with Snort 3",
        "Se valida la configuración y se procesa una copia del PCAP. No se captura tráfico ni se modifica el servicio del sistema.": "The configuration is validated and a copy of the PCAP is processed. No traffic is captured and the system service is not modified.",
        "Reglas: ": "Rules: ",
        "Seleccionar reglas…": "Select rules…",
        "Procesar PCAP…": "Process PCAP…",
        "Paquetes: ": "Packets: ",
        "Sin PCAP importado": "No PCAP imported",
        "Ver alertas": "View alerts",
        "PCAP clásico, hasta 1 GiB. PCAPNG pendiente. Verificación de checksum desactivada en replay; la procedencia conserva este ajuste.": "Classic PCAP, up to 1 GiB. PCAPNG pending. Checksum validation is disabled for replay; provenance records this setting.",
        "Proveedor no configurado": "Provider not configured",
        "El aislamiento y la restauración requieren un proveedor EDR con endpoints administrados y capacidades verificadas.": "Isolation and restoration require an EDR provider with managed endpoints and verified capabilities.",
        "Aislar host": "Isolate host",
        "Restaurar conectividad": "Restore connectivity",
    }
)
EN_US.update(
    {
        "Notas de investigación": "Investigation notes",
        "Guardar": "Save",
        "new": "New",
        "investigating": "Investigating",
        "resolved": "Resolved",
        "closed": "Closed",
    }
)
ES_419 = {
    "new": "Nuevo",
    "investigating": "En investigación",
    "resolved": "Resuelto",
    "closed": "Cerrado",
}
EN_US.update(
    {
        "Seleccionar ejecutable Snort": "Select Snort executable",
        "Seleccionar motor…": "Select engine…",
        "Borrador de regla local": "Local rule draft",
        "Guardar borrador y validar": "Save draft and validate",
        "Regla válida": "Valid rule",
        "Regla rechazada": "Rule rejected",
        "Validación con Snort -T en un perfil aislado. No despliega reglas ni reinicia sensores.": "Validated with Snort -T in an isolated profile. Does not deploy rules or restart sensors.",
    }
)
EN_US.update(
    {
        "Prioridad Snort": "Snort priority",
        "Tiempo original": "Original time",
        "Confianza temporal": "Timestamp confidence",
        "epoch_seconds": "Epoch seconds",
        "explicit_timezone": "Explicit time zone",
    }
)
ES_419.update(
    {
        "unknown": "Desconocida",
        "epoch_seconds": "Segundos desde epoch",
        "explicit_timezone": "Zona horaria explícita",
    }
)
EN_US.update(
    {
        "Propuestas de respuesta": "Response proposals",
        "Motivo de la propuesta": "Reason for proposal",
        "Guardar propuesta": "Save proposal",
        "Aplicar al firewall": "Apply to firewall",
        "Revocar": "Revoke",
        "Sólo candidatos locales: no bloquean tráfico ni silencian alertas. Caducan en 1 hora. Firewall no configurado.": "Local candidates only: they do not block traffic or suppress alerts. They expire in 1 hour. Firewall not configured.",
        "Propuesta guardada; ningún cambio de red aplicado.": "Proposal saved; no network changes applied.",
        "Crear regla": "Create rule",
        "Enviar a firewall": "Send to firewall",
        "CANDIDATE": "CANDIDATE",
        "REVOKED": "REVOKED",
        "EXPIRED": "EXPIRED",
    }
)
ES_419.update({"CANDIDATE": "CANDIDATO", "REVOKED": "REVOCADO", "EXPIRED": "VENCIDO"})
EN_US["Exportar CSV"] = "Export CSV"
EN_US["Registro parcial; esperando fin de línea"] = (
    "Partial record; waiting for end of line"
)

EN_US.update(
    {
        key: key
        for key in [
            "Cancel",
            "Open",
            "Save",
            "Close",
            "Folder",
            "File name",
            "File type",
        ]
    }
)
ES_419.update(
    {
        "Cancel": "Cancelar",
        "Open": "Abrir",
        "Save": "Guardar",
        "Close": "Cerrar",
        "Folder": "Carpeta",
        "File name": "Nombre de archivo",
        "File type": "Tipo de archivo",
    }
)

EN_US.update(
    {
        "Servicio": "Service",
        "Servicio del sensor": "Sensor service",
        "Perfil administrado en /etc/jaltrix. El perfil inicial usa lo y una regla de laboratorio; no protege toda la red.": "Managed profile in /etc/jaltrix. The initial profile uses lo and a lab rule; it does not protect the entire network.",
        "Administrar servicio real": "Manage real service",
        "Estado: ": "Status: ",
        "Arranque: ": "Startup: ",
        "Iniciar servicio": "Start service",
        "Detener servicio": "Stop service",
        "Iniciar con el sistema": "Start at system boot",
        "Detener no cambia el arranque automático. La interfaz solicita autorización al sistema y verifica el resultado.": "Stopping does not change automatic startup. The application requests system authorization and verifies the result.",
        "Actualizar estado": "Refresh status",
        "Ver alertas del servicio": "View service alerts",
        "Servicio del sistema seleccionado": "System service selected",
        "El modo demo no modifica servicios.": "Demo mode does not modify services.",
        "active": "Running",
        "inactive": "Stopped",
        "failed": "Failed",
        "enabled": "Enabled",
        "disabled": "Disabled",
        "El estado del servicio cambió. Actualiza y vuelve a intentar.": "Service state changed. Refresh and try again.",
        "El servicio no está instalado o no se puede administrar.": "The service is not installed or cannot be managed.",
        "El servicio no alcanzó el estado solicitado. Revisa el registro del sistema.": "The service did not reach the requested state. Check the system journal.",
    }
)
ES_419.update(
    {
        "active": "En ejecución",
        "inactive": "Detenido",
        "failed": "Falló",
        "enabled": "Habilitado",
        "disabled": "Deshabilitado",
    }
)

EN_US.update(
    {
        "Información legal y componentes": "Legal information and components",
        "Información legal": "Legal information",
        "Componentes y licencias": "Components and licenses",
        "Abrir fuente del componente": "Open component source",
    }
)

EN_US.update(
    {
        " · Consultas paginadas de 500 registros": " · Queries paged in batches of 500 records",
        "Abrir copia en aplicación externa": "Open copy in external application",
        "Anterior": "Previous",
        "Siguiente": "Next",
        "Buscar": "Search",
        "Cancelar": "Cancel",
        "alertas": "alerts",
        "Asociación heurística versionada por gid:sid:rev. No confirma ejecución ni compromiso. Verifica el identificador en MITRE ATT&CK.": "Versioned heuristic association by gid:sid:rev. It does not confirm execution or compromise. Verify the identifier in MITRE ATT&CK.",
        "Base GeoIP local": "Local GeoIP database",
        "Buscar paquete por IP, puerto o protocolo": "Find packet by IP, port or protocol",
        "Conectar a recolector": "Connect to collector",
        "Conexiones observadas": "Observed connections",
        "Configurar interfaz y HOME_NET": "Configure interface and HOME_NET",
        "Confirmar operación administrada": "Confirm managed operation",
        "Confirmar y autorizar": "Confirm and authorize",
        "Contadores del sistema: incluyen tráfico ajeno a Snort. No acreditan captura ni protección del sensor.": "System counters include traffic unrelated to Snort. They do not certify sensor capture or protection.",
        "Continúa al cerrar la ventana. Inicio automático al iniciar sesión; no equivale al servicio de captura.": "Continues after closing the window. Starts automatically at login; separate from the capture service.",
        "Detener recolector": "Stop collector",
        "El borrador se valida de forma aislada. Desplegar requiere previsualización y autorización; conserva copia para restaurar.": "Drafts are validated in isolation. Deployment requires preview and authorization; a rollback copy is retained.",
        "Esperando dos muestras válidas": "Waiting for two valid samples",
        "Evidencia y justificación del mapeo": "Mapping evidence and rationale",
        "Explorar captura": "Explore capture",
        "Gráficas y exportación: página actual": "Charts and export: current page",
        "Guardar revisión del mapeo": "Save mapping revision",
        "Iniciar recolector": "Start collector",
        "Justificación": "Justification",
        "Las propuestas no bloquean. El adaptador activo opera solo en el laboratorio aislado jaltrix-lab; no modifica el firewall del host.": "Proposals do not block. The active adapter operates only in the isolated jaltrix-lab namespace; it does not change the host firewall.",
        "Mapeos ATT&CK del analista": "Analyst ATT&CK mappings",
        "Nombre de técnica verificado": "Verified technique name",
        "PCAP/PCAPNG hasta 1 GiB. Replay sin verificación de checksum. PCAPNG con timestamps y un único tipo de enlace.": "PCAP/PCAPNG up to 1 GiB. Replay without checksum validation. PCAPNG requires timestamps and a single link type.",
        "Perfil de captura administrado": "Managed capture profile",
        "Previsualizar bloqueo de laboratorio": "Preview lab block",
        "Previsualizar configuración": "Preview configuration",
        "Previsualizar despliegue": "Preview deployment",
        "Recolector independiente": "Independent collector",
        "Relaciones origen/destino de las alertas de la página actual. No descubre equipos, rutas ni infraestructura.": "Source/destination relationships from alerts on the current page. Does not discover devices, routes or infrastructure.",
        "Restaurar perfil anterior": "Restore previous profile",
        "Retirar bloqueo de laboratorio": "Remove lab block",
        "Revisa destino, cambios y justificación. El sistema solicitará autorización y verificará el resultado.": "Review the target, changes and justification. The system will request authorization and verify the result.",
        "Seleccionar interfaz": "Select interface",
        "Solo modifica /etc/jaltrix. Reinicia el sensor si está activo. Valida antes de aplicar y restaura ante fallos.": "Only modifies /etc/jaltrix. Restarts the sensor if active. Validates before applying and restores on failure.",
        "Tráfico de interfaz local": "Local interface traffic",
        "Ubicaciones aproximadas; solo IP públicas. Sin consultas externas.": "Approximate locations; public IPs only. No external queries.",
        "Verificar bloqueo de laboratorio": "Verify lab block",
        "Sin conexión": "Disconnected",
        "following": "Following",
        "reading": "Reading",
        "low": "Low",
        "medium": "Medium",
        "high": "High",
    }
)
ES_419.update(
    {
        "following": "Siguiendo archivo",
        "reading": "Leyendo",
        "low": "Baja",
        "medium": "Media",
        "high": "Alta",
    }
)
EN_US.update(
    {
        "Investigar alerta": "Investigate alert",
        "Etiquetas separadas por coma": "Comma-separated tags",
        "Marcar alerta": "Bookmark alert",
        "false_positive": "False positive",
    }
)
ES_419["false_positive"] = "Falso positivo"
EN_US.update(
    {
        "Excepción de triage: ": "Triage exception: ",
        "Anotar excepción para firma seleccionada": "Annotate exception for selected signature",
        "ACTIVE_TRIAGE": "TRIAGE ANNOTATION",
    }
)
ES_419["ACTIVE_TRIAGE"] = "ANOTACIÓN DE TRIAGE"
EN_US.update(
    {
        "Retención de alertas LIVE": "LIVE alert retention",
        "El recolector eliminará alertas antiguas según su fecha de ingesta. Conserva las vinculadas a casos. 0 desactiva la limpieza. No elimina PCAP ni cuarentena.": "The collector will delete old alerts by ingestion date. Alerts linked to cases are retained. 0 disables cleanup. PCAP and quarantine are not deleted.",
        "Confirmar retención en días": "Confirm retention in days",
        "Retención": "Retention",
        "Retención guardada": "Retention saved",
        "Paquete asociado": "Associated packet",
    }
)
EN_US["Grafo: hasta 24 IP; lista: hasta 200 relaciones de la página actual."] = (
    "Graph: up to 24 IPs; list: up to 200 relationships from the current page."
)
EN_US["Registro del sensor"] = "Sensor log"
EN_US.update(
    {
        "Las propuestas no bloquean. Elige laboratorio o este host. El host requiere política de destinos autorizada; protege IP locales, gateway y DNS.": "Proposals do not block. Choose lab or this host. Host operations require an authorized target policy; local IPs, gateways and DNS are protected.",
        "Destinos permitidos: CIDR separados por coma": "Allowed targets: comma-separated CIDRs",
        "Habilitar respuesta en este host": "Enable response on this host",
        "Previsualizar política": "Preview policy",
        "Previsualizar bloqueo": "Preview block",
        "Verificar bloqueo": "Verify block",
        "Retirar bloqueo": "Remove block",
    }
)
EN_US["source_missing"] = "Source removed; holding previous file"
ES_419["source_missing"] = "Archivo retirado; conservando descriptor anterior"
EN_US["Tabla paginada; mapa y exportación: consulta completa"] = (
    "Paged table; map and export: entire query"
)

EN_US.update(
    {
        "Guardar copia de seguridad": "Save backup",
        "Copia de seguridad guardada: ": "Backup saved: ",
        "Exportar alertas": "Export alerts",
    }
)
