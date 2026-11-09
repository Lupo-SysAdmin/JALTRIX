# Primer inicio / First run — JALTRIX 1.2

Una instalación nueva abre el asistente, sin alertas simuladas. La demostración es una elección explícita. Instalar el paquete gráfico no descarga Snort ni activa captura.

## 1. Motor

El asistente busca el ejecutable configurado, `snort` en PATH y el motor administrado; ejecuta `-V` como el usuario del escritorio, con límite de tiempo. Distingue Snort 3, versiones incompatibles, ausencia y errores de ejecución. **Volver a detectar** comprueba otra vez después de instalarlo; **Seleccionar motor…** admite una ruta propia.

Si falta, abre la [guía oficial de instalación de Snort 3](https://docs.snort.org/start/installation) o las [descargas oficiales](https://www.snort.org/snort3). Sigue las dependencias y pasos de LibDAQ y Snort para tu distribución. Consulta la versión del paquete disponible antes de instalarlo: `snort` puede designar Snort 2, y no está disponible en todos los repositorios. JALTRIX no agrega repositorios ni ejecuta descargas con privilegios. La instalación del motor es manual, guiada mediante esos enlaces; no hay un instalador universal automático.

Comprueba `snort -V` y `snort --daq-list`. Para el servicio propio se exige Snort 3 instalado bajo `/usr` o `/opt`, archivo y directorios propiedad de root sin escritura de grupo/otros, DAQ `afpacket`, systemd, Polkit y `setfacl` (paquete `acl`). Un ejecutable en la carpeta personal se puede usar para reproducción sin privilegios, pero no para el servicio del sistema.

## 2. Sensor existente o nuevo

**Existente/externo:** conserva su servicio y reglas. Configura [alert_json en Snort 3](https://docs.snort.org/start/alert_logging) y conecta una copia local o un archivo local legible por tu usuario. No hace falta un motor local para analizar ese archivo. JALTRIX no inicia ni detiene servicios ajenos.

**Nuevo:** selecciona interfaz, HOME_NET en CIDR y pega reglas locales de Snort 3. Revisa la operación y autoriza con la ventana nativa del sistema. Se comprueba el motor, DAQ y reglas antes de escribir la configuración. El servicio usa una cuenta dedicada, captura pasiva y permisos limitados. Se crean `/etc/jaltrix`, `/var/log/jaltrix` y `jaltrix-sensor.service`; se concede lectura del registro al usuario que autorizó. El servicio queda detenido y sin arranque automático. No se incluye una colección de reglas de protección; la cobertura depende de las reglas y del tráfico visible.

Un perfil, servicio o directorio de registros existente no se sobrescribe. Si hay una instalación parcial, revisa sus archivos antes de volver a crearla. Un perfil existente tiene acceso a configurar interfaz/HOME_NET y revisar reglas. `lo` observa tráfico del propio equipo; no protege toda la red.

## 3. Alertas y arranque

**Iniciar servicio** y **Iniciar con el sistema** son decisiones independientes. Después pulsa **Conectar alertas de JALTRIX**, o selecciona un `alert_json` existente. Una lectura exitosa, incluso de un archivo vacío, permite abrir la consola real. No garantiza captura: un servicio activo y un archivo legible son estados distintos de haber detectado tráfico. Para verificar el recorrido completo, usa una regla y tráfico de laboratorio autorizados.

La última conexión LIVE leída correctamente se recuerda por usuario. Al reabrir se sigue el mismo archivo, sin iniciar ni habilitar servicios. Si falta o pierde permisos, el asistente muestra el problema y mantiene datos reales separados; no cambia a demo. La elección de demo también se recuerda. Una importación REPLAY no reemplaza la conexión LIVE guardada. Las instalaciones anteriores sin preferencia guardada ven el asistente una vez.

Puedes volver desde **Configuración → Asistente de configuración**, o `jaltrix --setup`. Cerrar la interfaz no detiene Snort. El recolector independiente conserva sus controles separados en Servicio.

# English

New installations open the setup assistant with no simulated alerts. Demo is an explicit, remembered choice. The GUI package does not bundle or automatically install Snort. The assistant checks the engine version, links to official installation instructions, and detects it again after manual installation. It can read local alerts from an external sensor without a local engine.

Keep an existing sensor and connect its readable `alert_json`, or create a separate JALTRIX sensor using a root-owned Snort 3 installation under `/usr` or `/opt`, afpacket, systemd, Polkit and `acl`. Supply the interface, HOME_NET and your local rules. Native authorization is required; validation precedes configuration writes. Existing profiles are preserved. No protection ruleset is bundled. Creation leaves capture and boot startup disabled; enable them independently.

A successful LIVE file connection is remembered. Missing or unreadable files show a setup error instead of demo data. Opening the GUI never starts the sensor automatically. Use Settings → Setup assistant or `jaltrix --setup` to revisit setup. Engine/service availability, readable alerts and confirmed packet detection are separate facts.
