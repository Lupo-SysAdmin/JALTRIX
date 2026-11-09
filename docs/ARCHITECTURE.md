# Arquitectura actual — 1.0.0

PySide6/QML sin privilegios, modelos virtualizados y tareas de ingesta/replay/operaciones fuera del hilo gráfico. `app.py` coordina consultas y revisiones; `advanced.py` expone explorador, telemetría, contexto y planes de respuesta. Se conserva el contrato de eventos normalizado de `snort.py`.

`collector.py` es un proceso sin Qt, independiente de la ventana, con unidad systemd de usuario y lock. `AlertStore` ofrece checkpoints, consultas SQL paginadas y retención. `reporting.py` recorre una instantánea de consulta para exportación completa. Triage, casos, propuestas y mapeos usan almacenes separados por modo. Capturas originales se copian y verifican antes de replay; `capture.py` analiza formatos sin ejecutar contenido.

`operations.py` prepara diffs y peticiones; `privileged.py`, instalado y propiedad de root, limita cambios a perfil administrado y tabla nft propia. Autenticación Polkit, precondiciones y validación backend. La aplicación no ejecuta una terminal arbitraria: el panel inferior lee journal acotado. EDR conserva contrato de capacidades y denegación por defecto.

`backup.py` genera snapshots SQLite mediante su API de backup, conserva hashes por archivo y restaura sólo en carpetas nuevas. La ingesta usa BEGIN IMMEDIATE para serializar checkpoints entre procesos; índices de SID permiten consultas numéricas sin decodificar toda la fuente.

## Registro histórico de diseño

# Estado de arquitectura — actualización 0.2.0

La base inicial de abajo es un registro histórico del primer incremento. Actualmente existen adaptadores `snort.py` (JSON/checkpoints), `engine.py` (PCAP/replay/validación), `localization.py`, `response.py` (propuestas/audit) e `integrations/edr.py` (contrato y rechazo por defecto). Un executor de un hilo realiza la lectura/ejecución fuera de la UI; cada tarea abre su propia conexión SQLite. La UI recibe el resultado mediante timer de Qt. Se mantiene el modelo QML virtualizado.

La ingesta sigue ligada a la ventana: el servicio independiente, paginación SQL, retención, métricas y control activo todavía están pendientes. Ver README, SNORT_SETUP y RESPONSE_ENGINE para capacidades actuales. El motor 3.13.2.0 ya está compilado en un prefijo privado con parches documentados, sin captura del host.

Los idiomas es-419/en-US usan catálogo y QTranslator con IDs estables separados del texto presentado; las preferencias se guardan con QSettings. Acerca de lleva autoría Jan Herrera, perfil GitHub y GPL-3.0-or-later local.

---

# Arquitectura y decisiones — 2026-11-09

## Inspección

Repositorio vacío con Git inicializado, sin commits. Host Kali 2026.3 amd64, Python 3.14.8, PySide6 6.10.3, Qt 6.10.2. Snort desinstalado en la tarea anterior. QEMU, virsh y `/dev/kvm` disponibles; 62 GiB de memoria y aproximadamente 140 GiB libres. No se han creado máquinas virtuales.

## Decisión de interfaz

Python + PySide6 + Qt Quick/QML, sin servidor web. QML permite mantener el diseño solicitado; QAbstractListModel limita los delegados a la ventana visible. El prototipo actual mantiene la colección demo en memoria: virtualizar la vista no equivale a paginar una base de datos. La ingesta real requerirá consultas paginadas, agregaciones SQL e hilos/procesos fuera del hilo UI.

Separación actual: `core.py` contiene fixtures, filtros/agregados y almacenamiento demo; `app.py` adapta los datos a Qt; `ui/Main.qml` presenta la interfaz. Estos módulos se dividirán por dominio cuando se incorporen adaptadores reales, evitando anticipar carpetas vacías.

## Contrato futuro de detección

AlertEvent: source_id, event_id, observed_at, ingested_at, original_timestamp, timestamp_confidence, gid, sid, rev, src_ip, src_port, dst_ip, dst_port, protocol, message, classification, priority, action, raw_record y mode. Campos ausentes nulos. Separar prioridad Snort, severidad derivada y estado de triage.

Identidad de ingesta: fuente + generación de archivo + posición del registro; persistir checkpoint y evento en una misma transacción. Considerar rotación rename/copytruncate, línea incompleta, cuarentena, reinicios y límites de recursos. Una alerta repetida legítima no debe eliminarse por compartir SID/IP.

Motor como proceso separado. Perfiles: conectar instalación existente o instancia administrada con configuración/servicio propios. No modificar automáticamente `/etc/snort`. Primero validar el recorrido offline con un PCAP benigno y una regla de laboratorio.

Versión inicial candidata: Snort 3.13.2.0, consultada en https://www.snort.org/downloads y https://github.com/snort3/snort3/releases/tag/3.13.2.0. No instalada ni probada en este hito. Revisar dependencias y reglas compatibles antes de construir. Logger: https://docs.snort.org/start/alert_logging. Qt: https://doc.qt.io/qtforpython-6/PySide6/QtQml/QQmlApplicationEngine.html.

## Respuesta e investigación

El núcleo futuro separará política, planificación, ejecución, verificación y reversión de la UI. Contratos requeridos: ResponseCommand, ActionTarget, Capability, PolicyDecision, ActionPlan, ExecutionResult, VerificationResult, RollbackPlan, AuditEvent y CaseRecord. No implementados todavía.

Cada operación persistirá identidad, actor, alcance, justificación, clave de idempotencia y referencias de evidencia. Estados: unavailable, planned, awaiting approval, queued, running, verified, failed, partial, unknown, reverted y expired. El cierre de la UI no cancelará inadvertidamente un TTL o una reversión: jobs persistentes en servicio separado.

Orden: PCAP y casos; excepciones de triage y reglas en borrador; nftables en laboratorio aislado; proveedor EDR seleccionado después de verificar API y disponibilidad. No confundir IP de alerta con identidad de endpoint. Secretos en almacén del sistema, helper mínimo Polkit, GUI sin root. Las operaciones de laboratorio autorizadas se automatizarán sin solicitudes redundantes; los límites reales del sistema se informarán.

## Secuencia de entregas

1. Incrementos de UI demo y accesibilidad, contratos y pruebas (actual).
2. Snort offline real → JSON → persistencia → consulta → exportación; fixtures capturados del motor real.
3. Ingesta continua, recuperación y salud de sensor.
4. PCAP, casos completos, reglas, MITRE y topología observada.
5. Motor de respuesta, políticas y adaptadores probados.
6. EDR real sujeto a laboratorio/proveedor.
7. Paquetes DEB/RPM/PKGBUILD y pruebas por distribución; publicación GitHub con evidencia.

El proyecto completo y los gates de la especificación no están completados por este primer incremento.
