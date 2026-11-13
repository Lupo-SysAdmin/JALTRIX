# Observabilidad local de Linux — diseño 1.3.0

JALTRIX amplía la investigación de Snort con eventos locales de Linux. El alcance de esta entrega es journald, registros existentes de auditd, un formato común y tres correlaciones explicables. osquery, Falco, agentes remotos y nuevos motores de respuesta quedan para entregas posteriores.

## Compatibilidad y aislamiento

- Las bases, identificadores, checkpoints y casos de Snort 1.2.0 se conservan.
- Los eventos adicionales usan `live/host-events.sqlite3`; su recolector es independiente del recolector de Snort y de la ventana.
- Las fuentes nuevas están deshabilitadas por defecto. El modo demo no consulta eventos locales reales.
- Lectura con permisos del operador. No se instala auditd, no se reemplazan reglas del administrador y no se cambia el firewall al activar observabilidad.
- Relacionar alertas Snort con el equipo local requiere una asociación explícita de la fuente seleccionada. Una dirección IP no constituye identidad fiable de un equipo.

## Modelo y correlación

Se conservan identidad de la fuente, identidad del equipo, fecha UTC y confianza temporal, actor, proceso, archivo, dirección de red, resultado y registro original. Los campos desconocidos no se inventan. Las fechas ausentes y los actores ambiguos no producen coincidencias positivas.

Las reglas previstas son:

1. Cinco o más fallos SSH y posterior acceso exitoso del mismo usuario, IP y equipo dentro de cinco minutos.
2. Acceso SSH y operación auditada exitosa de escritura o metadatos sobre `authorized_keys` por el mismo actor y equipo dentro de diez minutos.
3. Alerta Snort de tráfico hacia SSH, acceso SSH exitoso desde esa IP y uso posterior de sudo por el mismo usuario/equipo dentro de diez minutos. Requiere asociación explícita del sensor al equipo.

Cada resultado conserva las evidencias y explica la ventana y los campos relacionados. Una correlación es una hipótesis de investigación, no una demostración automática de intrusión. Crear un caso reutiliza los casos existentes y protege sus evidencias frente a la retención. Ninguna correlación ejecuta bloqueos, aislamiento ni comandos de respuesta.

## Criterios de publicación

La entrega debe validar migración sin cambios en los datos anteriores, separación de modos, fuentes inaccesibles, reinicio/rotación, deduplicación, eventos tardíos, límites de retención y consumo, casos con evidencia protegida, falsos positivos entre equipos/usuarios y traducción ES/EN. Las pruebas con fixtures se distinguirán de las pruebas reales de journald/auditd y de las comprobaciones de paquetes por distribución.

## Uso del módulo (ES)

En modo LIVE, abre **Eventos del sistema → Fuentes**. Selecciona las fuentes que ya existan en tu equipo, guarda la configuración y arranca el recolector. Este servicio es independiente del sensor y de la recolección de alertas Snort. Iniciarlo habilita su arranque al iniciar sesión; detenerlo también deshabilita ese arranque. Cerrar la ventana con Ctrl+Q no detiene los servicios independientes.

- **Journal de Linux:** lee los registros accesibles de journald mediante `journalctl`, con los permisos de tu cuenta. En el primer inicio consulta los últimos 15 minutos; después continúa desde el cursor guardado. Los registros antiguos anteriores a esa ventana no se importan automáticamente. Si el journal eliminó un cursor, se informa del problema en lugar de saltarlo silenciosamente.
- **auditd:** elige un registro local existente y legible. Es lectura de registros, no instalación ni configuración de auditd. Sin reglas de auditoría adecuadas, el archivo puede contener autenticaciones y no contener operaciones sobre archivos o procesos. Un acceso de escritura registrado no acredita por sí solo un cambio de contenido. Una cuenta sin permiso verá el diagnóstico correspondiente; JALTRIX no se ejecuta como root para eludirlo.
- **Snort:** selecciona una fuente LIVE y confirma expresamente que pertenece al equipo local antes de relacionarla con sus eventos. No asocies un sensor que observa otros equipos: una alerta hacia el puerto 22 no demuestra que el equipo local sea el destino.

Las pestañas permiten buscar eventos, ver el equipo observado, examinar las correlaciones y abrir un caso con su cronología y registros originales. El inventario muestra equipos presentes en estas fuentes locales; no descubre ni administra endpoints remotos. Las fuentes y los casos reales no aparecen en modo demo.

Retención inicial de esta base adicional: 30 días y 100.000 eventos; los eventos fijados por casos se conservan aunque eso supere el límite. La política de retención de alertas Snort no cambia. Los datos de journal/audit pueden contener nombres de usuario, rutas y argumentos de comandos: protege las copias de seguridad y no las publiques en GitHub. La copia de seguridad existente incluye también esta base SQLite y su configuración.

Para diagnosticar acceso, ejecuta como tu usuario `journalctl -n 5 --no-pager` y comprueba que puedes leer el archivo audit elegido. Si no tienes permisos, pide al administrador acceso de lectura según la política de tu distribución. Pertenecer a un grupo como `adm` o `systemd-journal` puede otorgar lectura de muchos registros del sistema; no es un permiso limitado a JALTRIX. El cambio de grupo requiere una sesión nueva. El software nunca añade grupos ni permisos automáticamente.

Referencias de los proveedores: [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html), [auditctl](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8) y [auditd.conf](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditd.conf.5).

## Operation (EN)

In LIVE mode, open **System events → Sources**. Select existing local sources, save their configuration and start the separate collector. Starting enables it at user login; stopping also disables that autostart. Closing the desktop window does not stop independent services.

Journal collection starts with the previous 15 minutes, then resumes its saved cursor. Access is limited by your account's permissions. Missing or expired journal cursors are reported rather than silently skipped. auditd ingestion reads an existing local regular log file: the administrator must separately arrange auditd, appropriate audit rules and read permission. A writable open or metadata operation does not prove file-content modification. Do not select another machine's audit log as local evidence.

Snort correlations require an explicit association of the selected LIVE source with this machine. A sensor observing other machines must not be bound to the local host merely because its alerts mention SSH. Correlations are investigatory leads based on identity and time, not automatic proof of compromise. They never block an address or isolate a machine.

The event, host and correlation tabs expose original evidence and links to existing cases. Inventory is restricted to observed local evidence, with no remote agent or network discovery. Real observations stay hidden in demo mode. Host-event retention defaults to 30 days and 100,000 events, while evidence pinned to cases remains protected. The separate Snort retention policy is unchanged. Existing backups include the new database; protect them because logs may contain usernames, paths and command arguments.

No new root helper, automatic audit rules, broad permission grants, cloud upload, osquery, Falco or remote EDR is included in this stage.

## Límites de consulta y correlación

La vista muestra hasta 100 correlaciones recientes; los eventos originales se consultan por páginas de 100. La regla que enlaza red, SSH y sudo evalúa como máximo los 64 accesos SSH más recientes del usuario dentro de su ventana de diez minutos, para limitar el trabajo ante ráfagas. Las tres reglas no cubren todas las técnicas ni sustituyen una revisión manual. El trabajo pendiente de correlación se conserva y continúa en los siguientes ciclos del recolector.

The UI lists up to 100 recent correlations and pages original observations by 100. The network/SSH/sudo rule considers at most the most recent 64 matching SSH logins in its ten-minute window. This is a bounded investigation aid, not complete detection coverage. Pending correlation work persists across collector cycles and restarts.
