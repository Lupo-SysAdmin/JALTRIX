# Cambios

## 1.3.0 — 2026-11-12

- Optional, local Linux journal/audit ingestion with persistent checkpoints and
  a separate user collector. Sources remain disabled until explicitly configured.
- A common event store and three evidence-based SSH correlations, with actor,
  host, time and source constraints. Correlations do not execute responses.
- Bilingual system-event, local-host and source views, connected to existing cases
  through retained evidence timelines.
- Snort alert IDs, checkpoints, notes and existing case data remain compatible.
- Build helpers read the release version from project metadata.

## 1.2.0 — 2026-11-09

- Public repository links, edited Kali/Parrot tutorials and native setup/power-cycle validation evidence.

- First-run assistant in es-419/en-US; demo is explicit, live connections persist.
- Snort 3 version detection and official installation guidance; existing sensor logs can be connected without a local engine.
- Optional isolated sensor creation with rule validation and native authorization; no service auto-start and no overwrites.
- Separate service startup and boot preferences; missing log recovery stays in real mode.


## 1.1.0 — 2026-11-09

- Mapa mundial offline con marcadores, zoom, países y exploración paginada de alertas.
- Totales geográficos sobre toda la consulta; distingue IP sin ubicación y demo sintética.
- Importación GeoIP privada y persistente, con selección de la red más específica IPv4/IPv6.
- Pestañas con contadores: categorías demo o clasificación original de Snort; filtro también aplicado a exportaciones y mapa.
- Barra de estado del servicio local, modo, interfaz configurada, recolector y última alerta de la fuente.
- Mejora de botones principales, diseño a 1080×720 y etiquetas ES/EN; cartografía Natural Earth con atribución.

## 1.0.1 — 2026-11-09

- Añade Ctrl+Q mediante el atajo nativo de Qt para cerrar la ventana y liberar recursos.
- Unifica paquete, comando, módulo Python, lanzador, AppStream y servicio con la marca JALTRIX.
- Sustituye el paquete anterior mediante las relaciones de actualización nativas de DEB/RPM/Arch.
- Migra datos sin modificar identidades de eventos/casos; conserva rutas antiguas mediante enlaces de compatibilidad.
- Migra explícitamente sensor, cuenta de servicio y configuración, conservando reglas y estados de arranque/ejecución, con reversión ante errores.
- Archiva compilaciones históricas fuera de la carpeta pública de distribución.

## 1.0.0 — 2026-11-09

- Nueva identidad SVG aportada por Jan Herrera: logo completo e icono escalable de escudo.
- Copias privadas de datos con snapshots de SQLite y restauración verificada, sin sobrescribir datos existentes.
- Escritura serializada de checkpoints entre GUI y recolector; recuperación tras configuración de fuente inválida.
- Revisión estática y formato uniforme, pruebas de actualización y ensayo de ingesta con rotaciones y reinicio.
- Metadatos Debian completos, fuentes reproducibles, hashes e inventario de componentes directos.
- Alcance estable: consola local de escritorio. EDR real y capacidades empresariales multiusuario quedan fuera de esta versión.

## 0.4.0 — 2026-11-09

- Recolector systemd independiente, recuperación de log rotado y retención configurable.
- Consultas SQL paginadas, filtros CIDR/SID/puerto y exportación completa en streaming.
- Triage, notas, etiquetas, favoritos y excepciones temporales auditadas.
- Explorador PCAP/PCAPNG, bytes, procedencia y replay real con conversión validada.
- Telemetría de interfaz, topología observacional, mapeos ATT&CK manuales y GeoIP local.
- Helper administrativo limitado: configurar sensor, validar/desplegar reglas y restaurar perfil.
- Respuesta nftables temporal con política explícita, verificación, revocación y pruebas aisladas.
- Metadata AppStream, manual y normalización de permisos de paquetes.
- Escritorios reales en VMs Ubuntu, Parrot, Fedora y Arch; pruebas nativas en Kali.
- EDR continúa no configurado y deshabilitado, conforme a la decisión del propietario.

## 0.3.3

Identidad JALTRIX, emblema propio adaptado, créditos y avisos legales bilingües.
