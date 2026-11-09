# Validación 1.2.0 — 2026-11-09

## Cierre de publicación: instalaciones nuevas y encendido posterior

- Kali 2026.3 (VM del propietario, Snort 3.12.2.0 / DAQ 3.0.24) y Parrot Security 7.4 (VM del propietario, Snort 3.1.82.0 / DAQ 3.0.22): instalación del DEB, motor separado, alta del sensor y autorizaciones nativas Polkit completadas por el operador: PASS.
- Sensor en `lo`, HOME_NET `127.0.0.0/8`, regla UDP benigna: cuatro alertas reales por VM durante el tutorial. Cierre con Ctrl+Q, recolección independiente y reapertura LIVE: PASS. Después se instaló el DEB con los enlaces finales y se ejecutó la suite completa: **61 PASS en cada VM**, con su motor real. Son resultados adicionales; no se reescriben los contadores de las otras VM de la matriz original.
- Tras apagar y volver a encender ambas VM, `jaltrix-sensor.service` estaba activo/habilitado y el recolector de usuario activo/habilitado al iniciar sesión. Un nuevo envío local produjo dos alertas adicionales: seis eventos en cada base, `PRAGMA quick_check=ok`. No fue necesario iniciar manualmente los servicios: PASS.
- En Parrot se seleccionó `/usr/sbin/snort` desde el asistente. El servicio `snort.service` que acababa de habilitar el paquete de la distro se deshabilitó para usar únicamente el sensor de JALTRIX. Esto no es una instrucción para detener sensores preexistentes en uso.
- [Evidencia resumida sin datos privados](evidence/1.2.0/commissioning.json) y [tutoriales editados](TUTORIALS.md). El encendido posterior se verificó aparte y no forma parte de la grabación original.

- Paquete final DEB: instalación/actualización en ambas VM conservó el sensor activo y el arranque habilitado. Lintian ejecutado en Parrot: sin errores ni avisos. Desktop/AppStream y revisión de formato: PASS.
- GitHub Actions valida Python 3.11–3.14. La primera ejecución detectó la ausencia de `libEGL.so.1` en el runner; el workflow instala las bibliotecas Qt necesarias. Consulta el resultado del commit publicado en [Actions](https://github.com/Lupo-SysAdmin/JALTRIX/actions). Las pruebas de Snort se omiten explícitamente en ese runner sin motor; la integración real se comprueba por separado.

## Matriz automática anterior al cierre

- Kali y Ubuntu: 61 pruebas aprobadas. Arch/Fedora/Parrot: 58 aprobadas, 3 omitidas por ausencia del motor real.
- Primer inicio sin demo implícita, motor ausente/3/2/inválido, persistencia LIVE, recuperación ante archivo perdido, ES/EN y geometría 1080×720.
- GUI instalada, mapa y asistente en ES/EN en los cuatro escritorios de VM.
- Ubuntu, creación real: reglas inválidas rechazadas antes de escribir perfil, autorización de helper probado en contexto root del laboratorio, no sobrescritura, servicio detenido y arranque deshabilitado, posterior inicio y alerta UDP de loopback legible por el operador. El diálogo Polkit del alta no fue automatizado; se reutiliza el canal de autorización existente.
- La cuenta heredada del laboratorio conservaba /home/snort-soc; se admite esa migración. Ubuntu permite al grupo syslog escribir /var/log; las modificaciones privilegiadas al nuevo registro se realizan mediante descriptores sin seguir enlaces. El fixture de laboratorio deshabilita y restaura su arranque previo para simular una instalación nueva.
- Los ensayos de carga/rotación y otras integraciones de 1.1.0 son evidencia histórica, no ensayos nuevos de esta versión. No hay publicación ni ejecución de GitHub Actions.

# Validación JALTRIX 1.1.0 — 2026-11-09

- **55 PASS** en Kali y Ubuntu; **52 PASS / 3 SKIP** en Arch, Fedora y Parrot (motor Snort ausente en esas tres VMs).
- Mapa sobre toda la consulta (prueba de 1308 eventos, fuera de la primera página), países y marcadores, paginación, aislamiento de modos/fuentes, coincidencia de red más específica IPv4/IPv6 e IP privadas/desconocidas sin ubicación: PASS.
- Interacción GUI mediante clics en país/marcador/alerta, inspector, pestañas, CSV privado persistente, ES/EN, 1080×720 y ausencia de errores QML: PASS. GUI instalada y mapa abiertos en los escritorios reales de las cuatro VMs.
- Actualización nativa 1.0.1 → 1.1.0 con fixtures nuevas, dentro del mismo arranque: PASS en cuatro VMs; conserva identidades/checkpoints/casos/notas. Un verificador histórico del renombrado encontró dos generaciones en su antigua fixture Fedora; se conservó esa evidencia y se preparó una comparación antes/después específica de esta actualización. No se presenta como ensayo de continuidad ante cambios de dispositivo/inodo.
- En Parrot, el primer intento gráfico no encontró la autorización X11 de KDE tras reiniciar el laboratorio. Se corrigió la detección de la sesión gráfica en el verificador y se repitieron suite y GUI satisfactoriamente; no fue una omisión de la prueba gráfica.
- Ensayo de mapa con **100.000 alertas sintéticas**: resumen completo 0,296 s y última página de país 0,131 s en este equipo. El RSS del informe corresponde al proceso completo que también creó/ingirió el dataset, no al mapa aislado. No constituye una garantía de rendimiento.
- Recolector: **600.000 alertas sintéticas**, 10.000/s durante 60 s, cinco rotaciones y reinicio; sin pérdidas/duplicados, SQLite OK. No mide capacidad de captura de Snort.
- Evidencias: [resumen](evidence/1.1.0/validation.json), [mapa](evidence/1.1.0/geomap-benchmark.json), [recolector](evidence/1.1.0/soak.json) e informes de VM/actualización en ese directorio.

Las integraciones privilegiadas y el ciclo de paquetes previos se documentan debajo, con sus versiones originales. El mapa es offline, requiere GeoIP local para IP reales y separa la demo. GitHub Actions remoto sigue NOT RUN. EDR permanece deshabilitado sin proveedor.

## Evidencia histórica

# Validación JALTRIX 1.0.1 — 2026-11-09

## Cambio de nombre y cierre nativo

- Suite: **51 PASS** en Kali/Ubuntu; **48 PASS / 3 SKIP** en Arch/Fedora/Parrot por ausencia de Snort en esas tres VMs. Incluye la migración y Ctrl+Q con foco en un campo de texto.
- Sustitución real del paquete 1.0.0 por `jaltrix`: comprobada en Kali y las cuatro VMs. Comando y menú antiguos retirados; datos, eventos, checkpoints, casos, notas y favoritos conservados.
- Sensor migrado con reglas idénticas: en Kali permaneció detenido y deshabilitado; en Ubuntu permaneció activo y habilitado. Cuenta/servicio/directorios usan JALTRIX; enlaces de compatibilidad preservan rutas antiguas.
- Helper instalado en Ubuntu: validación real de reglas, rollback, rechazo de reglas inválidas, HOME_NET y firewall en namespaces aislados PASS. La prueba detectó una referencia de tabla incorrecta durante el cambio de nombre; se corrigió y se repitió completa satisfactoriamente. No se alteró el firewall host del propietario.
- Backup/restauración y eliminación/reinstalación del nuevo paquete: PASS en las cuatro VMs, conservando datos y restableciendo el recolector si estaba activo.
- Escritorio real instalado e icono de ventana: verificación en la matriz; SVG originales conservados byte por byte. Ctrl+Q utiliza `Shortcut` de Qt con Ctrl+Q explícito en todas las distribuciones y la misma ruta de cierre de la ventana.
- Ensayo nuevo del recolector: **600.000 eventos a 10.000/s durante 60 s**, 5 rotaciones y reinicio; 600.000 almacenados/únicos, cero rechazados. Duración real 62,25 s; consultas hasta 0,030 s; SQLite OK. No mide capacidad de captura Snort.
- Referencias de prueba actuales: `docs/evidence/1.0.1/validation.json`, informes de las cuatro VMs y soak. Las evidencias 1.0.0 siguientes son históricas, no se atribuyen de nuevo a 1.0.1.

GitHub Actions remoto sigue **NOT RUN**. EDR sigue **NO CONFIGURADO** y deshabilitado. No se afirma certificación legal, soporte universal ni detección completa de amenazas. Ver [migración](MIGRATION.md) y [matriz](COMPATIBILITY_MATRIX.md).

## Evidencia histórica de 1.0.0

# Validación estable 1.0.0 — 2026-11-09

## Resultado actual

- **45 PASS** en Kali y Ubuntu, con Snort real: `artifacts/tests-v100.log`, `ubuntu-vm-tests-v100.log`.
- **42 PASS / 3 SKIP** en Arch, Fedora y Parrot; tres pruebas de motor omitidas por no estar instalado. GUI instalada sobre escritorio real: PASS en las cinco plataformas.
- Actualización real de paquetes desde 0.4: conserva alertas, checkpoint, casos, notas y favoritos; comprobada en las cuatro VMs mediante `test_upgrade_vm.py`.
- Backup de SQLite abierto con WAL, restauración, hashes, rechazo de sobrescritura/path traversal y dos escritores concurrentes: PASS. Recuperación del recolector tras cambiar temporalmente a una fuente inexistente: PASS.
- SVG originales intactos, iconos SVG/PNG empaquetados, logo completo en UI, icono de ventana EWMH real: PASS. Se añadió dependencia SVG explícita en Arch, Debian y RPM; la fuente usa PNG si el runtime no tiene decodificador SVG.
- Ruff (F/E9) y formato: PASS. Desktop/AppStream: PASS. Lintian: **0 errores**, aviso `initial-upload-closes-no-bugs` esperado porque este paquete independiente no cierra un ITP del archivo Debian.
- Reglas/configuración/rollback y firewall aislado con helper instalado: PASS en Kali y Ubuntu. Firewall en ámbito host dentro de Ubuntu VM: bloqueo real, TTL y revocación PASS. En Kali no se habilitó firewall host.
- Fuentes y DEB: dos construcciones consecutivas byte a byte idénticas con SOURCE_DATE_EPOCH. Hashes finales e inventario se entregan junto a los instaladores.

## Ensayos del recolector

| Ensayo | Eventos | Duración programada / real | Rotaciones | Reinicio | Pérdidas / duplicados |
|---|---:|---:|---:|---|---|
| 1.000 eventos/s, antes de optimizar índices SID | 600.000 | 600 s / 603,64 s | 59 | Sí | 0 / 0 |
| 10.000 eventos/s, con índices SID | 600.000 | 60 s / 62,27 s | 5 | Sí | 0 / 0 |

SQLite quick_check: OK en ambos. El ensayo inicial detectó consultas SID de hasta 10,182 s; índices dedicados redujeron el máximo observado a 0,035 s en el segundo ensayo. Las cargas y duraciones son distintas: no se presenta como comparación controlada general ni garantía de latencia para filtros arbitrarios. RSS máximo muestreado del recolector aproximadamente 26 MiB; no incluye GUI ni Snort.

Evidencia: `artifacts/soak-v100.json` y `soak-fast-v100.json`. Son eventos sintéticos escritos en archivos, recolector real, rotación/reinicio y lectores SQL concurrentes; **no son una medición de capacidad de captura de paquetes ni un ensayo de operación durante días**.

## Alcance y publicación

La versión estable corresponde a consola local, motor separado y respuesta local autorizada. EDR real: NO CONFIGURADO por decisión del propietario. No se certifican arm64, despliegues empresariales multiusuario ni versiones de distribuciones distintas a la matriz. Snort 3.13.2.0 sigue siendo la versión de código fuente indicada en la [página oficial de descargas](https://www.snort.org/downloads), consultada el 9 de noviembre de 2026; el build de laboratorio contiene los dos parches documentados.

GitHub Actions está preparado pero **NOT RUN remoto**, porque el repositorio no se publica en esta tarea. Ejecutarlo y comprobarlo al publicar; no mostrar un badge de éxito inventado. Documentación de publicación: RELEASE.md.

## Evidencia histórica 0.4

# Validación 0.4.0 — 2026-11-09

## Suite local

`QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software python3 -m pytest -q -ra`: **41 PASS**, incluidos tres tests con Snort real (validación y replay de PCAP/PCAPNG). Evidencia: `artifacts/tests-v040.log`. Snort 3.13.2.0 con dos parches locales de construcción; no se presenta como binario oficial redistribuido.

Cobertura: normalización, fechas desconocidas, entradas inválidas/cuarentena, checkpoints/rotación/truncado/reinicio, recuperación de descriptor rotado, fragmento incompleto, SQL/CIDR/SID/paginación, exportación completa de 1200 alertas y CSV seguro, retención con preservación de casos, PCAPNG/conversión/bytes, triage concurrente, mapeos versionados, GeoIP local, telemetría, contratos EDR, propuestas/auditoría y denegación de acciones no autorizadas. GUI: panel de servicio desplazable en ventanas pequeñas, navegación de todas las páginas, ES/EN, selección, casos, 100.000 filas virtualizadas, servicio sin parpadeo por consultas de estado y warnings QML.

## Integraciones reales

- `artifacts/advanced-admin-v040.log`: Kali, helper instalado, autorización nativa, despliegue y rollback de reglas, rechazo de regla inválida conservando perfil, configuración HOME_NET y restauración. Firewall en namespace propio: tráfico real bloqueado/restaurado, TTL y tabla ajena preservada. Firewall host no modificado.
- `artifacts/ubuntu-host-firewall-v040.json`: Ubuntu KVM desechable, respuesta en ámbito host, bloqueo real, TTL, protección de IP propia/loopback, rechazo fuera de política y revocación después de deshabilitar política. Red/tabla/política de prueba eliminadas al terminar.
- `artifacts/collector-systemd-v040.json`: recolector systemd de usuario sin GUI, ingesta y reinicio sin duplicar datos.
- `artifacts/ubuntu-reboot-before.txt` / `ubuntu-reboot-after.txt`: reboot de VM, sensor y recolector activos después del arranque. Kali no se reinició.
- `artifacts/ubuntu-live-sensor-v040.json`: alerta benigna realmente capturada; `ubuntu-daq-shutdown-v040.log`: cambio afpacket y parada/reinicio comprobados.
- `artifacts/*-package-lifecycle-v040.json`: remove/purge según gestor, launcher/menú retirados, datos preservados, reinstalación y restauración del recolector cuando estaba activo.

## Rendimiento

`artifacts/benchmark-v040.json`: corridas sintéticas de **5 segundos** a 1.000 y 10.000 eventos/s; 5.000 y 50.000 registros, respectivamente, cero rechazados/perdidos en ese ensayo, 4,912 y 4,948 segundos medidos. No incluyen GUI ni captura de paquetes y **no son una prueba de estabilidad prolongada o de rendimiento de Snort**. RSS informado por el proceso de prueba no es una medición aislada del consumo de la GUI.

## Distribuciones y empaquetado

Ver [matriz](COMPATIBILITY_MATRIX.md) para escritorio real, motor disponible y SKIP. Pruebas de fuente offscreen se complementan con ejecutable instalado sobre sesión gráfica real. Los screenshots son de la aplicación ejecutada, no mockups generados.

AppStream `validate --no-net`: PASS (un aviso pedante); desktop-file-validate: PASS. DEB, RPM y Arch construidos e instalados. `lintian` no estaba instalado: NOT RUN; no sustituir por PASS. CI de GitHub definido, todavía NOT RUN. El intento de repetir contenedores 0.4.0 no accedió al socket Docker; no se considera un éxito y se reemplazó por la matriz KVM.

## Límites del resultado

PASS acredita los casos ejecutados, no certificación de seguridad. EDR real: NOT CONFIGURED, explícitamente deshabilitado. Motor no instalado en VMs Parrot/Fedora/Arch: tres tests de motor SKIP, aunque la GUI y la suite restante pasan. Sin ensayo arm64, captura de una LAN de producción, RBAC multiusuario, auditoría externa ni soak prolongado. Mantener límites visibles al publicar una release.
