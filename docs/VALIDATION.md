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
