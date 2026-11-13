# Publicación JALTRIX 1.3.0

## Alcance de la versión estable

Consola **local, nativa y de un operador Linux**, con demo separada, investigación de alertas/capturas, recolección independiente, reglas y respuesta local autorizadas. Estable significa que las funciones documentadas superaron los controles de esta versión; no es una certificación comercial, legal o de detección completa.

EDR real permanece fuera de alcance porque el propietario no dispone de proveedor. No se anuncia multiusuario/RBAC empresarial, aislamiento remoto, auditoría remota inmutable, cifrado propio, feed comercial de reglas ni soporte universal de distribuciones. MITRE es mapeo explícito del analista; GeoIP necesita un archivo local del operador. Estas capacidades se presentan con sus límites en UI y documentación.

## Novedades 1.3.0

Observabilidad local opcional: lectura de journald y registros existentes de auditd, una base adicional versionada y un servicio de usuario independiente. Las fuentes se habilitan de manera explícita y respetan los permisos del operador. El software no instala auditd, cambia sus reglas ni concede acceso administrativo automáticamente.

La vista **Eventos del sistema** incorpora eventos paginados, equipos observados, configuración de fuentes y tres correlaciones SSH explicables. Permite abrir casos existentes con una cronología de evidencia protegida frente a la retención. Las coincidencias son hipótesis para investigar, con identidad y ventanas de tiempo verificables; no activan respuestas. Para cruzar Snort y el host se exige asociar expresamente la fuente local seleccionada. Ver [guía ES/EN](LOCAL_OBSERVABILITY.md).

La actualización conserva las bases y checkpoints de Snort, los casos, las notas y la configuración anterior. Los paquetes llevan la misma identidad JALTRIX de la versión previa. Se comprueban las fuentes reales en laboratorio y se distinguen las pruebas sintéticas, las pruebas de paquetes y las del motor; resultados exactos en [VALIDATION.md](VALIDATION.md).

## Funciones incorporadas en 1.2.0

Asistente de primer inicio ES/EN, detección de Snort 3, guía oficial para instalarlo si falta, conexión a sensores existentes y creación opcional de un servicio propio con validación de reglas. La conexión LIVE y la elección de demo se recuerdan. La instalación del motor sigue siendo manual; no se descarga ni ejecuta automáticamente. Ver [SETUP.md](SETUP.md).

La creación nueva del sensor se probó con Snort real en Ubuntu: reglas inválidas rechazadas, perfil existente conservado, creación detenida/deshabilitada y alerta UDP benigna legible por el operador. El paquete no activa el servicio durante instalación o actualización. Además se completaron instalaciones nuevas con autorizaciones nativas y pruebas posteriores al encendido en Kali y Parrot; ver [validación](VALIDATION.md) y [tutoriales](TUTORIALS.md).

## Funciones incorporadas en 1.1.0

Mapa mundial offline con marcadores, países y exploración paginada de alertas; base GeoIP local persistente; pestañas con contadores de clasificación; barra de estado y mejoras de legibilidad/acciones. Ver [GEOIP.md](GEOIP.md). Las localizaciones reales necesitan un CSV del operador; la cartografía de tierra viene incluida.

## Archivos que acompañan la publicación

- DEB para las plataformas Debian probadas, RPM para Fedora y paquete nativo Arch.
- Tarball de **fuentes correspondientes** con licencias, SVG originales, herramientas, pruebas y CI.
- SHA256SUMS, inventario de componentes directos y manifiesto de release.
- README ES/EN, changelog, seguridad, instrucciones de backup, matriz y evidencias de pruebas.

Los paquetes no incluyen Snort modificado ni dependencias Qt redistribuidas. El motor se instala por separado. Para redistribuir el build local modificado del motor se necesita su paquete independiente de fuentes/parches/avisos; no añadir `.runtime` a la release.

## Actualización y cambio de nombre

La versión 1.0.1 usa `jaltrix` como paquete/comando, `io.github.LupoSysAdmin.Jaltrix` como identidad gráfica y `jaltrix-sensor.service` para el sensor administrado. Los paquetes declaran el reemplazo del paquete anterior. Leer [MIGRATION.md](MIGRATION.md) antes de actualizar; documenta copias, enlaces de compatibilidad, conservación de casos y migración explícita del sensor.

## Controles de publicación

Ejecutar pytest con motor real donde esté disponible; revisión Ruff y formato; validación desktop/AppStream y lintian; instalación/upgrade/remove en la matriz; replay PCAP/PCAPNG; pruebas de respuesta en laboratorio y ensayo de ingesta prolongado. Registrar SKIP por motor ausente, no convertirlo en PASS. Los resultados exactos están en VALIDATION.md.

`python3 tools/source_archive.py` produce un tarball reproducible con SOURCE_DATE_EPOCH. `python3 tools/build_deb.py` normaliza permisos y tiempos. El manifiesto de release verifica que la versión y los assets empaquetados correspondan al árbol probado. El checksum prueba integridad, no una firma de identidad.

## Paso público del propietario

Repositorio del proyecto: [Lupo-SysAdmin/JALTRIX](https://github.com/Lupo-SysAdmin/JALTRIX). Para cada publicación: activar Issues y Private Vulnerability Reporting, subir fuentes y ejecutar Actions, corregir cualquier fallo remoto antes de marcar la release pública, y adjuntar paquetes, fuentes, hashes y notas. No afirmar que el CI remoto pasó antes de observar su resultado. No subir claves, imágenes de VM, `.runtime`, bases, capturas privadas ni todo el directorio `artifacts` indiscriminadamente.

Mantenedor: Jan Herrera. Identidad pública de paquete: `281252544+Lupo-SysAdmin@users.noreply.github.com`, elegida por el propietario para no exponer correo personal. No es un buzón de soporte. El botón GitHub y los metadatos de los paquetes apuntan al repositorio del proyecto.
