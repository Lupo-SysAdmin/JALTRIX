# Publicación JALTRIX 1.0.1

## Alcance de la versión estable

Consola **local, nativa y de un operador Linux**, con demo separada, investigación de alertas/capturas, recolección independiente, reglas y respuesta local autorizadas. Estable significa que las funciones documentadas superaron los controles de esta versión; no es una certificación comercial, legal o de detección completa.

EDR real permanece fuera de alcance porque el propietario no dispone de proveedor. No se anuncia multiusuario/RBAC empresarial, aislamiento remoto, auditoría remota inmutable, cifrado propio, feed comercial de reglas ni soporte universal de distribuciones. MITRE es mapeo explícito del analista; GeoIP necesita un archivo local del operador. Estas capacidades se presentan con sus límites en UI y documentación.

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

El código está preparado localmente; no se publica ni se crea un repositorio externo automáticamente. Al elegir el repositorio de GitHub: activar Issues y Private Vulnerability Reporting, subir fuentes y ejecutar Actions, corregir cualquier fallo remoto antes de marcar la release pública, y adjuntar paquetes, fuentes, hashes y notas. No afirmar que el CI remoto pasó antes de observar su resultado. No subir claves, imágenes de VM, `.runtime`, bases, capturas privadas ni todo el directorio `artifacts` indiscriminadamente.

Mantenedor: Jan Herrera. Identidad pública de paquete: `281252544+Lupo-SysAdmin@users.noreply.github.com`, elegida por el propietario para no exponer correo personal. No es un buzón de soporte. El botón GitHub apunta al perfil verificado hasta tener la URL final del repositorio; actualizar esa URL en la próxima revisión cuando exista.
