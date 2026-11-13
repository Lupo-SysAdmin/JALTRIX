# Identidad JALTRIX

Jan Herrera aportó dos archivos SVG transparentes el 9 de noviembre de 2026 y solicitó sustituir el emblema anterior por ellos:

- `design/branding/jaltrix-logo.svg`: copia íntegra de JALTRIX_LOGO_VECTOR_TRANSPARENTE.svg, logo completo original conservado para la imagen del repositorio y material de presentación.
- `design/branding/jaltrix-icon.svg`: copia íntegra de JALTRIX_ICONO_VECTOR_TRANSPARENTE.svg, escudo para lanzador, ventanas/Alt+Tab y paquetes.

Se distribuyen los SVG en `src/jaltrix/ui`, y el escudo en el tema Linux `hicolor/scalable/apps`. Los PNG de respaldo se renderizan de esos mismos SVG con `python3 tools/render_branding.py` (librsvg/PyGObject/Cairo), sin generación de imágenes ni fondos añadidos. El SVG no contiene imágenes externas ni código ejecutable. La aplicación conserva las proporciones y la transparencia.

Los originales proporcionados sustituyen el lobo anterior en los paquetes nuevos. El historial de diseño previo permanece en el árbol de trabajo, pero no se incluye en el tarball de la versión nueva. No se atribuye a estos SVG una procedencia de generación no declarada por el propietario. Su incorporación autorizada no certifica exclusividad de derechos ni disponibilidad de la marca JALTRIX.

Desde 1.0.1 se adoptan el paquete `jaltrix`, el comando `jaltrix`, el identificador `io.github.LupoSysAdmin.Jaltrix`, los directorios de datos y el servicio `jaltrix-sensor.service` con la migración descrita en [MIGRATION.md](MIGRATION.md) para preservar preferencias y casos. Snort identifica el motor externo y conserva sus avisos.

En 1.3.0, por indicación del propietario, la barra lateral y Acerca de usan `jaltrix-emblem.svg` / `app-emblem.svg`: una variante del escudo original sin el grupo decorativo exterior `network-globe` del pie ni el bloque tipográfico del logo completo. Conserva escudo, radar, nodos, candado, órbita y transparencia. Los dos SVG originales y la imagen principal del repositorio no se modifican. Los iconos del lanzador y Alt+Tab conservan su variante anterior. El PNG de respaldo del emblema también se renderiza directamente del SVG.
