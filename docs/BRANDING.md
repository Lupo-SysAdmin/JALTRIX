# Identidad JALTRIX

Jan Herrera aportó dos archivos SVG transparentes el 9 de noviembre de 2026 y solicitó sustituir el emblema anterior por ellos:

- `design/branding/jaltrix-logo.svg`: copia íntegra de JALTRIX_LOGO_VECTOR_TRANSPARENTE.svg, identidad completa dentro de la interfaz y Acerca de.
- `design/branding/jaltrix-icon.svg`: copia íntegra de JALTRIX_ICONO_VECTOR_TRANSPARENTE.svg, escudo para lanzador, ventanas/Alt+Tab y paquetes.

Se distribuyen los SVG en `src/snort_soc/ui`, y el escudo en el tema Linux `hicolor/scalable/apps`. Los PNG de respaldo se renderizan de esos mismos SVG con `python3 tools/render_branding.py` (librsvg/PyGObject/Cairo), sin generación de imágenes ni fondos añadidos. El SVG no contiene imágenes externas ni código ejecutable. La aplicación conserva las proporciones y la transparencia.

Los originales proporcionados sustituyen el lobo anterior en los paquetes nuevos. El historial de diseño previo permanece en el árbol de trabajo, pero no se incluye en el tarball de la versión nueva. No se atribuye a estos SVG una procedencia de generación no declarada por el propietario. Su incorporación autorizada no certifica exclusividad de derechos ni disponibilidad de la marca JALTRIX.

Se mantienen el paquete `snort-soc-desktop`, el comando `snort-soc`, el identificador `io.github.LupoSysAdmin.SnortSOC`, los directorios de datos y el servicio `snort-soc.service` para permitir actualizaciones sin perder preferencias ni casos. Snort identifica el motor externo y conserva sus avisos.
