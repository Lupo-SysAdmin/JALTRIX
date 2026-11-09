# Mapa de amenazas — JALTRIX 1.1

Abrir **Mapa de amenazas** en el menú, pulsar **Explorar** en el mapa del Dashboard o ejecutar `jaltrix --map`. Todo el mapa funciona localmente: no requiere navegador, API, token ni conexión a servicios de mapas.

## Lectura e interacción

- El resumen cuenta **todas las alertas de la consulta** de la fuente seleccionada, con búsqueda, severidad, intervalo y clasificación; no solo las 500 filas de la página de la tabla.
- Los países muestran alertas, IP de origen distintas y porcentaje respecto de las alertas ubicadas. Los porcentajes se redondean a un decimal.
- Pulsar un país filtra los marcadores y la lista inferior. Pulsar un marcador selecciona su ubicación. Varias IP con el mismo país/coordenadas se agrupan en un marcador.
- La lista inferior pagina de 100 en 100. Pulsar una alerta abre su inspector y permite crear un caso. La selección del mapa no cambia silenciosamente los filtros de la tabla general ni el alcance de sus exportaciones.
- Los botones +/− amplían/reducen; arrastrar desplaza el mapa ampliado. ↺ restablece la escala. Los marcadores y países también son controles accesibles por teclado.
- Se dibujan hasta 1000 ubicaciones, ordenadas por frecuencia, en la vista elegida; un aviso indica si hay más. Los totales y la exploración paginada siguen incluyendo todas.

**Sin ubicación** incluye IP privadas/reservadas, direcciones ausentes y direcciones públicas sin coincidencia en la base. No se colocan en coordenadas inventadas. La localización de una IP es aproximada: puede señalar un proveedor, VPN o infraestructura compartida; no identifica a una persona ni demuestra el origen físico de un atacante.

## Base GeoIP real

La cartografía mundial viene incluida, pero **no se incluye una base mundial de geolocalización IP**. Importar una base local con **Base GeoIP local**. El operador debe disponer de autorización/licencia para sus datos; JALTRIX no descarga ni redistribuye bases comerciales.

CSV UTF-8 de hasta 8 MiB, con estas cinco columnas exactas:

```csv
network,country,latitude,longitude,source
```

Cada fila contiene una red IPv4/IPv6 CIDR canónica, código de país de dos letras mayúsculas, latitud de −90 a 90, longitud de −180 a 180 y procedencia no vacía. Si varias redes coinciden, se usa la más específica. Usar rangos y coordenadas verificados de su proveedor, no valores de ejemplo para clasificar tráfico real.

La aplicación valida la importación y guarda una copia privada `geoip.csv` en su directorio de datos. La copia persiste tras cerrar, se incluye en los backups de usuario y no depende de conservar el CSV original. Un CSV inválido no sustituye la base válida. La huella SHA-256 identifica el archivo de datos usado por el resumen.

## Demostración

En DEMO se asignan seis ubicaciones **sintéticas** a las direcciones reservadas de la fixture. La pantalla y el mapa pequeño lo anuncian explícitamente. Esas asignaciones no se utilizan para alertas LIVE o REPLAY. Las IP de documentación y privadas reales permanecen sin ubicación.

## Categorías y estado operativo

Las pestañas del Dashboard muestran las categorías de la fixture en DEMO. En LIVE/REPLAY muestran **la clasificación original de Snort** (`class`), con sus propios nombres y contadores. No se infiere «Malware» o «Escaneo» por el país de una IP ni por coincidencias vagas del mensaje. El contador de cada pestaña respeta búsqueda/severidad/intervalo y se calcula antes de aplicar la pestaña seleccionada; `Todas` muestra la suma.

La barra superior distingue el servicio local, modo, interfaz configurada, estado reciente del recolector y hora de la última alerta de la fuente. El servicio se consulta sin autorización interactiva y sin vaciar la UI durante la consulta. **Servicio activo no equivale a captura verificada**. No se presentan tasas de paquetes ni reglas cargadas sin una medición verificable. La última alerta procede del archivo seleccionado, no necesariamente del sensor local.

## Cartografía

Siluetas de tierra Natural Earth 1:110m en proyección equirectangular, sin fronteras políticas. Datos de dominio público según los [términos de Natural Earth](https://www.naturalearthdata.com/about/terms-of-use/). La aplicación incluye el aviso, origen y hash del GeoJSON usado para derivar el SVG. No hay solicitudes externas durante la visualización.

## English summary

The offline map summarizes the entire filtered source query, groups source IPs by country/location and provides paginated alert drilldown. Real data requires a locally imported, properly licensed GeoIP CSV with `network,country,latitude,longitude,source` columns, at most 8 MiB. The validated private copy persists across restarts. Private/reserved and unmapped IPs remain unlocated. Demo locations are explicitly synthetic and never applied to real alerts. Coordinates do not identify an attacker. Native Snort classification tabs and the local service status strip do not imply packet capture or threat attribution. Map land geometry is public-domain Natural Earth data.
