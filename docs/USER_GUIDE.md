# Manual operativo 1.0.0

## Alertas e investigación

En Configuración, importar un `alert_json` o seguir un archivo accesible. El modo LIVE significa seguimiento de una fuente, no prueba por sí mismo que el sensor esté sano. DEMO usa datos separados. La fecha desconocida se conserva como desconocida; los filtros temporales no inventan fechas.

Buscar texto libre, `src:192.0.2.0/24`, `dst:198.51.100.1`, `sid:1000001`, `gid:1`, `proto:UDP`, `port:9999`, o un CIDR sin prefijo para ambos extremos. Se combinan términos con AND. La tabla pagina por SQL; las gráficas de intervalos/fuentes y topología abarcan esa página. El mapa y los contadores de clasificación abarcan la consulta completa. Exportar JSON/CSV recorre la consulta completa y conserva filtros/procedencia. No exportar evidencia sensible sin revisar el destino.

Seleccionar una alerta permite triage con notas, etiquetas y favoritos; crear un caso conserva la asociación. Las excepciones de triage tienen firma/IP y vencimiento: anotan la coincidencia, sin ocultarla ni cambiar reglas de detección.

## Capturas y reglas

Abrir PCAP/PCAPNG en el explorador conserva una copia hash verificada. Inspeccionar metadatos, buscar paquetes, seleccionar bytes o abrir con la aplicación externa registrada. La vista hexadecimal está limitada a 256 bytes por paquete. Para analizar con Snort, seleccionar motor y reglas y ejecutar replay. No se captura tráfico de red en replay.

El parser admite Ethernet/VLAN y decodificación básica IPv4/IPv6; no pretende reemplazar Wireshark. La conversión PCAPNG exige timestamps y un tipo de enlace uniforme; bloques heredados o formatos no soportados se rechazan explícitamente.

Crear una regla desde una alerta genera un borrador amplio que debe revisarse. Validar con Snort; para desplegar, revisar el diff y autorizar en la ventana del sistema. El despliegue sustituye `local.rules` del perfil administrado, no agrega reglas a configuraciones externas. Rollback restaura el perfil anterior y reinicia sólo si estaba activo.

## Servicio y continuidad

El sensor y el recolector son independientes. Iniciar/detener y arrancar con el sistema controlan `jaltrix-sensor.service`. El recolector `jaltrix-ingest.service` pertenece al usuario, sigue el log con la ventana cerrada y arranca al iniciar sesión. Detenerlo no elimina su habilitación; usar `systemctl --user disable --now jaltrix-ingest.service` para deshabilitarlo. Revisar salud y permisos de lectura del log. La retención opcional se aplica por edad de ingesta y respeta casos.

## Contexto y respuesta

Tráfico muestra contadores reales de la interfaz elegida. Topología representa relaciones de alertas, no un escaneo de infraestructura. ATT&CK requiere firma exacta `gid:sid:rev`, técnica, confianza y justificación manual. GeoIP utiliza CSV local con cabecera `network,country,latitude,longitude,source`, coordenadas aproximadas y procedencia; no consulta servicios externos.

El firewall está desactivado hasta configurar una política administrativa de destinos permitidos. Elegir ámbito laboratorio o host, IP y TTL, revisar, aportar motivo y autenticar. Consultar estado o revocar; el kernel vence el bloqueo aunque la GUI se cierre. No se habilitó respuesta host en el Kali del propietario. Las pruebas host se realizaron dentro de una VM desechable.

Aislar/restaurar por EDR permanece deshabilitado hasta conectar y probar un proveedor real. No confundir bloqueo local de una IP con aislamiento de un endpoint remoto.

## Copia de seguridad y recuperación (1.0)

Configuración → Guardar copia de seguridad crea un ZIP privado fuera del directorio de datos. Incluye bases mediante snapshots SQLite, preferencias, evidencia y un inventario SHA-256. No incluye configuración del sensor en `/etc`, unidades systemd ni estado del firewall. Cada base tiene consistencia individual; para preservar simultáneamente todos los almacenes, detener el recolector y cerrar otras ventanas antes de copiar. El ZIP no está cifrado.

También se puede ejecutar `jaltrix --backup /ruta/copia.zip`. Para recuperar, cerrar la GUI y usar `jaltrix --restore /ruta/copia.zip --data-dir /ruta/directorio-nuevo`. El destino debe ser inexistente: la restauración rechaza sobrescrituras, rutas inseguras y hashes inválidos. Revisar después con `jaltrix --data-dir /ruta/directorio-nuevo`. Servicios y captura no se activan al restaurar. Conservar la carpeta anterior hasta comprobar casos, evidencia y ajustes.

## Atajos de teclado

- **Ctrl+Q**: cerrar JALTRIX por la misma ruta de cierre que el botón de la ventana. No detiene el sensor ni el recolector independiente.
- **Ctrl+K**: enfocar la búsqueda.

## Mapa, pestañas y barra de estado

Ver [GEOIP.md](GEOIP.md) para importar una base local, explorar países/marcadores y abrir alertas, distinguir demo de ubicaciones reales y entender el alcance de los contadores y estados del sensor.
