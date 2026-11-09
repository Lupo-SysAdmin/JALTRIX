# Servicio del sensor — 0.4.0

En Servicio, **Administrar servicio real** sale de demo. Iniciar/detener controla exclusivamente `snort-soc.service`. **Iniciar con el sistema** habilita el arranque de forma independiente: detener no deshabilita el próximo arranque. El estado se confirma después de la operación; la consulta periódica no recrea el panel ni muestra un estado de carga por cada sondeo.

GUI no root, autorización nativa Polkit, cuenta de sensor dedicada y capacidades limitadas. El paquete gráfico no instala motor ni activa captura. `tools/install_lab_sensor.py` es un instalador de laboratorio para el motor local; rechaza sobrescribir un perfil existente. El perfil administrado usa `/usr/local/lib/snort-soc-engine`, `/etc/snort-soc` y `/var/log/snort-soc/alert_json.txt`, separado de instalaciones ajenas.

El perfil inicial captura **loopback** con DAQ `afpacket`, regla de marcador benigno y checksum deshabilitado por offload local. No protege la LAN. Configurar interfaz/HOME_NET desde la GUI muestra diferencias, valida con Snort y solicita autenticación. Revisar reglas y visibilidad de tráfico antes de usar otra interfaz.

## Recolector independiente

`jaltrix-ingest.service` es una unidad **de usuario**: sigue el archivo y actualiza SQLite con la GUI cerrada, arranca al iniciar sesión, sin listener de red. No requiere root y necesita permiso de lectura del log. El sensor puede arrancar al encender el sistema antes de esa sesión; son servicios distintos. No se habilita linger automáticamente.

Iniciar recolector escribe su configuración y habilita la unidad; detener no elimina su habilitación. Para deshabilitar: `systemctl --user disable --now jaltrix-ingest.service`. La GUI puede volver a conectar su fuente. Se utiliza un lock de escritor, checkpoint transaccional, salud y recuperación de rotación. Retención opcional 0–3650 días, donde 0 desactiva eliminación; protege eventos vinculados a casos. Consultar los límites de rotación en SECURITY.md.

## Evidencia

En Kali: inicio/detención, enable/disable, autenticación nativa, alerta UDP benigna real, permisos y despliegue/rollback validados. Se restaura **detenido / arranque deshabilitado**; no se reinició el host del propietario. Recolector independiente y reinicio con checkpoint: PASS.

En Ubuntu KVM: arranque completo tras reboot con sensor y recolector habilitados, escritorio operativo y sin reimportación de eventos anteriores: PASS. La transición a DAQ afpacket se verificó con una alerta real y parada/reinicio de aproximadamente 0,16 segundos en esa VM; no es una garantía de latencia universal.
