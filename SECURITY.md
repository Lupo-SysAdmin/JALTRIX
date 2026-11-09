# Seguridad y límites

La GUI y el recolector se ejecutan sin root. No hay servidor web ni listener de red propio. JSON, capturas y salidas de comandos se tratan como datos; la interfaz utiliza texto plano. Procesos con argumentos estructurados, límites y timeouts. Seleccionar un motor o reglas sigue siendo una decisión de confianza del operador.

## Privilegios y respuesta

Las operaciones del sensor y firewall requieren autenticación nativa. El helper instalado se ejecuta con Python aislado, verifica propiedad root y ausencia de escritura por terceros en rutas privilegiadas, y sólo acepta operaciones y ubicaciones fijas. No recibe comandos, Lua ni sintaxis nft arbitrarios. Valida reglas mediante Snort como usuario del sensor, muestra diferencias y comprueba la precondición hash antes del despliegue. Ante error intenta restaurar el perfil anterior; la escritura de múltiples archivos no es una transacción resistente a cortes de energía.

La respuesta host exige política root explícita de CIDRs permitidos, deniega rutas por defecto como alcance, protege direcciones locales, gateway y DNS, y aplica TTL de 1–3600 segundos en el kernel. Utiliza sólo su tabla `inet jaltrix` identificada con comentario propio. Una autorización de administrador sigue permitiendo afectar comunicaciones con destinos aprobados: revisar el destino y la vía de administración antes de confirmar. No constituye un sistema RBAC empresarial ni un firewall de perímetro. La revocación sigue disponible al deshabilitar la política.

EDR deniega por defecto en backend. No existe proveedor conectado y no se simula aislamiento exitoso. La salud de Snort no implica salud de EDR.

## Datos

Almacenes separados por modo, bases 0600 y directorios nuevos 0700. Copias de evidencia privadas, hashes de integridad, cuarentena de entradas inválidas y CSV con neutralización de fórmulas. Los datos no se envían automáticamente a terceros. Los enlaces externos se abren por acción del operador. No hay cifrado de disco propio: usar protección del sistema cuando se necesite.

El recolector conserva el descriptor del log rotado y busca el inodo anterior al reiniciar si aún existe en el directorio. Un fragmento incompleto de un archivo rotado se pone en cuarentena tras dos segundos sin crecimiento. Copytruncate con recrecimiento idéntico, eliminación/compresión previa a recuperar el inodo y escrituras tardías posteriores a abandonar un archivo pueden perder datos. No se garantiza entrega sin pérdida ante cualquier rotación; conservar logs originales y monitorizar errores.

Retención opcional por tiempo de ingesta, preservando eventos vinculados a casos. Exportaciones contienen datos sensibles. No publicar PCAP, logs privados ni secretos.

## Auditoría y reporte

Las operaciones administrativas registran actor autenticado, solicitud y resultado en `/var/lib/jaltrix/audit.jsonl`. Historias locales y cadena hash de propuestas ayudan a detectar modificaciones parciales; no protegen contra root o un atacante capaz de reescribir toda la base. No hay ancla externa ni identidad multiusuario.

Reporta vulnerabilidades mediante [GitHub Private Vulnerability Reporting](https://github.com/Lupo-SysAdmin/JALTRIX/security/advisories/new). La política de mantenimiento de la serie 1.x se describe a continuación. No enviar vulnerabilidades con datos sensibles en issues públicos. Esta versión requiere revisión de seguridad adicional antes de un despliegue de respuesta de producción.

## Serie estable 1.x

El alcance estable es una consola local con autenticación del sistema para cambios administrativos. Versiones anteriores a 1.0 deben actualizarse a la versión correctiva más reciente de la serie 1.x. Las correcciones se distribuyen como versiones nuevas con fuentes, avisos, checksums y pruebas; no se ejecutan actualizaciones de binarios o reglas automáticamente.

Los backups de usuario son privados (0600), sin cifrado integrado. SQLite se copia mediante su API de backup; se verifica integridad al restaurar. La restauración requiere un destino nuevo y valida rutas, tamaño e inventario SHA-256. No restablece políticas del firewall ni activa servicios. El hash verifica integridad, no autenticidad frente a quien pueda reescribir el backup y su manifiesto.

Utiliza la pestaña Security del repositorio para reportes sensibles. La dirección noreply del mantenedor sólo identifica la cuenta; no es un buzón de soporte. No se anuncia un canal privado como operativo antes de habilitarlo.
