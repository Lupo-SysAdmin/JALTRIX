# Observabilidad local de Linux — diseño 1.3.0

JALTRIX amplía la investigación de Snort con eventos locales de Linux. El alcance de esta entrega es journald, registros existentes de auditd, un formato común y tres correlaciones explicables. osquery, Falco, agentes remotos y nuevos motores de respuesta quedan para entregas posteriores.

## Compatibilidad y aislamiento

- Las bases, identificadores, checkpoints y casos de Snort 1.2.0 se conservan.
- Los eventos adicionales usan `live/host-events.sqlite3`; su recolector es independiente del recolector de Snort y de la ventana.
- Las fuentes nuevas están deshabilitadas por defecto. El modo demo no consulta eventos locales reales.
- Lectura con permisos del operador. No se instala auditd, no se reemplazan reglas del administrador y no se cambia el firewall al activar observabilidad.
- Relacionar alertas Snort con el equipo local requiere una asociación explícita de la fuente seleccionada. Una dirección IP no constituye identidad fiable de un equipo.

## Modelo y correlación

Se conservan identidad de la fuente, identidad del equipo, fecha UTC y confianza temporal, actor, proceso, archivo, dirección de red, resultado y registro original. Los campos desconocidos no se inventan. Las fechas ausentes y los actores ambiguos no producen coincidencias positivas.

Las reglas previstas son:

1. Cinco o más fallos SSH y posterior acceso exitoso del mismo usuario, IP y equipo dentro de cinco minutos.
2. Acceso SSH y modificación exitosa de `authorized_keys` por el mismo actor y equipo dentro de diez minutos.
3. Alerta Snort de tráfico hacia SSH, acceso SSH exitoso desde esa IP y uso posterior de sudo por el mismo usuario/equipo dentro de diez minutos. Requiere asociación explícita del sensor al equipo.

Cada resultado conserva las evidencias y explica la ventana y los campos relacionados. Una correlación es una hipótesis de investigación, no una demostración automática de intrusión. Crear un caso reutiliza los casos existentes y protege sus evidencias frente a la retención. Ninguna correlación ejecuta bloqueos, aislamiento ni comandos de respuesta.

## Criterios de publicación

La entrega debe validar migración sin cambios en los datos anteriores, separación de modos, fuentes inaccesibles, reinicio/rotación, deduplicación, eventos tardíos, límites de retención y consumo, casos con evidencia protegida, falsos positivos entre equipos/usuarios y traducción ES/EN. Las pruebas con fixtures se distinguirán de las pruebas reales de journald/auditd y de las comprobaciones de paquetes por distribución.
