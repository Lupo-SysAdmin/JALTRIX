# Respuesta e investigación — 0.4.0

| Flujo | Implementado | Alcance |
|---|---|---|
| PCAP | Copia/hash, PCAPNG, explorador/bytes, replay real | Asociación de paquete disponible en replay; no inventa PCAP para logs externos |
| Casos | Crear/abrir, notas, estados e historial | Local, sin roles ni colaboración multiusuario |
| Firewall | Preview, política CIDR, autenticación, nftables, TTL, consulta/revocación | Desactivado por defecto; tabla propia; probado en namespace aislado y VM |
| EDR | Contrato, capacidades y rechazo en backend | Sin proveedor; aislamiento/restauración deshabilitados por decisión del propietario |
| Allowlist | Candidato auditado y excepción de triage limitada por firma/IP/TTL | Anota; no elimina alertas ni cambia detección |
| Blocklist | Candidato local con motivo/TTL | Su aprobación no aplica automáticamente firewall; éste requiere su flujo explícito |
| Regla | Borrador desde alerta, edición/validación, deploy y rollback | Sustituye reglas locales del perfil administrado, previa revisión |

La GUI prepara un plan revisable; el helper root valida alcance y argumentos otra vez. Cambios de perfil usan hash de precondición, validación real como usuario del sensor, copia del perfil anterior y verificación. La bitácora administrativa registra UID autenticado y resultado.

Para firewall host, primero configurar política root con 1–32 CIDRs acotados, sin `/0`. Se rechazan loopback, link-local, multicast, dirección propia, gateway y DNS. El TTL es del kernel y permanece efectivo sin GUI. Repetir un bloqueo existente no prolonga su vencimiento. Consultar/revocar siguen disponibles cuando la política queda deshabilitada. No se tocan tablas ajenas ni se permite sintaxis nft suministrada por eventos.

Las pruebas aisladas verificaron tráfico real, TTL y reversión, rechazo de destinos protegidos/fuera de política y conservación de una tabla ajena. No se activó la política host en Kali. Las operaciones son locales a la máquina donde se ejecuta JALTRIX; no son un firewall central ni aislamiento remoto.

No se implementó RBAC multiusuario, cola distribuida ni auditoría remota inmutable. Las autorizaciones corresponden a la cuenta Linux y al administrador autenticado. Revisar SECURITY.md antes de producción.
