# JALTRIX

<img src="design/branding/jaltrix-logo.svg" alt="JALTRIX" width="220">

[English](README.en.md) · Español

Consola nativa Linux de investigación y respuesta para Snort 3, desarrollada por **Jan Herrera**. [GitHub del desarrollador](https://github.com/Lupo-SysAdmin). Versión **1.0.0**, GPL-3.0-or-later.

Interfaz **ES (español latinoamericano) / EN (inglés estadounidense)** con preferencia persistente, modo demo separado, icono propio y Acerca de con autoría, licencia y componentes. JALTRIX es independiente de Snort/Cisco/Talos. Su disponibilidad como marca no está certificada; [procedencia del emblema](docs/BRANDING.md).

## Funciones

- Ingesta `alert_json` con checkpoints SQLite, cuarentena, recuperación de rotación y recolector independiente de la ventana mediante systemd de usuario.
- Consulta paginada de la base completa, filtros por tiempo, severidad, texto, IP/CIDR, SID, protocolo y puerto. Exportación JSON/CSV de **toda la consulta**, con procedencia y neutralización de fórmulas CSV.
- Copias de seguridad privadas con snapshots SQLite, hashes y restauración verificada en un directorio nuevo.
- Triage persistente: estado, notas, etiquetas, favoritos, revisión concurrente, casos e historial. Excepciones temporales anotan alertas; no las ocultan ni desactivan detección.
- PCAP y PCAPNG: evidencia copiada y hash SHA-256, explorador de paquetes y bytes, apertura externa y replay real con Snort sin root. PCAPNG compatible se convierte conservando el original.
- Reglas: editor, borrador desde una alerta, validación real `Snort -T`, vista previa de cambios, despliegue del perfil administrado y rollback con autenticación nativa.
- Sensor: iniciar/detener, arranque del sistema, configuración de interfaz/HOME_NET y consulta de journal. GUI sin root; helper instalado de alcance limitado.
- Telemetría real de interfaz; topología de relaciones observadas; mapeos ATT&CK manuales, versionados y justificados; geolocalización aproximada con CSV local aportado por el operador.
- Respuesta nftables: vista previa, motivo, autenticación de administrador, política de destinos permitidos, bloqueo temporal verificado, consulta y revocación. **Deshabilitada por defecto.** No modifica tablas ajenas.
- EDR: contrato y denegación por defecto. **Aislamiento/restauración deshabilitados por decisión del propietario, sin proveedor configurado.**

## Uso

Requiere Python >=3.11 y PySide6 >=6.8,<7. El motor Snort se instala por separado; demo e investigación de archivos funcionan sin él.

```sh
./run.sh
./run.sh --pcap tests/fixtures/lab/benign.pcapng --rules tests/fixtures/lab/local.rules
QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software python3 -m pytest -q -ra
python3 tools/build_deb.py
```

Instalación Debian: `sudo apt install ./dist/snort-soc-desktop_1.0.0-1_all.deb`. El paquete **no instala automáticamente un sensor ni modifica reglas de Snort existentes**. El perfil opcional administrado usa `/etc/snort-soc`, separado de `/etc/snort`. Véanse [servicio](docs/SERVICE.md), [manual operativo](docs/USER_GUIDE.md) y [empaquetado](docs/PACKAGING.md).

Datos en `$XDG_DATA_HOME/snort-soc-desktop/` (por defecto `~/.local/share/snort-soc-desktop/`), separados en `demo`, `replay` y `live`. `--data-dir` permite un laboratorio independiente. El recolector de usuario arranca **al iniciar sesión**; el sensor systemd puede arrancar con el sistema. La retención es explícita y preserva alertas asociadas a casos; inicialmente está desactivada.

## Validación y límites

[Resultados](docs/VALIDATION.md) · [Matriz de plataformas](docs/COMPATIBILITY_MATRIX.md) · [Seguridad](SECURITY.md) · [Arquitectura](docs/ARCHITECTURE.md) · [Cambios](CHANGELOG.md) · [Publicación 1.0](docs/RELEASE.md).

Se ha probado el escritorio en Kali y en VMs KVM de Ubuntu, Parrot, Fedora y Arch. Las pruebas de motor y respuesta tienen un alcance distinto del lanzamiento de la GUI; la matriz distingue PASS, SKIP y lo no ejecutado.

Esta versión no se presenta como certificación de producción ni de compatibilidad universal. No incluye EDR real, RBAC multiusuario, almacenamiento cifrado propio, auditoría remota inmutable ni actualización automática de reglas comerciales. Las gráficas, topología y resúmenes describen la **página actual** de alertas; la exportación abarca toda la consulta. Los mapeos ATT&CK requieren evaluación del analista y no prueban una técnica por sí solos. GeoIP no atribuye personas ni atacantes.

## Licencia y créditos

Copyright © 2026 Jan Herrera. [LICENSE](LICENSE) · [NOTICE](NOTICE) · [AUTHORS](AUTHORS). Snort se ejecuta como proceso separado; Qt, PySide6 y demás componentes conservan sus licencias. El inventario legal integrado declara componentes directos y procedencia, no una auditoría exhaustiva de dependencias transitivas.

![JALTRIX 1.0.0 — DEMO](docs/screenshots/dashboard-es.png)
