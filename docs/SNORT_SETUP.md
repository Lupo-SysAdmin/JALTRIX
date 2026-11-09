# Motor local de laboratorio

Versión objetivo consultada: Snort 3.13.2.0, release oficial https://github.com/snort3/snort3/releases/tag/3.13.2.0. LibDAQ 3.0.29.

Se compilaron las fuentes oficiales en `.runtime/`, ignorado por Git. La interfaz no incluye ni redistribuye el binario del motor. El build resultante está identificado como **3.13.2.0 + parches locales**:

1. `packaging/patches/snort-3.13.2.0-appid-linkage.patch`: elimina `inline` de una definición externa usada desde otras unidades de compilación. El build sin parche falla al enlazar `appid_log`.
2. `packaging/patches/snort-3.13.2.0-isolated-rpath.patch`: respeta RPATH para cargar LibDAQ desde el prefijo privado. Sin ello se cargaba el DAQ 3.0.24 del host. Build final confirmado con DAQ 3.0.29.0.

Dependencias instaladas con autenticación del propietario: libpcap-dev, libdumbnet-dev, libluajit-5.1-dev, libhwloc-dev, flex, bison, libtool, autoconf, automake. APT actualizó libpcap a 1.11.0 e instaló sus dependencias; no se instaló ni activó el servicio Snort del sistema. El host ya tenía CMake/Ninja, compilador y otras bibliotecas requeridas.

Reproducir: `tools/build_engine.sh`. Script con versiones y hashes fijados de los archivos descargados, y parches versionados en el repositorio. Requiere las dependencias de desarrollo. No pide root ni modifica `/etc/snort`. Logs de esta ejecución en `.runtime/*build*.log`.

Este build tiene Hyperscan, LibML, Brotli y Libunwind deshabilitados por ausencia de esas dependencias opcionales. No se anuncia soporte de sus funcionalidades. Las reglas de laboratorio sólo detectan un marcador benigno UDP; no equivalen a un ruleset de protección.

`engine.replay` valida primero `-T`, copia PCAP/reglas a un directorio de ejecución, genera un perfil Lua mínimo propio y ejecuta `-r` como usuario normal. Conserva SHA-256 de evidencia/reglas, salida y metadatos. Se desactiva checksum con `-k none` para replay y se registra este ajuste. Nunca usa shell para argumentos de archivos. PCAP máximo 1 GiB, reglas de replay máximo 8 MiB, timeout 90 s. PCAPNG se rechaza con explicación.

`seconds` del JSON permite convertir a UTC. Un `timestamp` sin año/zona se conserva sin inventar fecha. Prioridad 1 → Alta, 2 → Media, 3 → Baja; el resto → Sin información. No se deriva criticidad automáticamente. La acción `allow` o `would_drop` nunca se presenta como bloqueo.
