# Cambio de identidad a JALTRIX 1.0.1

El nombre público del paquete, comando y módulo Python es `jaltrix`. El lanzador y el icono usan `io.github.LupoSysAdmin.Jaltrix`. El sensor administrado usa `jaltrix-sensor.service`, la cuenta `jaltrix-sensor`, `/etc/jaltrix`, `/var/log/jaltrix` y `/usr/local/lib/jaltrix-engine`.

Snort sigue siendo el motor externo de Cisco; su nombre y sus avisos legales se conservan. Cambiar la marca de esta aplicación no modifica licencias de terceros ni garantiza la disponibilidad legal de una marca.

## Instalaciones nuevas

No crean ningún identificador antiguo. Instalar el paquete JALTRIX no instala automáticamente el motor ni activa captura, firewall o EDR.

## Actualización del paquete anterior

1. Cerrar la interfaz y guardar una copia privada de los datos. En la versión 1.0.0: `snort-soc --backup /ruta/backup-antes-de-jaltrix.zip`. Guardar también la configuración administrada del sensor si existe.
2. Detener temporalmente el recolector con `systemctl --user stop jaltrix-ingest.service`, si se utiliza. Esto no desactiva su arranque al iniciar sesión.
3. Instalar `jaltrix_1.0.1-1_all.deb` con `sudo apt install ./jaltrix_1.0.1-1_all.deb`; en Fedora usar `sudo dnf install ./jaltrix-1.0.1-1.noarch.rpm`; en Arch `sudo pacman -U ./jaltrix-1.0.1-1-any.pkg.tar.zst`. El gestor sustituye `snort-soc-desktop`, retirando el comando y el menú antiguos.
4. Si existe el sensor administrado anterior, ejecutar `jaltrix --migrate-system` y completar la autorización nativa. La migración conserva reglas, archivos, permisos, UID/GID, estado activo/detenido y arranque automático. La configuración externa `/etc/snort` no participa. Se guarda la unidad original y el estado en `/var/lib/jaltrix/migration-1.0.1-*`. Ante un error se intenta revertir los cambios y restaurar el servicio anterior. Si hay unidades personalizadas, overrides o conflictos de directorios/cuentas, se detiene para revisión sin fusionarlos a ciegas.
5. Abrir `jaltrix`. Al usar el directorio predeterminado migra `$XDG_DATA_HOME/snort-soc-desktop` a `$XDG_DATA_HOME/jaltrix`, actualiza la unidad del recolector y mantiene sus preferencias de inicio. Si se detuvo manualmente en el paso 2, iniciarlo de nuevo desde la interfaz y revisar su salud. `--data-dir` explícito conserva la ruta elegida.

Las rutas antiguas de datos/configuración/motor/logs se conservan como enlaces de compatibilidad **solo en instalaciones migradas**. Permiten abrir evidencias con rutas absolutas y conservar referencias externas. No borrarlos mientras existan referencias antiguas. No son paquetes adicionales ni una segunda instalación. La identidad de las alertas y los checkpoints se conserva: no se vuelven a importar las mismas líneas por el cambio de directorio.

Si ambos directorios de datos existen y contienen conjuntos distintos, la migración se rechaza; ambos se conservan. Abrir el deseado con `--data-dir` y revisar/copiar datos antes de elegir uno como predeterminado. No combinar bases SQLite manualmente.

## Publicación

Los instaladores y ZIP actuales solo llevan JALTRIX en su nombre. Las referencias al identificador anterior se limitan a la migración, las relaciones de reemplazo de paquetes, las pruebas y la evidencia histórica. Son necesarias para actualizar correctamente; no se presenta el software como un producto oficial de Snort.

Las compilaciones históricas de este equipo se archivaron bajo `.runtime/releases-before-jaltrix/`, excluido por Git y del tarball. No publicar esa carpeta. La release actual se prepara en `dist/JALTRIX-1.0.1/` y `dist/JALTRIX-1.0.1-release.zip`.

## English upgrade summary

Back up and close the old GUI; stop the user collector if used. Install the new `jaltrix` package with your distribution's package manager. It replaces the old package and removes the old menu/launcher. Run `jaltrix --migrate-system` if you have the old managed sensor, then open `jaltrix` and restart any collector you stopped manually. Default user data migrates automatically; explicit custom data directories remain unchanged. Legacy symlinks preserve evidence paths. Existing rules and sensor running/boot states are retained. Conflicting directories, accounts and custom service overrides require review. Keep backups and do not remove compatibility aliases while old references remain.
