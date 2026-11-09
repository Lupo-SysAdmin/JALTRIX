# Paquetes 1.1.0

`python3 tools/build_deb.py` genera DEB con módulos privados `/usr/lib/jaltrix`, lanzador `/usr/bin/jaltrix`, menú, icono, AppStream, página man, documentación y licencias. No incluye motor, reglas comerciales ni activa servicios. `postinst` normaliza los permisos de directorios propios para actualizar instalaciones anteriores que eran escribibles por grupo; no cambia datos del usuario.

`python3 tools/source_archive.py` genera el tarball para RPM/Arch. Excluye motores, imágenes de VM, bases privadas y documento de requisitos original. RPM se construye con `rpmbuild -bb packaging/rpm/jaltrix.spec`, colocando el tarball en SOURCES del topdir. Arch usa `packaging/arch/PKGBUILD` y tarball local con `makepkg` sin root. La receta local usa checksum SKIP; antes de distribuirla fuera de este árbol debe fijarse el hash del tarball final. No está publicada en AUR.

Snort se detecta por configuración/`JALTRIX_ENGINE`, PATH, perfil administrado `/usr/local/lib/jaltrix-engine/bin/snort` o build de desarrollo. nftables/Polkit/iproute2 son capacidades opcionales de administración, no requisitos para abrir demo. Una distribución sin las dependencias gráficas especificadas no está soportada sólo por aceptar `all`/`noarch`.

Datos y ajustes residen fuera del paquete, en XDG; remover/purgar el paquete no solicita borrar evidencia. Un recolector configurado por el usuario debe detenerse/deshabilitarse antes de remover los módulos. El sensor separado debe administrarse por separado; no se borra una instalación externa al quitar la GUI.

Validaciones: desktop-file-validate, AppStream sin red, inspección de permisos/contenido DEB, instalación y actualización en máquinas de prueba. La matriz detalla el alcance GUI/motor por distribución. CI remoto está definido pero no se declara ejecutado hasta tener resultados de GitHub Actions.

## Serie 1.0

El paquete se llama `jaltrix`, reemplaza el paquete anterior y distribuye icono SVG escalable además del PNG. El logo completo SVG se incluye en la interfaz. Debian incorpora copyright con formato DEP-5 y changelog de distribución; los textos legales íntegros siguen disponibles dentro de la aplicación. El mantenedor usa la dirección noreply elegida, no correo personal.

Fuentes y DEB normalizan tiempos con SOURCE_DATE_EPOCH. La receta Arch dentro de las fuentes sigue admitiendo construcción local; la receta preparada para publicar en `dist/PKGBUILD-1.1.0` incluye el SHA-256 concreto de ese tarball, evitando una referencia circular al hash de un archivo que contiene su propia receta.
