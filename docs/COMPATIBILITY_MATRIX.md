# Compatibilidad 1.3.0 — 2026-11-12

| Plataforma amd64 | Paquete / escritorio probado | Suite final | GUI y actualización |
|---|---|---|---|
| Kali 2026.3 | DEB; VM con Xvfb explícito como usuario | 179 PASS, Snort 3.12.2.0 | PASS: ES/EN, 1080×720, datos y sensor conservados |
| Ubuntu 26.04.1 LTS | DEB; KVM, Xfce/Xorg | 179 PASS, motor real | PASS; journald/auditd y servicio independiente reales |
| Parrot Security 7.4 | DEB; VM del propietario, KDE/Wayland mediante Xwayland | 179 PASS, Snort 3.1.82.0 | PASS; estilo Qt, ES/EN, 1080×720 y sensor conservado |
| Arch rolling | paquete pacman .pkg.tar.zst construido con makepkg; KVM, Xfce | 176 PASS / 3 SKIP | PASS; sin motor, SKIP explícito de sus tres pruebas |
| Fedora 44 Cloud | RPM; KVM, Xfce/Xorg | 176 PASS / 3 SKIP | PASS; sin motor; denegación de lectura audit correctamente diagnosticada |

La suite local del Kali anfitrión obtuvo 179 PASS con Snort 3.13.2.0. Los datos de 1.2.0 se compararon antes y después de instalar el paquete nuevo; los casos, checkpoints, notas y configuración del sensor se conservaron. Además se compararon los archivos de aplicación instalados con las fuentes verificadas byte por byte. Las versiones y capturas detalladas están en [evidencia 1.3.0](evidence/1.3.0/validation.json).

El DEB no es universal: exige las versiones Python/Qt/PySide declaradas. No se certifican arm64, Ubuntu 24.04, Fedora 45 ni distribuciones no probadas. En Arch el archivo `.pkg.tar.zst` es el paquete nativo que instala pacman; el PKGBUILD publicado fija el hash del tarball correspondiente. No se ha publicado en AUR.

Python de las VM: Kali 3.14.8, Ubuntu 3.14.4, Arch 3.14.9, Fedora 3.14.3 y Parrot 3.13.5. GitHub Actions añade Python 3.11–3.14, pero no sustituye las pruebas de distribuciones ni de Snort real. Las fuentes Linux requieren permisos del operador y, para auditd, registros y reglas existentes; una GUI que abre correctamente no prueba cobertura de detección.

Las imágenes originales de laboratorio se verificaron con hashes de los proveedores. Las evidencias de versiones anteriores se conservan en [VALIDATION.md](VALIDATION.md) y el historial Git; no se atribuyen a esta entrega pruebas antiguas de firewall, reinicio del host o larga duración que no se hayan repetido.
