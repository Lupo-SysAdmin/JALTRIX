# Compatibilidad 1.0.1 — 2026-11-09

| Plataforma amd64 | Entorno | Suite | GUI instalada | Motor / sistema |
|---|---|---|---|---|
| Kali 2026.3 rolling | Host real, DEB, Wayland | 51 PASS | PASS; ES/EN e icono propio | Snort 3.13.2.0, migración nativa del sensor sin cambiar reglas/estado |
| Ubuntu 26.04.1 LTS | KVM, Xfce/Xorg, DEB | 51 PASS | PASS | Snort real, migración del sensor activo, reglas/rollback y firewall aislado |
| Arch rolling, imagen 20261101 y actualización 2026-11-09 | KVM, Xfce/Xorg, makepkg | 48 PASS / 3 SKIP | PASS | Sin motor; SKIP explícito de integración Snort |
| Fedora 44 Cloud 1.7 | KVM, Xfce/Xorg, RPM | 48 PASS / 3 SKIP | PASS | Sin motor; SKIP explícito de integración Snort |
| Parrot 7.4 Home | KVM, KDE, DEB | 48 PASS / 3 SKIP | PASS | Sin motor; SKIP explícito de integración Snort |

Evidencia: `artifacts/<distro>-vm-tests-v101.log`, screenshots `*-installed-v101.png` y resultados de ciclo de paquete. Las pruebas automáticas de la fuente usan offscreen; además el ejecutable instalado se abre en un escritorio gráfico real. No confundir estas dos verificaciones.

Las imágenes proceden de servidores oficiales y se verificaron contra SHA-256 publicados: Ubuntu cloud-images.ubuntu.com, Arch geo.mirror.pkgbuild.com/images, Fedora dl.fedoraproject.org y Parrot deb.parrot.sh/parrot/iso/7.4. Eso no es una auditoría de la cadena de suministro ni una certificación de distribución.

Versiones Python de laboratorio: Kali 3.14.8, Ubuntu 3.14.4, Arch 3.14.9, Fedora 3.14.3; Parrot 3.13.5. El DEB no es universal: depende de las versiones Qt/PySide/Python declaradas. No se probó arm64, Ubuntu 24.04 ni Fedora 45. Kali se probó como host, no como VM ni reiniciando el equipo del propietario.

Las pruebas históricas 0.3.0 en contenedores constan en `artifacts/matrix`. Para 0.4.0, el socket Docker no era accesible; el intento `matrix-v040` no es PASS. Los nuevos resultados son KVM. No hay publicación AUR ni resultados de GitHub Actions todavía.

Parrot: la suspensión automática de la VM interrumpió el montaje 9p del laboratorio. Se reinició el entorno, se deshabilitó suspensión sólo en esa VM y se transfirieron paquetes por SSH. Después pasaron suite y GUI; no se presenta como prueba de suspensión/reanudación de captura.

El arranque tras reboot y el firewall host dentro de Ubuntu VM se verificaron en 1.0.0; en 1.0.1 se repitieron la migración y las comprobaciones indicadas arriba. Ctrl+Q está incluido en la suite gráfica.
