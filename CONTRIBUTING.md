# Contribuir

Python >=3.11, PySide6 >=6.8,<7 y pytest. Ejecutar `QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software python3 -m pytest -q -ra`. Los tests de motor requieren Snort y reportan SKIP si no existe. No reemplazar un resultado real por un mock presentado como integración.

Separar datos demo/live/replay, traducir cadenas de interfaz ES/EN, mantener GUI sin root y justificar permisos. Acompañar cambios funcionales con regresiones significativas y documentar limitaciones. No subir capturas privadas, credenciales, imágenes de VM ni binarios del motor. Las pruebas privilegiadas se ejecutan sólo en laboratorios propios y revisando su alcance; las de host requieren VM desechable.

Las contribuciones de código se distribuyen bajo GPL-3.0-or-later. Declarar procedencia y licencia de assets/dependencias añadidos. Revisar `SECURITY.md` antes de informar problemas sensibles.

Revisión estática: `ruff check src tests tools`; formato: `ruff format --check src tests tools`. La configuración versionada habilita F/E9. Las pruebas de paquetes se ejecutan en VMs desechables, nunca cambiando reglas de producción.
