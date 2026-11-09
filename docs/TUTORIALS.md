# Instalación de JALTRIX 1.2.0

Grabaciones reales de instalaciones nuevas, con indicaciones en español, sin audio y con pausas recortadas. Las acciones conservadas se reproducen a velocidad normal. Puedes pausar para copiar un comando. Desarrollador: Jan Herrera.

| Entorno observado | Motor del repositorio | Video Full HD |
|---|---|---|
| Kali Linux 2026.3 | Snort 3.12.2.0, DAQ 3.0.24 | [Kali — 2:48](https://github.com/Lupo-SysAdmin/JALTRIX/releases/download/v1.2.0/JALTRIX-Kali-tutorial.mp4) |
| Parrot Security 7.4 | Snort 3.1.82.0, DAQ 3.0.22 | [Parrot — 3:05](https://github.com/Lupo-SysAdmin/JALTRIX/releases/download/v1.2.0/JALTRIX-Parrot-tutorial.mp4) |

Los videos muestran la instalación del DEB, el primer inicio sin motor, la instalación separada de Snort, la creación del sensor con Polkit, el arranque, la conexión de alertas y la continuidad del recolector al cerrar la interfaz.

## Comandos de las instalaciones probadas

Desde el directorio que contiene el paquete descargado:

```sh
sudo apt-get install -y ./jaltrix_1.2.0-1_all.deb
sudo apt-get install -y snort acl
snort -V
snort --daq-list
```

Estos comandos corresponden a las versiones de Kali y Parrot indicadas. No se afirma que un paquete llamado `snort` sea Snort 3 en todas las distribuciones. Si el ejecutable no está en el PATH del escritorio, usa «Seleccionar motor…»; en estas instalaciones es `/usr/sbin/snort`.

En la instalación nueva de Parrot, el paquete habilitó su propio `snort.service`. Se deshabilitó con `sudo systemctl disable --now snort.service` antes de crear `jaltrix-sensor.service`. **No detengas un sensor existente en uso**: puedes conectar su archivo de alertas conservando el servicio y las reglas.

## Prueba local reproducible

Interfaz `lo`, HOME_NET `127.0.0.0/8` y esta regla:

```text
alert udp any any -> any 19999 (msg:"JALTRIX - Prueba de conexion"; content:"JALTRIX_TEST"; sid:1000001; rev:1;)
```

Genera tráfico sin privilegios:

```sh
python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"JALTRIX_TEST", ("127.0.0.1", 19999)); s.close()'
```

En loopback se observaron dos alertas por envío, por entrada y salida. La regla no define prioridad: «Sin información» es el valor esperado. Una dirección loopback no debe producir marcadores GeoIP públicos.

Este perfil valida la conexión local. Para vigilar una red hay que elegir su interfaz, definir HOME_NET y cargar reglas adecuadas. El recolector arranca al iniciar sesión; el sensor puede arrancar con el sistema.

El encendido posterior se verificó después de grabar los tutoriales: ambos servicios se recuperaron y cada base pasó de cuatro a seis eventos al enviar otra prueba. Consulta [los resultados](VALIDATION.md).
