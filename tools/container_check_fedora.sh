#!/bin/bash
set -euo pipefail
kind="$1"
mkdir -p /work
cp -r /source/src /source/tests /source/pyproject.toml /work/
cp /source/packaging/desktop/io.github.LupoSysAdmin.SnortSOC.desktop /work/
cd /work
cat /etc/os-release
if [ "$kind" = ubuntu ] || [ "$kind" = parrot ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends /source/dist/snort-soc-desktop_1.0.0-1_all.deb python3-pytest xvfb xauth x11-utils libgl1
elif [ "$kind" = fedora ]; then
    dnf install -y python3-pyside6 python3-pytest python3-gobject-base qt6-qtdeclarative xorg-x11-server-Xvfb xauth xdpyinfo mesa-libGL
    dnf install -y /source/dist/snort-soc-desktop-1.0.0-1.noarch.rpm
elif [ "$kind" = arch ]; then
    pacman -Syu --noconfirm --needed base-devel python pyside6 python-gobject python-pytest xorg-server-xvfb xorg-xauth xorg-xdpyinfo
    useradd -m builder
    mkdir /work/pkg
    cp /source/packaging/arch/PKGBUILD /source/dist/snort-soc-desktop-1.0.0.tar.gz /work/pkg/
    chown -R builder:builder /work/pkg
    su builder -c 'cd /work/pkg && makepkg --noconfirm'
    pacman -U --noconfirm /work/pkg/*.pkg.tar.zst
fi
python3 -c 'import platform,PySide6; print(platform.python_version(), PySide6.__version__)'
QT_QPA_PLATFORM=offscreen python3 -m pytest -q -ra > /result/tests.txt 2>&1
# Exercise real X11 protocol via a virtual X server; not a full desktop or VM.
Xvfb :99 -screen 0 1480x920x24 -nolisten tcp > /result/xvfb.log 2>&1 &
xpid=$!
trap 'kill "$xpid" 2>/dev/null || true' EXIT
export DISPLAY=:99 QT_QPA_PLATFORM=xcb QT_QUICK_BACKEND=software
for i in $(seq 1 40); do xdpyinfo >/dev/null 2>&1 && break; sleep .1; done
snort-soc --language en-US --about --screenshot /result/about-en.png --data-dir /work/data
snort-soc --language es-419 --screenshot /result/dashboard-es.png --data-dir /work/data
# Local user data must survive removal/purge; no test writes to host data.
echo preserved > /work/data/preservation-marker
if [ "$kind" = ubuntu ] || [ "$kind" = parrot ]; then
    apt-get install -y --reinstall /source/dist/snort-soc-desktop_1.0.0-1_all.deb
    apt-get purge -y snort-soc-desktop
elif [ "$kind" = fedora ]; then
    dnf reinstall -y /source/dist/snort-soc-desktop-1.0.0-1.noarch.rpm
    rpm -e snort-soc-desktop
else
    pacman -U --noconfirm /work/pkg/*.pkg.tar.zst
    pacman -R --noconfirm snort-soc-desktop
fi
test "$(cat /work/data/preservation-marker)" = preserved
! test -e /usr/bin/snort-soc
printf 'PASS: tests, package install/reinstall/remove, X11 screenshots, data preservation\n' > /result/result.txt
