"""Rootless Fedora/Arch cloud image validation with a complete Xfce desktop."""

from pathlib import Path
import argparse, hashlib, json, re, shutil, subprocess

parser = argparse.ArgumentParser()
parser.add_argument("distro", choices=["arch", "fedora"])
args = parser.parse_args()
ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / ".runtime/vms" / args.distro
with (VM / "base.img").open("rb") as stream:
    digest = hashlib.file_digest(stream, "sha256").hexdigest()
checks = (VM / "SHA256SUMS").read_text()
expected = (
    checks.split()[0]
    if args.distro == "arch"
    else re.search(
        r"SHA256 \(Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2\) = ([0-9a-f]{64})",
        checks,
    )[1]
)
assert digest == expected, "Checksum mismatch"
key = VM / "ssh-key"
if not key.exists():
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
        capture_output=True,
    )
share = ROOT / ".runtime/vms/share"
seed = VM / "seed"
seed.mkdir(exist_ok=True)
(seed / "meta-data").write_text(
    f"instance-id: jaltrix-{args.distro}-v040\nlocal-hostname: jaltrix-{args.distro}\n"
)
common = """#cloud-config
users:
  - name: jaltrix
    groups: [wheel]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - PUBLIC_KEY
ssh_pwauth: false
write_files:
  - path: /etc/lightdm/lightdm.conf.d/50-jaltrix-lab.conf
    content: |
      [Seat:*]
      autologin-user=jaltrix
      autologin-user-timeout=0
      user-session=xfce
runcmd:
  - mkdir -p /mnt/jaltrix
  - mount -t 9p -o trans=virtio,ro,version=9p2000.L hostshare /mnt/jaltrix
""".replace("PUBLIC_KEY", key.with_suffix(".pub").read_text().strip())
if args.distro == "fedora":
    commands = """  - dnf install -y xfce4-session xfce4-panel xfdesktop xfwm4 lightdm lightdm-gtk xorg-x11-server-Xorg xorg-x11-drv-libinput dbus-x11 python3-pytest /mnt/jaltrix/jaltrix.rpm
"""
else:
    commands = """  - pacman -Syu --noconfirm --needed xorg-server xorg-xinit xfce4-session xfce4-panel xfdesktop xfwm4 lightdm lightdm-gtk-greeter python-pytest base-devel pyside6 python-gobject qt6-declarative ttf-dejavu
  - mkdir -p /home/jaltrix/build
  - tar -xzf /mnt/jaltrix/source.tar.gz -C /home/jaltrix/build
  - chown -R jaltrix:jaltrix /home/jaltrix/build
  - cp /mnt/jaltrix/source.tar.gz /home/jaltrix/build/jaltrix-1.2.0/packaging/arch/jaltrix-1.2.0.tar.gz
  - chown jaltrix:jaltrix /home/jaltrix/build/jaltrix-1.2.0/packaging/arch/jaltrix-1.2.0.tar.gz
  - su - jaltrix -c 'cd build/jaltrix-1.2.0/packaging/arch && makepkg --noconfirm'
  - sh -c 'pacman -U --noconfirm /home/jaltrix/build/jaltrix-1.2.0/packaging/arch/*.pkg.tar.zst'
"""
common += (
    commands
    + """  - mkdir -p /home/jaltrix/.config/autostart
  - printf '[Desktop Entry]\\nType=Application\\nName=JALTRIX validation\\nExec=env QT_QUICK_BACKEND=software jaltrix --about --language en-US\\n' > /home/jaltrix/.config/autostart/jaltrix.desktop
  - chown -R jaltrix:jaltrix /home/jaltrix/.config
  - groupadd -rf autologin
  - usermod -aG autologin jaltrix
  - systemctl enable lightdm
  - systemctl set-default graphical.target
  - systemctl restart lightdm
"""
)
(seed / "user-data").write_text(common)
subprocess.run(
    [
        "xorriso",
        "-as",
        "mkisofs",
        "-quiet",
        "-output",
        str(VM / "seed.iso"),
        "-volid",
        "cidata",
        "-joliet",
        "-rock",
        str(seed),
    ],
    check=True,
    capture_output=True,
)
disk = VM / "test.qcow2"
if not disk.exists():
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(VM / "base.img"),
            str(disk),
            "24G",
        ],
        check=True,
        capture_output=True,
    )
if (VM / "qemu.pid").exists():
    raise SystemExit("Existing VM pid file; inspect first")
shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", VM / "vars.fd")
port = 22941 if args.distro == "arch" else 22942
display = 96 if args.distro == "arch" else 97
subprocess.run(
    [
        "qemu-system-x86_64",
        "-enable-kvm",
        "-cpu",
        "host",
        "-m",
        "4096",
        "-smp",
        "4",
        "-drive",
        "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
        "-drive",
        f"if=pflash,format=raw,file={VM / 'vars.fd'}",
        "-drive",
        f"file={disk},if=virtio,format=qcow2",
        "-drive",
        f"file={VM / 'seed.iso'},media=cdrom,readonly=on",
        "-netdev",
        f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-vga",
        "virtio",
        "-display",
        "none",
        "-vnc",
        f"127.0.0.1:{display}",
        "-serial",
        f"file:{VM / 'serial.log'}",
        "-monitor",
        f"unix:{VM / 'monitor.sock'},server,nowait",
        "-virtfs",
        f"local,path={share},mount_tag=hostshare,security_model=none,readonly=on",
        "-daemonize",
        "-pidfile",
        str(VM / "qemu.pid"),
    ],
    check=True,
)
(VM / "provenance.json").write_text(
    json.dumps(
        dict(
            sha256=digest,
            scope="KVM + Xorg/Xfce, rootless host process",
            distro=args.distro,
        ),
        indent=2,
    )
)
print(f"{args.distro} VM started; loopback SSH {port}")
