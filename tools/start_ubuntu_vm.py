"""Rootless KVM GUI validation VM, official image + SHA256, no host network changes."""

from pathlib import Path
import hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / ".runtime/vms/ubuntu"
VM.mkdir(parents=True, exist_ok=True, mode=0o700)
name = "ubuntu-26.04-server-cloudimg-amd64.img"
expected = next(
    line.split()[0]
    for line in (VM / "SHA256SUMS").read_text().splitlines()
    if line.split()[-1].lstrip("*") == name
)
with (VM / "base.img").open("rb") as stream:
    actual = hashlib.file_digest(stream, "sha256").hexdigest()
assert actual == expected, "Cloud image checksum mismatch"
key = VM / "ssh-key"
if not key.exists():
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
        capture_output=True,
    )
share = ROOT / ".runtime/vms/share"
share.mkdir(exist_ok=True)
shutil.copyfile(ROOT / "dist/jaltrix_1.2.0-1_all.deb", share / "jaltrix.deb")
shutil.copyfile(ROOT / "dist/jaltrix-1.2.0.tar.gz", share / "source.tar.gz")
seed = VM / "seed"
seed.mkdir(exist_ok=True)
(seed / "meta-data").write_text(
    "instance-id: jaltrix-ubuntu-v040\nlocal-hostname: jaltrix-ubuntu\n"
)
user = """#cloud-config
users:
  - name: jaltrix
    groups: [adm, sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - PUBLIC_KEY
ssh_pwauth: false
package_update: true
packages: [xorg, xfce4, lightdm, dbus-x11, python3-pytest, fonts-dejavu-core]
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
  - apt-get install -y /mnt/jaltrix/jaltrix.deb
  - mkdir -p /home/jaltrix/.config/autostart
  - printf '[Desktop Entry]\\nType=Application\\nName=JALTRIX validation\\nExec=env QT_QUICK_BACKEND=software jaltrix --about --language en-US\\n' > /home/jaltrix/.config/autostart/jaltrix.desktop
  - chown -R jaltrix:jaltrix /home/jaltrix/.config
  - systemctl set-default graphical.target
  - systemctl restart lightdm
""".replace("PUBLIC_KEY", key.with_suffix(".pub").read_text().strip())
(seed / "user-data").write_text(user)
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
    raise SystemExit("Existing VM pid file; inspect before starting another instance")
cmd = [
    "qemu-system-x86_64",
    "-enable-kvm",
    "-cpu",
    "host",
    "-m",
    "4096",
    "-smp",
    "4",
    "-drive",
    f"file={disk},if=virtio,format=qcow2",
    "-drive",
    f"file={VM / 'seed.iso'},media=cdrom,readonly=on",
    "-netdev",
    "user,id=net0,hostfwd=tcp:127.0.0.1:22940-:22",
    "-device",
    "virtio-net-pci,netdev=net0",
    "-vga",
    "virtio",
    "-display",
    "none",
    "-vnc",
    "127.0.0.1:95",
    "-serial",
    f"file:{VM / 'serial.log'}",
    "-monitor",
    f"unix:{VM / 'monitor.sock'},server,nowait",
    "-virtfs",
    f"local,path={share},mount_tag=hostshare,security_model=none,readonly=on",
    "-daemonize",
    "-pidfile",
    str(VM / "qemu.pid"),
]
subprocess.run(cmd, check=True)
(VM / "provenance.json").write_text(
    json.dumps(
        dict(
            url="https://cloud-images.ubuntu.com/releases/26.04/release/" + name,
            sha256=actual,
            scope="KVM + Xorg/Xfce, rootless host process",
        ),
        indent=2,
    )
)
print(
    "Ubuntu KVM started; SSH 127.0.0.1:22940, VNC loopback :95. Keys remain in ignored .runtime."
)
