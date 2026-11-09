"""Resume existing project-owned KVM disks without downloading or reprovisioning."""

import argparse
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("distro", choices=["ubuntu", "arch", "fedora", "parrot"])
args = parser.parse_args()
root = Path(__file__).resolve().parents[1] / ".runtime/vms"
vm = root / args.distro
assert (vm / "test.qcow2").is_file()
if (vm / "qemu.pid").exists():
    raise SystemExit("Existing PID file; inspect before starting")
port = {"ubuntu": 22940, "arch": 22941, "fedora": 22942, "parrot": 22943}[args.distro]
cmd = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "4096", "-smp", "4"]
if args.distro != "ubuntu":
    cmd += [
        "-drive",
        "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
        "-drive",
        f"if=pflash,format=raw,file={vm / 'vars.fd'}",
    ]
cmd += ["-drive", f"file={vm / 'test.qcow2'},if=virtio,format=qcow2"]
if (vm / "seed.iso").exists():
    cmd += ["-drive", f"file={vm / 'seed.iso'},media=cdrom,readonly=on"]
cmd += [
    "-netdev",
    f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
    "-device",
    "virtio-net-pci,netdev=net0",
    "-vga",
    "virtio",
    "-display",
    "none",
    "-vnc",
    f"127.0.0.1:{95 + port - 22940}",
    "-serial",
    f"file:{vm / 'serial.log'}",
    "-monitor",
    f"unix:{vm / 'monitor.sock'},server,nowait",
    "-virtfs",
    f"local,path={root / 'share'},mount_tag=hostshare,security_model=none,readonly=on",
    "-daemonize",
    "-pidfile",
    str(vm / "qemu.pid"),
]
subprocess.run(cmd, check=True)
print(f"{args.distro}: existing disposable lab started, loopback SSH {port}")
