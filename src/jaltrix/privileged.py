"""Fixed-scope administrator helper. Installed root-owned; GUI remains unprivileged.
No arbitrary paths, commands, Lua or nft syntax are accepted from the caller.
"""

import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile
import time

CONFIG = Path("/etc/jaltrix")
STATE = Path("/var/lib/jaltrix")
ENGINE = Path("/usr/local/lib/jaltrix-engine/bin/snort")
UNIT = "jaltrix-sensor.service"


def run(args, **kwargs):
    return subprocess.run(
        args, check=True, capture_output=True, text=True, timeout=40, **kwargs
    )


def trusted(path):
    path = Path(path)
    for parent in [path, *path.parents]:
        stat = parent.lstat()
        if parent.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o022:
            raise PermissionError(
                "Privileged path must be root-owned and not writable by group/others"
            )


def profile(interface, network):
    if (
        not re.fullmatch("[A-Za-z0-9_.:-]{1,15}", interface)
        or not (Path("/sys/class/net") / interface).exists()
    ):
        raise ValueError("Unknown interface")
    networks = [
        str(ipaddress.ip_network(v.strip(), strict=True)) for v in network.split(",")
    ]
    if not 1 <= len(networks) <= 32:
        raise ValueError("Expected 1–32 HOME_NET networks")
    home = "[" + ",".join(networks) + "]"
    lua = (
        "HOME_NET = '"
        + home
        + "'\nEXTERNAL_NET = 'any'\nips = { enable_builtin_rules = false, variables = { nets = { HOME_NET = HOME_NET, EXTERNAL_NET = EXTERNAL_NET } } }\nalert_json = { file = true, limit = 32, fields = 'timestamp seconds pkt_num proto src_addr src_port dst_addr dst_port rule msg class priority action' }\n"
    )
    env = (
        "SNORT_INTERFACE="
        + interface
        + "\nSNORT_CHECKSUM="
        + ("none" if interface == "lo" else "all")
        + "\n"
    )
    return lua, env


def rules_valid(text):
    if not isinstance(text, str) or not 0 < len(text.encode()) <= 1024 * 1024:
        raise ValueError("Rules must contain 1 byte to 1 MiB")
    # Managed local text rules only; no include directives, Lua, dynamic objects or file outputs.
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not re.match(r"^(alert|pass|drop|reject|block)\s", stripped):
            raise ValueError(
                "Each local rule must be on one line; directives are not accepted"
            )
        if re.search(r"\b(include|soid|luajit|logto)\s*[:=]", stripped, re.I):
            raise ValueError("External code and output paths are not accepted")
    ids = re.findall(r"\bsid\s*:\s*(\d+)\s*;", text)
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate SID")
    if not ids:
        raise ValueError("At least one SID is required")


def snapshot():
    files = {
        name: (CONFIG / name).read_text()
        for name in ("local.rules", "snort.lua", "sensor.env")
    }
    return dict(
        files=files,
        sha256=hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
    )


def write_files(files):
    for name, text in files.items():
        if name not in ("local.rules", "snort.lua", "sensor.env"):
            raise ValueError("Invalid managed file")
        temp = CONFIG / (name + ".jaltrix-new")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temp.replace(CONFIG / name)


def active():
    result = subprocess.run(
        ["systemctl", "is-active", UNIT], capture_output=True, text=True, timeout=10
    )
    return result.stdout.strip() == "active"


def restart_verified():
    run(["systemctl", "restart", UNIT])
    time.sleep(1)
    if not active():
        raise RuntimeError("Sensor failed to remain active")


def deploy(request):
    trusted(CONFIG)
    trusted(ENGINE)
    for name in ("local.rules", "snort.lua", "sensor.env"):
        trusted(CONFIG / name)
    before = snapshot()
    if request.get("expected") != before["sha256"]:
        raise ValueError("Sensor configuration changed; refresh the preview")
    files = dict(before["files"])
    operation = request["action"]
    if operation == "configure":
        files["snort.lua"], files["sensor.env"] = profile(
            request["interface"], request["network"]
        )
    elif operation == "deploy_rules":
        rules_valid(request["rules"])
        files["local.rules"] = request["rules"]
    elif operation == "rollback":
        saved = json.loads((STATE / "previous-profile.json").read_text())
        files = saved["files"]
    else:
        raise ValueError("Unsupported profile operation")
    owner = pwd.getpwnam("jaltrix-sensor")
    with tempfile.TemporaryDirectory(prefix="validate-", dir=STATE) as temp:
        directory = Path(temp)
        os.chown(directory, owner.pw_uid, owner.pw_gid)
        for name, content in files.items():
            (directory / name).write_text(content)
            (directory / name).chmod(0o644)
        result = run(
            [
                str(ENGINE),
                "-T",
                "-c",
                str(directory / "snort.lua"),
                "-R",
                str(directory / "local.rules"),
                "-l",
                str(directory),
            ],
            user=owner.pw_uid,
            group=owner.pw_gid,
            extra_groups=[],
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "TZ": "UTC"},
        )
        validation = result.stdout[-3000:]
    was_active = active()
    backup = STATE / "previous-profile.json"
    backup.write_text(json.dumps(before))
    backup.chmod(0o600)
    try:
        write_files(files)
        if was_active:
            restart_verified()
        if snapshot()["files"] != files:
            raise RuntimeError("Configuration verification failed")
    except Exception:
        write_files(before["files"])
        if was_active:
            restart_verified()
        raise
    return dict(
        state="verified",
        sha256=snapshot()["sha256"],
        active=was_active,
        validation=validation,
    )


def configure_firewall(request):
    trusted(CONFIG)
    networks = [
        str(ipaddress.ip_network(value.strip(), strict=True))
        for value in request["allowed"].split(",")
    ]
    if not 1 <= len(networks) <= 32 or any(
        ipaddress.ip_network(n).prefixlen == 0 for n in networks
    ):
        raise ValueError(
            "Specify 1–32 bounded destination networks; default routes are forbidden"
        )
    policy = dict(enabled=request.get("enabled") is True, allowed=networks)
    path = CONFIG / "response-policy.json"
    if path.is_symlink():
        raise ValueError("Policy symlink rejected")
    temp = CONFIG / "response-policy.json.new"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as stream:
        json.dump(policy, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)
    return dict(
        state="verified",
        policy=policy,
        effect="authorization_policy_only_no_network_changes",
    )


def nft_command(scope, allow_disabled=False):
    if scope == "lab":
        if not Path("/run/netns/jaltrix-lab").exists():
            raise RuntimeError("Isolated firewall lab is not installed")
        return ["/usr/sbin/ip", "netns", "exec", "jaltrix-lab", "/usr/sbin/nft"]
    if scope == "host":
        policy = CONFIG / "response-policy.json"
        if not policy.exists():
            raise PermissionError("Host firewall policy is not configured")
        trusted(policy)
        if (
            not allow_disabled
            and json.loads(policy.read_text()).get("enabled") is not True
        ):
            raise PermissionError("Host firewall is disabled by administrator policy")
        return ["/usr/sbin/nft"]
    raise PermissionError("Unsupported firewall scope")


def guard_host(address):
    policy = json.loads((CONFIG / "response-policy.json").read_text())
    if not any(address in ipaddress.ip_network(n) for n in policy["allowed"]):
        raise PermissionError("Target outside administrator-approved networks")
    protected = set()
    for link in json.loads(run(["/usr/sbin/ip", "-j", "addr", "show"]).stdout):
        for item in link.get("addr_info", []):
            protected.add(item["local"])
    for family in ("-4", "-6"):
        for route in json.loads(
            run(["/usr/sbin/ip", family, "-j", "route", "show", "default"]).stdout
        ):
            if route.get("gateway"):
                protected.add(route["gateway"])
    for line in Path("/etc/resolv.conf").read_text().splitlines():
        if line.strip().startswith("nameserver ") and len(line.split()) >= 2:
            protected.add(line.split()[1].split("%")[0])
    if str(address) in protected:
        raise PermissionError(
            "Local interface, default gateway or DNS resolver is protected"
        )


def firewall(request):
    action = request["action"]
    command = nft_command(
        request.get("scope"),
        allow_disabled=action in ("firewall_revoke", "firewall_status"),
    )
    address = ipaddress.ip_address(request["target"])
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise ValueError("Protected address")
    if request.get("scope") == "host" and action == "firewall_apply":
        guard_host(address)
    duration = request.get("ttl", 60)
    if type(duration) is not int or not 1 <= duration <= 3600:
        raise ValueError("TTL must be 1–3600 seconds")
    version = "4" if address.version == 4 else "6"
    action = request["action"]
    if action not in ("firewall_apply", "firewall_revoke", "firewall_status"):
        raise ValueError("Unknown firewall operation")
    # One dedicated table in the explicitly selected scope. Never flush unrelated rules.
    existing = subprocess.run(
        command + ["-j", "list", "table", "inet", "jaltrix"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if not existing.returncode:
        tables = [
            entry["table"]
            for entry in json.loads(existing.stdout).get("nftables", [])
            if "table" in entry
        ]
        if not tables or tables[0].get("comment") != "jaltrix-managed-v1":
            raise PermissionError("Existing table does not belong to JALTRIX")
    if existing.returncode and action == "firewall_apply":
        rules = 'add table inet jaltrix { comment "jaltrix-managed-v1"; }\n'
        for v, typ in [("4", "ipv4_addr"), ("6", "ipv6_addr")]:
            rules += (
                f"add set inet jaltrix blocked{v} {{ type {typ}; flags timeout; }}\n"
            )
        rules += "add chain inet jaltrix input { type filter hook input priority 0; policy accept; }\nadd chain inet jaltrix output { type filter hook output priority 0; policy accept; }\n"
        for chain in ("input", "output"):
            for fam, v in [("ip", "4"), ("ip6", "6")]:
                rules += (
                    f"add rule inet jaltrix {chain} {fam} "
                    + ("saddr" if chain == "input" else "daddr")
                    + f" @blocked{v} drop\n"
                )
        run(command + ["-f", "-"], input=rules)

    def present():
        result = subprocess.run(
            command
            + [
                "get",
                "element",
                "inet",
                "jaltrix",
                "blocked" + version,
                "{",
                str(address),
                "}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0

    already_present = present()
    if action == "firewall_apply" and not already_present:
        run(
            command + ["-f", "-"],
            input=f"add element inet jaltrix blocked{version} {{ {address} timeout {duration}s }}\n",
        )
    if action == "firewall_revoke" and present():
        run(
            command + ["-f", "-"],
            input=f"delete element inet jaltrix blocked{version} {{ {address} }}\n",
        )
    effective = present()
    if action == "firewall_apply" and not effective:
        raise RuntimeError("Firewall verification failed")
    if action == "firewall_revoke" and effective:
        raise RuntimeError("Firewall revocation failed")
    return dict(
        scope=request["scope"],
        namespace="jaltrix-lab" if request["scope"] == "lab" else "host",
        target=str(address),
        effective=effective,
        requested_ttl_seconds=duration,
        existing_timeout_preserved=already_present and action == "firewall_apply",
        state="verified",
    )


def main():
    if os.geteuid() != 0:
        raise PermissionError("Administrator authentication required")
    trusted(Path(__file__).resolve())
    raw = sys.stdin.buffer.read(1024 * 1024 + 8192)
    if len(raw) > 1024 * 1024 + 4096:
        raise ValueError("Request too large")
    request = json.loads(raw)
    actor = os.environ.get("PKEXEC_UID")
    if not actor or not actor.isdigit():
        raise PermissionError("Authenticated caller missing")
    if (
        not isinstance(request.get("reason"), str)
        or not 3 <= len(request["reason"]) <= 4000
    ):
        raise ValueError("A reason is required")
    if request.get("approved") is not True:
        raise PermissionError("Explicit approval required")
    STATE.mkdir(exist_ok=True, mode=0o755)
    trusted(STATE)
    with (STATE / "operation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            result = (
                configure_firewall(request)
                if request.get("action") == "configure_firewall"
                else firewall(request)
                if request.get("action", "").startswith("firewall_")
                else deploy(request)
            )
            record = dict(
                actor=actor,
                action=request["action"],
                reason=request["reason"],
                timestamp=time.time(),
                result=result,
            )
        except Exception as exc:
            record = dict(
                actor=actor,
                action=request.get("action"),
                timestamp=time.time(),
                error=str(exc),
            )
            raise
        finally:
            fd = os.open(
                STATE / "audit.jsonl",
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "a") as audit:
                audit.write(json.dumps(record) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)
