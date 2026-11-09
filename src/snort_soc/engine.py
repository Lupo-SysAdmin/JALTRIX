"""Rootless, bounded offline Snort execution and PCAP provenance."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]


def find_engine():
    # Explicit opt-in path, then system executable, then local development build.
    candidates = [
        os.environ.get("SNORT_SOC_ENGINE"),
        shutil.which("snort"),
        Path("/usr/local/lib/snort-soc-engine/bin/snort"),
        ROOT / ".runtime/snort-3.13.2.0/bin/snort",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return Path(candidate).resolve()
    return None


from .capture import inspect as inspect_pcap, convert_to_pcap


def replay(pcap, rules, output_root, timeout=90):
    engine = find_engine()
    if engine is None:
        raise RuntimeError("Snort is not installed or configured")
    info = inspect_pcap(pcap)
    rules = Path(rules).resolve(strict=True)
    if not rules.is_file() or rules.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Rules must be a regular file under 8 MiB")
    run = Path(output_root) / uuid.uuid4().hex
    run.mkdir(parents=True, mode=0o700)
    # Freeze evidence and rules before validation/replay; never edit external files.
    pcap_copy = run / ("input.pcapng" if info["format"] == "PCAPNG" else "input.pcap")
    shutil.copyfile(info["path"], pcap_copy)
    copied_info = inspect_pcap(pcap_copy)
    if copied_info["sha256"] != info["sha256"]:
        raise ValueError("PCAP changed during import")
    replay_input = pcap_copy
    if info["format"] == "PCAPNG":
        replay_input = run / "converted.pcap"
        convert_to_pcap(pcap_copy, replay_input)
        info["replay_sha256"] = inspect_pcap(replay_input)["sha256"]
    rules_copy = run / "local.rules"
    shutil.copyfile(rules, rules_copy)
    config = run / "snort.lua"
    config.write_text(
        """-- Managed offline profile. No Lua from the input log/PCAP.
ips = { enable_builtin_rules = false }
alert_json = { file = true, fields = 'timestamp seconds pkt_num proto src_addr src_port dst_addr dst_port rule msg class priority action' }
""",
        encoding="utf-8",
    )
    env = dict(os.environ, TZ="UTC")
    base = [str(engine), "-c", str(config), "-R", str(rules_copy), "-l", str(run)]
    with (run / "validation.log").open("wb") as log:
        checked = subprocess.run(
            base + ["-T"],
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=env,
        )
    if checked.returncode:
        raise RuntimeError(f"Snort validation failed; see {run / 'validation.log'}")
    with (run / "replay.log").open("wb") as log:
        completed = subprocess.run(
            base + ["-r", str(replay_input), "-A", "alert_json", "-k", "none"],
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=env,
        )
    if completed.returncode:
        raise RuntimeError(f"Snort replay failed; see {run / 'replay.log'}")
    alert_path = run / "alert_json.txt"
    if not alert_path.exists():
        alert_path.touch(mode=0o600)
    info.update(
        imported_path=str(pcap_copy),
        rules_sha256=hashlib.sha256(rules_copy.read_bytes()).hexdigest(),
        log_path=str(alert_path),
        engine=str(engine),
        run_path=str(run),
        checksum_validation="disabled for offline replay (-k none)",
    )
    import json

    (run / "provenance.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return info


def validate_draft(text, output_root, timeout=30):
    engine = find_engine()
    if engine is None:
        raise RuntimeError("Snort is not installed or configured")
    if not text.strip() or len(text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("Rule draft must contain 1 byte to 1 MiB")
    run = Path(output_root) / uuid.uuid4().hex
    run.mkdir(parents=True, mode=0o700)
    rules = run / "local.rules"
    rules.write_text(text, encoding="utf-8")
    config = run / "snort.lua"
    config.write_text("ips = { enable_builtin_rules = false }\n", encoding="utf-8")
    logfile = run / "validation.log"
    with logfile.open("wb") as log:
        result = subprocess.run(
            [str(engine), "-c", str(config), "-R", str(rules), "-T", "-l", str(run)],
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    return dict(
        valid=result.returncode == 0,
        rules_path=str(rules),
        log_path=str(logfile),
        output=logfile.read_text(errors="replace")[-8000:],
        sha256=hashlib.sha256(rules.read_bytes()).hexdigest(),
    )
