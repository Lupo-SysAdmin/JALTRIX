"""Benign loopback probe for disposable JALTRIX VMs only."""

import json, socket, time
from pathlib import Path

assert socket.gethostname().startswith("jaltrix-"), "VM-only probe"
start = time.time()
with (
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver,
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender,
):
    receiver.bind(("127.0.0.1", 9999))
    for _ in range(25):
        sender.sendto(
            b"SNORT_SOC_LAB jaltrix virtual machine probe", ("127.0.0.1", 9999)
        )
        time.sleep(0.2)
        rows = [
            json.loads(line)
            for line in Path("/var/log/snort-soc/alert_json.txt")
            .read_text()
            .splitlines()
        ]
        hits = [
            row
            for row in rows
            if row.get("seconds", 0) >= int(start)
            and row.get("src_port") == sender.getsockname()[1]
            and row.get("rule") == "1:1000001:1"
        ]
        if hits:
            break
    assert hits, "No matching alert from live loopback capture"
print(json.dumps(dict(result="PASS", alerts=len(hits), sample=hits[0]), indent=2))
