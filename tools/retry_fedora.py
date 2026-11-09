from pathlib import Path
import subprocess
import json

root = Path(__file__).resolve().parents[1]
out = root / "artifacts/matrix/fedora"
with (out / "run-retry.log").open("w") as log:
    r = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            "snort-soc-test-fedora-retry",
            "--cpus=2",
            "--memory=4g",
            "-v",
            f"{root}:/source:ro",
            "-v",
            f"{out}:/result",
            "registry.fedoraproject.org/fedora:44",
            "bash",
            "/source/tools/container_check_fedora.sh",
            "fedora",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
        timeout=1800,
    )
summary = json.loads((out / "summary.json").read_text())
summary["exit_code"] = r.returncode
summary["retry"] = "xdpyinfo package corrected"
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary))
