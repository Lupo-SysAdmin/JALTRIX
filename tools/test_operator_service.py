"""Native interactive authorization under the non-root desktop operator."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from snort_soc.services import ServiceManager

manager = ServiceManager()
initial = manager.snapshot()
assert initial["units"][0]["active"] == "inactive"
try:
    running = manager.apply("start", initial)
    assert running["units"][0]["active"] == "active"
finally:
    stopped = manager.apply("stop", manager.snapshot())
report = {"non_root_native_authorization": "PASS", "start": running, "stop": stopped}
Path("artifacts/operator-service.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report))
