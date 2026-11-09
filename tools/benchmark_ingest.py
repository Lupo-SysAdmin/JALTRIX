"""Measured finite-duration sustained ingestion, not a throughput guarantee."""

import json
from pathlib import Path
import platform
import resource
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jaltrix.snort import AlertStore

results = []
for rate in [1000, 10000]:
    with tempfile.TemporaryDirectory(prefix="jaltrix-benchmark-") as tmp:
        path = Path(tmp) / "alerts.txt"
        path.touch()
        duration = 5
        total = rate * duration
        base = {
            "seconds": 1794234000,
            "rule": "1:1000001:1",
            "src_addr": "192.0.2.1",
            "dst_addr": "198.51.100.1",
            "proto": "UDP",
            "priority": 2,
            "msg": "benign benchmark",
            "action": "allow",
        }
        started = time.monotonic()

        def writer():
            with path.open("ab", buffering=0) as f:
                for step in range(duration * 10):
                    delay = started + step / 10 - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
                    f.write(
                        b"".join(
                            (
                                json.dumps(dict(base, pkt_num=step * (rate // 10) + i))
                                + "\n"
                            ).encode()
                            for i in range(rate // 10)
                        )
                    )

        thread = threading.Thread(target=writer)
        thread.start()
        store = AlertStore(Path(tmp) / "events.sqlite")
        imported = rejected = 0
        while thread.is_alive() or imported < total:
            batch = store.ingest(path, "live", limit=5000)
            imported += batch["inserted"]
            rejected += batch["rejected"]
            if time.monotonic() - started > 90:
                raise RuntimeError("Benchmark timed out")
            if batch["inserted"] == 0:
                time.sleep(0.01)
        thread.join()
        elapsed = time.monotonic() - started
        assert store.count("live") == total and rejected == 0
        results.append(
            {
                "target_events_per_second": rate,
                "duration_scheduled_seconds": duration,
                "records": total,
                "elapsed_seconds": round(elapsed, 3),
                "drain_after_schedule_seconds": round(max(0, elapsed - duration), 3),
                "lost_or_rejected": rejected,
                "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            }
        )
        store.close()
report = {
    "platform": platform.platform(),
    "python": platform.python_version(),
    "scope": "5-second synthetic runs; no GUI or packet capture",
    "results": results,
}
Path("artifacts/benchmark-v040.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
