"""Finite soak of the real collector with rename rotation, restart and SQL readers."""

import argparse, json, os, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from snort_soc.snort import AlertStore
from snort_soc.collector import atomic_json

parser = argparse.ArgumentParser()
parser.add_argument("--seconds", type=int, default=600)
parser.add_argument("--rate", type=int, default=1000)
parser.add_argument("--output", type=Path, default=ROOT / "artifacts/soak-v100.json")
args = parser.parse_args()
assert 10 <= args.seconds <= 3600 and 10 <= args.rate <= 10000 and args.rate % 10 == 0
with tempfile.TemporaryDirectory(prefix="jaltrix-soak-") as temporary:
    root = Path(temporary)
    source = root / "alerts.json"
    source.touch()
    (root / "live").mkdir()
    atomic_json(
        root / "live/collector.json", {"source": str(source), "retention_days": 0}
    )
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))

    def start():
        return subprocess.Popen(
            [sys.executable, "-m", "snort_soc.collector", "--data-dir", str(root)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    process = start()
    began = time.monotonic()
    total = 0
    rotations = 0
    peak_rss = 0
    queries = []
    restarted = False
    try:
        for step in range(args.seconds * 10):
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            delay = began + step / 10 - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            if step and step % 100 == 0:
                source.rename(root / f"alerts.{rotations}.json")
                source.touch()
                rotations += 1
            if step >= args.seconds * 5 and not restarted:
                process.terminate()
                process.communicate(timeout=10)
                process = start()
                restarted = True
            batch = args.rate // 10
            with source.open("ab") as stream:
                stream.write(
                    b"".join(
                        (
                            json.dumps(
                                {
                                    "rule": "1:1000001:1",
                                    "src_addr": "192.0.2.1",
                                    "seconds": 1794240000,
                                    "pkt_num": total + i,
                                    "msg": "benign soak",
                                }
                            )
                            + "\n"
                        ).encode()
                        for i in range(batch)
                    )
                )
            total += batch
            if step % 100 == 0:
                store = AlertStore(root / "live/alerts.sqlite3")
                tick = time.monotonic()
                store.query("live", query="sid:1000001", minutes=0)
                queries.append(time.monotonic() - tick)
                store.close()
                status = Path(f"/proc/{process.pid}/status").read_text()
                peak_rss = max(
                    peak_rss,
                    int(
                        next(
                            line
                            for line in status.splitlines()
                            if line.startswith("VmRSS:")
                        ).split()[1]
                    ),
                )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            store = AlertStore(root / "live/alerts.sqlite3")
            count = store.count("live")
            store.close()
            if count == total:
                break
            time.sleep(0.2)
        process.terminate()
        process.communicate(timeout=10)
        store = AlertStore(root / "live/alerts.sqlite3")
        count = store.count("live")
        rejected = store.db.execute("SELECT count(*) FROM quarantine").fetchone()[0]
        unique = store.db.execute(
            "SELECT count(DISTINCT json_extract(data,'$.raw_record.pkt_num')) FROM events"
        ).fetchone()[0]
        integrity = store.db.execute("PRAGMA quick_check").fetchone()[0]
        store.close()
        report = dict(
            result="PASS"
            if count == total == unique and rejected == 0 and integrity == "ok"
            else "FAIL",
            duration_seconds=round(time.monotonic() - began, 2),
            scheduled_seconds=args.seconds,
            rate=args.rate,
            written=total,
            stored=count,
            unique_packet_numbers=unique,
            rejected=rejected,
            rotations=rotations,
            restart=restarted,
            collector_peak_sampled_rss_kib=peak_rss,
            query_max_seconds=round(max(queries), 3),
            sqlite=integrity,
            scope="Synthetic file ingestion; real collector subprocess, rotation, restart and concurrent bounded SQL query; no capture engine or GUI",
        )
        args.output.write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2), flush=True)
        assert report["result"] == "PASS"
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=10)
