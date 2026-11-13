"""Reproducible synthetic host-store load/recovery checks, never Snort capture claims.

Runs entirely in an automatically removed temporary directory. The JSON report
contains timings/counts/platform versions, never local hostnames or user evidence.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import platform
import resource
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from jaltrix.backup import create_backup, restore_backup
from jaltrix.core import CaseStore
from jaltrix.host_events import HostEventStore

BASE = datetime(2026, 11, 12, tzinfo=timezone.utc)
KINDS = (
    "auth_failure",
    "auth_success",
    "file_change",
    "privilege_use",
    "network_alert",
    "process_exec",
    "service_change",
    "system_event",
    "file_change",
    "auth_failure",
)


def observation(index, total):
    kind = KINDS[index % len(KINDS)]
    source = (
        "snort"
        if kind == "network_alert"
        else "audit"
        if kind in ("file_change", "process_exec", "system_event")
        else "journal"
    )
    value = dict(
        event_id=f"synthetic-{index:09}",
        original_id=f"fixture:{index}",
        host_id=f"synthetic-host-{index % 8}",
        hostname=f"fixture-{index % 8}",
        source=source,
        kind=kind,
        timestamp=(BASE + timedelta(seconds=index / 50)).isoformat(),
        service="sshd"
        if kind in ("auth_success", "auth_failure")
        else "sudo"
        if kind == "privilege_use"
        else None,
        user=f"synthetic-user-{index % 100}",
        uid=1000,
        auid=1000,
        outcome="failure" if kind == "auth_failure" else "success",
        src_ip="192.0.2.10",
        dst_ip="198.51.100.10",
        dst_port=22,
        host_bound=False,
        path="/tmp/synthetic-observation.txt",
        message="Synthetic load fixture; no real packet capture or host activity",
        raw_record={"fixture": index, "provider": source},
    )
    if index == 10 or index >= total - 5:
        late = index != 10
        value.update(
            host_id="synthetic-late",
            hostname="fixture-late",
            source="journal",
            kind="auth_failure" if late else "auth_success",
            service="sshd",
            user="synthetic-late-user",
            src_ip="192.0.2.231",
            outcome="failure" if late else "success",
            timestamp=(
                BASE + timedelta(seconds=10 + index - (total - 5) if late else 30)
            ).isoformat(),
        )
    return value


def process_peak_rss_kib():
    # Linux VmHWM describes this executable's address space; ru_maxrss may retain
    # a launcher high-water mark across exec, so retain it only as a fallback.
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def run(total=100000, batch_size=5000):
    if not 100 <= total <= 1000000 or not 1 <= batch_size <= 5000:
        raise ValueError("Use 100..1000000 observations and batches of 1..5000")
    started = time.monotonic()
    memory_stages = {}

    def memory_stage(name):
        memory_stages[name] = process_peak_rss_kib()

    memory_stage("start")
    batch_times, drain_times, query_times = [], [], {}
    inserted = rejected = pending_peak = 0
    with tempfile.TemporaryDirectory(prefix="jaltrix-host-benchmark-") as temporary:
        root = Path(temporary)
        data = root / "data"
        path = data / "live/host-events.sqlite3"
        store = HostEventStore(path)
        restarted = False
        for offset in range(0, total, batch_size):
            stop = min(offset + batch_size, total)
            records = [observation(i, total) for i in range(offset, stop)]
            before = time.monotonic()
            result = store.ingest(records, "synthetic-source", {"next": stop})
            batch_times.append(time.monotonic() - before)
            inserted += result["inserted"]
            rejected += result["rejected"]
            pending_peak = max(pending_peak, result["correlation_pending"])
            if not restarted and stop >= total // 2:
                store.close()
                store = HostEventStore(path)
                assert store.checkpoint("synthetic-source") == {"next": stop}
                assert store.count() == stop
                restarted = True
            if time.monotonic() - started > 300:
                raise RuntimeError("Synthetic ingestion exceeded 300 seconds")
        ingestion_seconds = time.monotonic() - started
        memory_stage("after_ingest")
        assert inserted == total and rejected == 0 and store.count() == total
        for _ in range(total // 100 + 100):
            before = time.monotonic()
            result = store.ingest([])
            drain_times.append(time.monotonic() - before)
            if not result["correlation_pending"]:
                break
            if time.monotonic() - started > 300:
                raise RuntimeError("Correlation drain exceeded 300 seconds")
        assert result["correlation_pending"] == 0
        memory_stage("after_drain")
        correlations = store.correlations()
        assert (
            len(correlations) == 1
            and correlations[0]["rule_id"] == "ssh_failures_then_success"
        )
        correlation = correlations[0]
        assert len(correlation["event_ids"]) == 6
        before = time.monotonic()
        duplicate_result = store.ingest(
            [observation(i, total) for i in range(min(total, batch_size))],
            "synthetic-source",
            {"next": total, "replayed": True},
        )
        duplicate_seconds = time.monotonic() - before
        assert duplicate_result["duplicates"] == min(total, batch_size)
        assert duplicate_result["inserted"] == 0 and store.count() == total
        assert store.checkpoint("synthetic-source") == {"next": total, "replayed": True}
        queries = {
            "recent_200": lambda: store.events(limit=200),
            "filtered_200": lambda: store.events(
                source="audit",
                kind="process_exec",
                host_id="synthetic-host-1",
                limit=200,
            ),
            "search_200": lambda: store.events(query="fixture", limit=200),
            "count": store.count,
            "hosts": store.hosts,
            "correlations": store.correlations,
            "evidence": lambda: store.correlation_events(correlation["id"]),
        }
        for name, query in queries.items():
            durations = []
            for _ in range(3):
                before = time.monotonic()
                query()
                durations.append(time.monotonic() - before)
            query_times[name] = round(max(durations), 6)
        memory_stage("after_queries")
        assert store.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        memory_stage("after_integrity")
        assert store.db.execute("PRAGMA foreign_key_check").fetchall() == []
        database_bytes = sum(
            p.stat().st_size for p in path.parent.glob("host-events.sqlite3*")
        )
        cases = CaseStore(data / "live/cases.sqlite3", "live")
        case_id = store.create_case(correlation["id"], cases, language="en-US")
        before = time.monotonic()
        retention = store.retain(days=0, max_events=1)
        retention_seconds = time.monotonic() - before
        memory_stage("after_retention")
        assert retention["removed"] == total - 6
        assert retention["preserved"] == retention["stored"] == 6
        assert retention["pinned_over_limit"] is True
        assert store.get_correlation(correlation["id"])["case_ids"] == [case_id]
        before = time.monotonic()
        archive = root / "backup.zip"
        backup_result = create_backup(data, archive)
        memory_stage("after_backup")
        restored_path = root / "restored"
        restore_result = restore_backup(archive, restored_path)
        memory_stage("after_restore")
        backup_seconds = time.monotonic() - before
        restored = HostEventStore(restored_path / "live/host-events.sqlite3")
        restored_cases = CaseStore(restored_path / "live/cases.sqlite3", "live")
        assert restored.count() == 6
        assert restored.get_correlation(correlation["id"])["case_ids"] == [case_id]
        assert restored.correlation_events(
            correlation["id"]
        ) == store.correlation_events(correlation["id"])
        assert restored.checkpoint("synthetic-source") == {
            "next": total,
            "replayed": True,
        }
        assert [case["id"] for case in restored_cases.list()] == [case_id]
        assert restored.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert restored.db.execute("PRAGMA foreign_key_check").fetchall() == []
        restored.close()
        restored_cases.db.close()
        cases.db.close()
        store.close()
    return {
        "scope": "Synthetic normalized host observations in a temporary database; no GUI, real host capture, Snort packet capture, or throughput guarantee.",
        "fixture_distribution": "Eight synthetic hosts with mixed journal/audit/snort observations plus a ninth host for a late SSH correlation. Snort records are synthetic and not bound to real hosts.",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "observations": total,
        "batch_size": batch_size,
        "batches": len(batch_times),
        "inserted": inserted,
        "rejected": rejected,
        "ingestion_elapsed_seconds": round(ingestion_seconds, 6),
        "max_ingest_batch_seconds": round(max(batch_times), 6),
        "peak_pending_time_buckets": pending_peak,
        "drain_passes": len(drain_times),
        "drain_elapsed_seconds": round(sum(drain_times), 6),
        "max_drain_pass_seconds": round(max(drain_times), 6),
        "final_pending": 0,
        "restart_checkpoint_verified": restarted,
        "duplicate_replay_count": duplicate_result["duplicates"],
        "duplicate_replay_seconds": round(duplicate_seconds, 6),
        "late_correlations": len(correlations),
        "query_max_seconds": query_times,
        "database_and_wal_bytes_before_retention": database_bytes,
        "retention": retention,
        "retention_seconds": round(retention_seconds, 6),
        "backup_restore_seconds": round(backup_seconds, 6),
        "backup_files": backup_result["files"],
        "restored_files": restore_result["files"],
        "restored_case_evidence_and_checkpoint_verified": True,
        "integrity_check": "ok",
        "foreign_key_check": "ok",
        "peak_process_rss_kib": process_peak_rss_kib(),
        "memory_measurement": "Linux /proc/self/status VmHWM; ru_maxrss only as a fallback",
        "memory_stages_peak_rss_kib": memory_stages,
        "total_elapsed_seconds": round(time.monotonic() - started, 6),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=100000)
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/v130/host-benchmark.json")
    )
    arguments = parser.parse_args()
    result = run(arguments.events, arguments.batch_size)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
