"""Measure an AI SDK research swarm under induced failures, with and without Chio.

The same scripted planner drives both configurations through the installed packages.
Chio runs the swarm as native processes under `chio process run`; the baseline runs the
same loop in one Node process with local tool callbacks and a restart-on-failure supervisor.
"""

import argparse
import difflib
import hashlib
import json
import os
import platform
import random
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
TYPESCRIPT = PACKAGE.parent.parent
sys.path.insert(0, str(PACKAGE / "qualification"))
sys.path.insert(0, str(HERE))

from journal_profiles import provider, requests  # noqa: E402
from qualify import command, installed_consumer, verify, write  # noqa: E402

from tools import SOURCES, corpus  # noqa: E402

BENCHMARK_FILES = ("planner.py", "tools.py", "chio_worker.mjs", "baseline_worker.mjs")
ROLES = ["coordinator"] + [f"researcher-{index}" for index in range(1, 5)]
SCENARIOS = {
    "steady": {},
    "worker-death": {"kill": {"role": "researcher-1", "attempt": 1, "tool": "read", "ordinal": 2}},
    "coordinator-death": {
        "kill": {"role": "coordinator", "attempt": {"chio": 2, "baseline": 1}, "tool": "publish"}
    },
    "host-death": {"interrupt": True},
    "cancel": {"interrupt": True, "cancel": True},
    "budget": {"max_calls": 27},
    "conflict": {"mode": "conflict"},
}
COMPLETING = ("steady", "worker-death", "coordinator-death", "host-death")
# The host is interrupted once the coordinator has suspended on its join and
# researcher 1 has completed its second read, both durable points.
INTERRUPTION = [
    {"role": "coordinator", "attempt": 1},
    {"role": "researcher-1", "attempt": 1, "tool": "read", "ordinal": 2},
]


def checksum(text):
    digest = hashlib.sha256(text.encode()).hexdigest()
    return "-".join(digest[i : i + 4] for i in range(0, len(digest), 4))


def resolve(spec, mode):
    """Kill specifications differ only where the native coordinator resumes in a later attempt."""
    if not spec:
        return None
    resolved = dict(spec)
    if isinstance(resolved.get("attempt"), dict):
        resolved["attempt"] = resolved["attempt"][mode]
    return resolved


def random_kill(rng):
    role = rng.choice(ROLES)
    if role == "coordinator":
        tool, ordinal = rng.choice(
            [("spawn_researcher", rng.randint(1, 4)), ("receive_findings", 1), ("publish", 1)]
        )
        attempt = {"chio": 1 if tool == "spawn_researcher" else 2, "baseline": 1}
    else:
        tool, ordinal = rng.choice([("read", rng.randint(1, 4)), ("send_findings", 1)])
        attempt = 1
    return {"role": role, "attempt": attempt, "tool": tool, "ordinal": ordinal}


def route(server, tool):
    return {"server_id": server, "tool_name": tool}


def effects(database):
    observed = {"reads": [], "reports": [], "messages": [], "timings": {}}
    if not database.exists():
        return observed
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "reads" in tables:
            observed["reads"] = [
                r[0] for r in db.execute("SELECT file_index FROM reads ORDER BY id")
            ]
        if "reports" in tables:
            observed["reports"] = [
                r[0] for r in db.execute("SELECT report FROM reports ORDER BY id")
            ]
        if "messages" in tables:
            observed["messages"] = [
                r[0] for r in db.execute("SELECT message_key FROM messages ORDER BY id")
            ]
        if "timings" in tables:
            for tool, duration in db.execute("SELECT tool, duration_ms FROM timings"):
                observed["timings"].setdefault(tool, []).append(duration)
    return observed


def handoffs(directory):
    """Native handoffs live in the host's mailbox store; the baseline records its own."""
    native = directory / "host" / "mailboxes.db"
    if native.exists():
        with sqlite3.connect(f"file:{native}?mode=ro", uri=True) as db:
            return [row[0] for row in db.execute("SELECT message_key FROM mailbox_messages")]
    return effects(directory / "effects.db")["messages"]


def valid_report(report, files):
    try:
        sources = json.loads(report)["sources"]
    except (ValueError, KeyError, TypeError):
        return False
    expected = [
        {"index": index, "path": str(path), "bytes": 8192, "checksum": checksum(path.read_text())}
        for index, path in enumerate(files, 1)
    ]
    return sources == expected


def stats(values):
    if not values:
        return None
    ordered = sorted(values)
    return {
        "count": len(values),
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(round(0.95 * len(ordered))) - 1)], 3),
        "max_ms": round(ordered[-1], 3),
    }


def latency(lines, keyed):
    originals, replays, seen = {}, {}, set()
    for entry in lines:
        bucket = originals
        if keyed:
            if entry["key"] in seen:
                bucket = replays
            seen.add(entry["key"])
        bucket.setdefault(entry["tool"], []).append(entry["ms"])
    return {
        "original": {tool: stats(values) for tool, values in sorted(originals.items())},
        "replay": {tool: stats(values) for tool, values in sorted(replays.items())},
    }


def ndjson(directory, pattern):
    return [
        json.loads(line)
        for path in sorted(directory.glob(pattern))
        for line in path.read_text().splitlines()
    ]


def summarize(
    directory, files, provider_db, started_ms, first_ms, completed, attempts, calls, keyed
):
    observed = effects(directory / "effects.db")
    observed["messages"] = handoffs(directory)
    valid = sum(valid_report(report, files) for report in observed["reports"])
    return {
        "completed": completed,
        "wall_ms": round(time.time() * 1000 - started_ms),
        "first_call_ms": None if first_ms is None else round(first_ms - started_ms),
        "publications": len(observed["reports"]),
        "valid_reports": valid,
        "unexpected_publications": len(observed["reports"]) - min(valid, 1),
        "reads": len(observed["reads"]),
        "distinct_reads": len(set(observed["reads"])),
        "duplicate_reads": len(observed["reads"]) - len(set(observed["reads"])),
        "messages": len(observed["messages"]),
        "duplicate_messages": len(observed["messages"]) - len(set(observed["messages"])),
        "provider_requests": len(requests(directory)) if provider_db.exists() else 0,
        "attempts": attempts,
        "latency": latency(calls, keyed),
        "handler": {tool: stats(values) for tool, values in sorted(observed["timings"].items())},
    }


def chio_trial(binary, consumer, directory, scenario, spec, endpoint):
    files = corpus(directory / "corpus")
    (directory / "policy.yaml").write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 2
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: sources
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: report
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: chio-process
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    server = lambda name: {  # noqa: E731
        "id": name,
        "command": [
            sys.executable,
            str(consumer / "tools.py"),
            "--server",
            name,
            "--database",
            str(directory / "effects.db"),
            "--corpus",
            str(directory / "corpus"),
        ],
    }
    write(
        directory / "host.json",
        {
            "schema": "chio.process.host.v1",
            "policy": "policy.yaml",
            "servers": [server("sources"), server("report")],
            "mailboxes": [
                {
                    "id": "findings",
                    "limits": {
                        "max_pending_messages": 4,
                        "max_messages": 16,
                        "max_pending_bytes": 16384,
                        "max_message_bytes": 4096,
                    },
                }
            ],
            "limits": {"max_processes": 8, "max_depth": 1, "max_calls": spec.get("max_calls", 64)},
            "spawn_templates": [
                {
                    "id": "researcher",
                    "max_budget_share_bps": 2500,
                    "tools": [route("sources", "read"), route("chio-ipc", "send_findings")],
                }
            ],
        },
    )
    initialized = json.loads(
        command(
            [
                binary,
                "process",
                "init",
                "--config",
                directory / "host.json",
                "--state",
                directory / "host",
            ],
            directory,
        ).stdout
    )
    (directory / "kernel.pub").write_text(initialized["kernel_key"] + "\n")
    settings = {
        "directory": str(directory),
        "mode": spec.get("mode", scenario),
        "endpoint": endpoint,
        "kill": resolve(spec.get("kill"), "chio"),
        "hang": INTERRUPTION if spec.get("interrupt") else None,
    }
    worker = {
        "command": [shutil.which("node"), str(consumer / "chio_worker.mjs")],
        "cwd": str(consumer),
        "input": settings,
        "timeout_seconds": 120,
    }
    write(
        directory / "worker-plan.json",
        {
            "schema": "chio.process.run.v1",
            "max_parallel": 2,
            "workers": [{"process": "root", "max_attempts": 4, **worker}],
            "templates": [{"id": "researcher", "max_attempts": 3, **worker}],
        },
    )
    invoke = [
        binary,
        "process",
        "run",
        "--state",
        directory / "host",
        "--plan",
        directory / "worker-plan.json",
    ]
    started_ms = time.time() * 1000
    if spec.get("interrupt"):
        interrupt_host(invoke, directory, [f"hang-{entry['role']}.json" for entry in INTERRUPTION])
        if spec.get("cancel"):
            cancelled = json.loads(
                command(
                    [
                        binary,
                        "process",
                        "cancel",
                        "--state",
                        directory / "host",
                        "--process",
                        "root",
                    ],
                    directory,
                ).stdout
            )
            assert cancelled["cancelled_processes"] >= 1, cancelled
    expected = scenario in COMPLETING or scenario.startswith("random")
    executed = command(invoke, directory, success=expected)
    if executed.stdout.strip():
        runner = json.loads(executed.stdout)
    else:
        # A cancelled coordinator is rejected before the runner opens a run report.
        assert spec.get("cancel") and "cancelled process" in executed.stderr, executed.stderr
        status = command(
            [binary, "--json", "process", "status", "--state", directory / "host"], directory
        )
        runner = {"complete": False, "workers": json.loads(status.stdout)["run"]["workers"]}
    assert runner["complete"] == expected, runner
    events = ndjson(directory, "*-receipts.ndjson")
    verified = verify(binary, directory, events)["receipts_verified"] if events else 0
    firsts = [json.loads(p.read_text())["at"] for p in directory.glob("*-first-receipt-1.json")]
    attempts = {}
    for w in runner["workers"]:
        role = "coordinator" if w["process"] == "root" else None
        for started in directory.glob(f"{w['process']}-started-1.json"):
            role = json.loads(started.read_text())["role"]
        attempts[role or w["process"]] = w["attempts"]
    summary = summarize(
        directory,
        files,
        directory / "provider.db",
        started_ms,
        min(firsts) if firsts else None,
        runner["complete"],
        attempts,
        ndjson(directory, "*-calls.ndjson"),
        True,
    )
    summary["receipts_verified"] = verified
    summary["denials"] = sum(1 for event in events if event["result"]["verdict"] != "allow")
    if expected:
        before = requests(directory)
        assert json.loads(command(invoke, directory).stdout) == runner, (
            "a completed run must be stable"
        )
        assert requests(directory) == before, "a completed run must not call the provider again"
    return summary


def gone(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] == "Z"
    except (FileNotFoundError, ProcessLookupError):
        return True


def interrupt_host(invoke, directory, markers):
    """Kill the host once every listed worker holds its durable point open."""
    with (directory / "host-interrupt.log").open("wb") as log:
        host = subprocess.Popen(list(map(str, invoke)), cwd=directory, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 120
            while not all((directory / marker).exists() for marker in markers):
                assert host.poll() is None, "host exited before the interruption point"
                assert time.monotonic() < deadline, "workers never reached the interruption point"
                time.sleep(0.05)
            workers = [json.loads((directory / marker).read_text())["pid"] for marker in markers]
            host.kill()
            host.wait(timeout=10)
            deadline = time.monotonic() + 5
            while not all(gone(pid) for pid in workers):
                assert time.monotonic() < deadline, "a worker outlived its native host"
                time.sleep(0.05)
            for marker in markers:
                (directory / marker).unlink()
        finally:
            if host.poll() is None:
                host.kill()
                host.wait(timeout=10)


def baseline_trial(consumer, directory, scenario, spec, endpoint):
    files = corpus(directory / "corpus")
    settings = {
        "directory": str(directory),
        "mode": spec.get("mode", scenario),
        "endpoint": endpoint,
        "database": str(directory / "effects.db"),
        "sources": list(map(str, files)),
        "kill": resolve(spec.get("kill"), "baseline"),
        "hang": INTERRUPTION if spec.get("interrupt") else None,
    }
    write(directory / "settings.json", settings)
    started_ms = time.time() * 1000
    attempts, completed = 0, False
    while attempts < 4 and not completed:
        attempts += 1
        with (directory / f"attempt-{attempts}.log").open("wb") as log:
            process = subprocess.Popen(
                [
                    shutil.which("node"),
                    "--disable-warning=ExperimentalWarning",
                    str(consumer / "baseline_worker.mjs"),
                    str(directory / "settings.json"),
                    str(attempts),
                ],
                cwd=consumer,
                stdout=log,
                stderr=log,
            )
            if spec.get("interrupt") and attempts == 1:
                deadline = time.monotonic() + 90
                marker = directory / "hang-coordinator.json"
                while not marker.exists():
                    assert process.poll() is None, "baseline exited before its interruption point"
                    assert time.monotonic() < deadline, (
                        "baseline never reached its interruption point"
                    )
                    time.sleep(0.02)
                marker.unlink()
                process.send_signal(signal.SIGKILL)
            process.wait(timeout=120)
        completed = process.returncode == 0
        if not completed:
            time.sleep(1)
    firsts = [json.loads(p.read_text())["at"] for p in directory.glob("first-call-1.json")]
    return summarize(
        directory,
        files,
        directory / "provider.db",
        started_ms,
        firsts[0] if firsts else None,
        completed,
        {"application": attempts},
        ndjson(directory, "calls.ndjson"),
        False,
    )


def check(scenario, mode, summary):
    """Behavior each configuration must reproduce; deviations fail the benchmark."""
    completes = scenario in COMPLETING or scenario.startswith("random")
    if mode == "chio":
        assert summary["duplicate_reads"] == 0 and summary["duplicate_messages"] == 0, summary
        assert summary["unexpected_publications"] == 0, summary
        if completes:
            assert summary["completed"] and summary["valid_reports"] == 1, summary
            assert summary["distinct_reads"] == SOURCES and summary["messages"] == 4, summary
        else:
            assert not summary["completed"] and summary["publications"] == 0, summary
        if scenario == "conflict":
            assert summary["denials"] >= 1, summary
        return
    if scenario in ("steady", "cancel", "budget"):
        assert summary["completed"] and summary["publications"] == 1, summary
    if scenario in ("worker-death", "host-death"):
        assert summary["completed"] and summary["duplicate_reads"] >= 1, summary
    if scenario == "coordinator-death":
        assert summary["completed"] and summary["publications"] == 2, summary
    if scenario == "conflict":
        assert summary["completed"] and summary["unexpected_publications"] == 1, summary


def integration():
    baseline = (HERE / "baseline_worker.mjs").read_text().splitlines()
    chio = (HERE / "chio_worker.mjs").read_text().splitlines()
    diff = [line for line in difflib.unified_diff(baseline, chio, lineterm="", n=0)]
    return {
        "baseline_worker_lines": len(baseline),
        "chio_worker_lines": len(chio),
        "lines_removed": sum(
            1 for line in diff if line.startswith("-") and not line.startswith("---")
        ),
        "lines_added": sum(
            1 for line in diff if line.startswith("+") and not line.startswith("+++")
        ),
    }


def exercise(binary, output, temporary, packages, majors, trials, seed, only=None):
    results = {}
    for major in majors:
        consumer = installed_consumer(major, temporary, packages)
        for name in BENCHMARK_FILES:
            shutil.copyfile(HERE / name, consumer / name)
        destination = output / major
        destination.mkdir()
        shutil.copyfile(consumer / "package-lock.json", destination / "consumer-lock.json")
        scenarios = dict(SCENARIOS)
        for trial in range(trials):
            rng = random.Random(f"{seed}:{major}:{trial}")
            scenarios[f"random-{trial + 1}"] = {"kill": random_kill(rng)}
        if only:
            scenarios = {name: spec for name, spec in scenarios.items() if name in only}
        results[major] = {}
        for scenario, spec in scenarios.items():
            results[major][scenario] = {"specification": spec}
            for mode in ("chio", "baseline"):
                directory = temporary / f"{major}-{scenario}-{mode}"
                directory.mkdir(mode=0o700)
                with provider(directory, consumer, scenario, "planner.py") as endpoint:
                    if mode == "chio":
                        summary = chio_trial(binary, consumer, directory, scenario, spec, endpoint)
                    else:
                        summary = baseline_trial(consumer, directory, scenario, spec, endpoint)
                check(scenario, mode, summary)
                case = destination / scenario / mode
                case.mkdir(parents=True)
                write(case / "summary.json", summary)
                write(case / "provider-requests.json", requests(directory))
                if mode == "chio":
                    for name in ("receipts.ndjson", "kernel.pub"):
                        if (directory / name).exists():
                            shutil.copyfile(directory / name, case / name)
                results[major][scenario][mode] = summary
                print(
                    json.dumps(
                        {
                            "sdk": major,
                            "scenario": scenario,
                            "mode": mode,
                            **{
                                key: summary[key]
                                for key in (
                                    "completed",
                                    "publications",
                                    "valid_reports",
                                    "duplicate_reads",
                                    "duplicate_messages",
                                    "provider_requests",
                                    "attempts",
                                    "wall_ms",
                                )
                            },
                        }
                    ),
                    flush=True,
                )
    return results


def cell(value, digits=1):
    return "" if value is None else f"{value:.{digits}f}"


def table(results):
    lines = []
    for major, scenarios in results.items():
        lines += [
            f"### {major}",
            "",
            "| Scenario | Chio completed | Chio publications | Chio valid reports "
            "| Chio duplicate reads | Chio attempts | Chio wall s "
            "| Baseline completed | Baseline publications | Baseline valid reports "
            "| Baseline duplicate reads | Baseline duplicate handoffs | Baseline attempts "
            "| Baseline wall s |",
            "| --- | --- | ---: | ---: | ---: | --- | ---: "
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        for scenario, outcome in scenarios.items():
            c, b = outcome["chio"], outcome["baseline"]
            researchers = [n for role, n in c["attempts"].items() if role != "coordinator"]
            attempts = f"coordinator {c['attempts'].get('coordinator', 0)}"
            if researchers:
                attempts += f", researchers {min(researchers)}-{max(researchers)}"
            lines.append(
                f"| {scenario} | {c['completed']} | {c['publications']} | {c['valid_reports']} "
                f"| {c['duplicate_reads']} | {attempts} | {c['wall_ms'] / 1000:.1f} "
                f"| {b['completed']} | {b['publications']} | {b['valid_reports']} "
                f"| {b['duplicate_reads']} | {b['duplicate_messages']} "
                f"| {b['attempts']['application']} | {b['wall_ms'] / 1000:.1f} |"
            )
        steady = scenarios["steady"]
        lines += [
            "",
            "| Tool | Chio round trip median ms | Chio round trip p95 ms | Tool handler median ms "
            "| Kernel and transport median ms | Baseline local call median ms |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
        for tool, chio in steady["chio"]["latency"]["original"].items():
            handler = steady["chio"]["handler"].get(tool)
            local = steady["baseline"]["latency"]["original"].get(tool)
            handler_median = None if handler is None else handler["median_ms"]
            overhead = None if handler is None else chio["median_ms"] - handler_median
            local_median = None if local is None else local["median_ms"]
            lines.append(
                f"| {tool} | {cell(chio['median_ms'])} | {cell(chio['p95_ms'])} "
                f"| {cell(handler_median, 2)} | {cell(overhead)} | {cell(local_median, 2)} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def main():
    if not __debug__:
        raise SystemExit("run the benchmark without Python optimization")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk", choices=("ai6", "ai7", "both"), default="both")
    parser.add_argument(
        "--trials", type=int, default=3, help="seeded random failure trials per SDK"
    )
    parser.add_argument("--seed", default="2026-09-06")
    parser.add_argument("--scenarios", help="comma-separated subset for development runs")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    package_dir = output / "packages"
    package_dir.mkdir()
    command(["npm", "run", "build", "--workspace", "@chio-protocol/ai-sdk-process"], TYPESCRIPT)
    packages = []
    for source in (TYPESCRIPT / "packages/process", PACKAGE):
        packed = json.loads(
            command(["npm", "pack", "--pack-destination", package_dir, "--json"], source).stdout
        )
        packages.append(package_dir / packed[0]["filename"])
    temporary = Path(tempfile.mkdtemp(prefix="chio-bench-"))
    binary = args.chio.resolve(strict=True)
    inputs = {
        "benchmark_checkout": {
            "commit": command(["git", "rev-parse", "HEAD"], PACKAGE).stdout.strip(),
            "dirty": bool(command(["git", "status", "--porcelain"], PACKAGE).stdout),
        },
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "cpus": os.cpu_count(),
        },
        "node": command(["node", "--version"], PACKAGE).stdout.strip(),
        "npm": command(["npm", "--version"], PACKAGE).stdout.strip(),
        "python": platform.python_version(),
        "sha256": {},
        "seed": args.seed,
        "random_trials": args.trials,
    }
    for path in [binary, *packages]:
        with path.open("rb") as stream:
            inputs["sha256"][path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    majors = ("ai6", "ai7") if args.sdk == "both" else (args.sdk,)
    try:
        only = set(args.scenarios.split(",")) if args.scenarios else None
        results = exercise(
            binary, output, temporary, packages, majors, args.trials, args.seed, only
        )
    except BaseException:
        print(f"Preserved private failure state: {temporary}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(temporary)
    report = {
        "schema": "chio.ai-sdk.adoption-benchmark.v1",
        "inputs": inputs,
        "integration": integration(),
        "results": results,
        "live_model_called": False,
    }
    write(output / "benchmark.json", report)
    if not args.scenarios:
        (output / "results.md").write_text(table(results))
        print(table(results))
    print(json.dumps({"integration": report["integration"]}))


if __name__ == "__main__":
    main()
