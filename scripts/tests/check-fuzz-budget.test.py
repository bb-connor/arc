#!/usr/bin/env python3
"""Behavior tests for scripts/check-fuzz-budget.sh against a fake gh CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(os.environ.get("FUZZ_BUDGET_SCRIPT", ROOT / "scripts/check-fuzz-budget.sh"))
REPO = "owner/repo"
WORKFLOW = "fuzz.yml"
ENVELOPES = {
    "cflite": ["cflite_pr.yml", "cflite_batch.yml"],
    "native": ["fuzz.yml"],
    "mutation": ["mutants.yml", "mutants-fuzz-cocoverage.yml", "proof-mutants.yml"],
}
NOW = int(time.time())

FAKE_GH = r"""#!/usr/bin/env python3
import os, re, sys
from pathlib import Path
fixtures = Path(os.environ["FAKE_GH_DIR"])
path = sys.argv[-1]
with open(fixtures / "calls.log", "a", encoding="utf-8") as log:
    log.write(path + "\n")
listing = re.match(r"repos/[^/]+/[^/]+/actions/workflows/([^/]+)/runs\?created=([^&]+)&", path)
jobs = re.match(r"repos/[^/]+/[^/]+/actions/runs/(\d+)/jobs\?", path)
if listing:
    name = "runs-" + listing.group(1) + ("-slice" if ".." in listing.group(2) else "")
elif jobs:
    name = "jobs-" + jobs.group(1)
else:
    sys.stderr.write("unexpected path " + path + "\n")
    sys.exit(1)
error = fixtures / (name + ".err")
if error.exists():
    sys.stderr.write(error.read_text())
    sys.exit(1)
body = fixtures / (name + ".json")
if not body.exists():
    sys.stderr.write("gh: Not Found (HTTP 404)\n")
    sys.exit(1)
sys.stdout.write(body.read_text())
"""


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(run_id: int, start: int, end: int, status: str = "completed", attempt: int = 1) -> dict:
    return {
        "id": run_id,
        "run_attempt": attempt,
        "status": status,
        "created_at": iso(start),
        "run_started_at": iso(start),
        "updated_at": iso(end),
    }


def job(start: int, end: int | None, runner: str | None) -> dict:
    return {
        "started_at": iso(start),
        "completed_at": None if end is None else iso(end),
        "runner_name": runner,
    }


class Case:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text(FAKE_GH, encoding="utf-8")
        gh.chmod(0o755)

    def listing(
        self,
        runs: list[dict],
        total: int | None = None,
        slice_: bool = False,
        workflow: str = WORKFLOW,
    ) -> None:
        suffix = "-slice" if slice_ else ""
        payload = {"total_count": len(runs) if total is None else total, "workflow_runs": runs}
        (self.dir / f"runs-{workflow}{suffix}.json").write_text(json.dumps(payload))

    def quiet(self, *envelopes: str) -> None:
        for envelope in envelopes:
            for workflow in ENVELOPES[envelope]:
                if not (self.dir / f"runs-{workflow}.json").exists():
                    self.listing([], workflow=workflow)

    def jobs(self, run_id: int, jobs: list[dict]) -> None:
        (self.dir / f"jobs-{run_id}.json").write_text(json.dumps({"jobs": jobs}))

    def error(self, name: str, text: str) -> None:
        (self.dir / f"{name}.err").write_text(text)

    def calls(self) -> list[str]:
        log = self.dir / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def check(self, scope: str = "native", **env: str) -> subprocess.CompletedProcess[str]:
        full_env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "FAKE_GH_DIR": str(self.dir),
            "GH_FUZZ_BUDGET_SCOPE": scope,
            "HOME": str(self.dir),
        }
        full_env.update(env)
        return subprocess.run(
            ["bash", str(SCRIPT), REPO],
            env=full_env,
            capture_output=True,
            text=True,
            check=False,
        )


def expect(result: subprocess.CompletedProcess[str], code: int, *needles: str) -> None:
    output = result.stdout + result.stderr
    if result.returncode != code:
        raise AssertionError(f"expected exit {code}, got {result.returncode}:\n{output}")
    for needle in needles:
        if needle not in output:
            raise AssertionError(f"missing {needle!r} in output:\n{output}")


def queued_time_is_not_runner_time() -> None:
    case = Case()
    start = NOW - 3 * 86400
    case.listing([run(1, start, start + 86400)])
    case.jobs(1, [job(start, start + 86400, ""), job(start + 60, start + 660, "GitHub Actions 7")])
    expect(
        case.check(),
        0,
        "workflow=fuzz.yml runs=1 queried=1 executed=10 min",
        "envelope=native window=30 days, used=10 min, cap=26000 min, remaining=25990 min",
    )


def parallel_matrix_jobs_each_count() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(2, start, start + 1860)], workflow="cflite_batch.yml")
    case.jobs(2, [job(start, start + 36000, f"runner-{index}") for index in range(3)])
    case.quiet("cflite")
    expect(
        case.check("cflite"),
        1,
        "envelope=cflite window=30 days, used=1800 min, cap=1800 min, remaining=0 min",
        "HALT - envelope=cflite used 1800 min >= cap 1800 min",
    )


def cflite_cap_covers_pr_and_batch() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(20, start, start + 60)], workflow="cflite_pr.yml")
    case.listing([run(21, start, start + 60)], workflow="cflite_batch.yml")
    case.jobs(20, [job(start, start + 900 * 60, "runner")])
    case.jobs(21, [job(start, start + 899 * 60, "runner")])
    expect(case.check("cflite"), 0, "used=1799 min, cap=1800 min, remaining=1 min")
    case.jobs(21, [job(start, start + 900 * 60, "runner")])
    expect(case.check("cflite"), 1, "HALT - envelope=cflite used 1800 min >= cap 1800 min")


def native_cap_is_separate() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(22, start, start + 60)])
    case.jobs(22, [job(start, start + 25999 * 60, "runner")])
    case.quiet("cflite", "mutation")
    expect(case.check("all"), 0, "envelope=native window=30 days, used=25999 min, cap=26000 min")
    case.jobs(22, [job(start, start + 26000 * 60, "runner")])
    result = case.check("all")
    expect(result, 1, "HALT - envelope=native used 26000 min >= cap 26000 min")
    assert "envelope=cflite window=30 days, used=0 min, cap=1800 min" in result.stdout, result.stdout


def mutation_lanes_are_reported_not_capped() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(23, start, start + 60)], workflow="mutants.yml")
    case.jobs(23, [job(start, start + 500000 * 60, "runner")])
    case.quiet("mutation")
    expect(
        case.check("mutation"),
        0,
        "envelope=mutation window=30 days, used=500000 min, reported only, not capped",
    )
    assert "HALT" not in case.check("mutation").stderr


def mutation_errors_do_not_fail_the_gate() -> None:
    case = Case()
    case.listing([run(24, NOW - 600, NOW - 300)], workflow="proof-mutants.yml")
    case.error("jobs-24", "gh: Server Error (HTTP 502)\n")
    case.quiet("mutation", "cflite", "native")
    expect(case.check("mutation"), 0, "envelope=mutation usage is unverified")
    result = case.check("all")
    expect(result, 0, "envelope=mutation usage is unverified", "envelope=native window=30 days")


def unknown_scope_fails_closed() -> None:
    case = Case()
    expect(case.check("everything"), 2, "unknown GH_FUZZ_BUDGET_SCOPE: everything")


def cap_warn_mode_reports_overrun() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(2, start, start + 1860)], workflow="cflite_pr.yml")
    case.jobs(2, [job(start, start + 1800 * 60, "runner")])
    case.quiet("cflite")
    expect(
        case.check("cflite", GH_FUZZ_BUDGET_CAP_MODE="warn"),
        0,
        "HALT - envelope=cflite used 1800 min >= cap 1800 min",
        "continuing because GH_FUZZ_BUDGET_CAP_MODE=warn",
    )


def running_job_counts_until_now() -> None:
    case = Case()
    start = NOW - 1170
    case.listing([run(3, start, start + 5, status="in_progress")])
    case.jobs(3, [job(start, None, "runner")])
    result = case.check(GH_FUZZ_BUDGET_LEDGER=str(case.dir / "ledger.json"))
    expect(result, 0, "used=20 min")
    ledger = json.loads((case.dir / "ledger.json").read_text())
    assert ledger == {"repo": REPO, "runs": {}}, ledger


def large_window_is_listed_by_day() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([], total=1500)
    case.listing([run(4, start, start + 600), run(5, start, start + 600)], slice_=True)
    case.jobs(4, [job(start, start + 600, "runner")])
    case.jobs(5, [job(start, start + 1200, "runner")])
    expect(case.check(), 0, "runs=2 queried=2 executed=30 min", "used=30 min")
    slices = [call for call in case.calls() if "created=" in call and ".." in call]
    assert len(slices) == 30, slices


def truncated_day_fails_closed() -> None:
    case = Case()
    case.listing([], total=1500)
    case.listing([run(6, NOW - 600, NOW - 300)], total=1001, slice_=True)
    expect(case.check(), 2, "more than 1000 runs in one day")


def short_listing_fails_closed() -> None:
    case = Case()
    case.listing([run(7, NOW - 600, NOW - 300)], total=2)
    expect(case.check(), 2, "returned 1 of 2 runs")


def jobs_api_failure_fails_closed() -> None:
    case = Case()
    case.listing([run(8, NOW - 600, NOW - 300)])
    case.error("jobs-8", "gh: Server Error (HTTP 502)\n")
    expect(case.check(), 2, "GitHub API failed")


def jobs_rate_limit_follows_mode() -> None:
    case = Case()
    case.listing([run(9, NOW - 600, NOW - 300)])
    case.error("jobs-9", "gh: API rate limit exceeded (HTTP 403)\n")
    expect(case.check(), 2, "rate limited while checking fuzz.yml")
    expect(
        case.check(GH_FUZZ_BUDGET_RATE_LIMIT_MODE="warn"),
        0,
        "continuing because GH_FUZZ_BUDGET_RATE_LIMIT_MODE=warn",
    )


def missing_workflow_fails_closed() -> None:
    case = Case()
    expect(case.check(), 2, "workflow fuzz.yml is not registered")


def ledger_skips_completed_runs() -> None:
    case = Case()
    start = NOW - 86400
    old = NOW - 40 * 86400
    case.listing([run(10, start, start + 600), run(11, start, start + 600, attempt=2)])
    case.jobs(11, [job(start, start + 300, "runner")])
    ledger = case.dir / "ledger.json"
    other_workflow = {"seconds": 60, "created": iso(start)}
    ledger.write_text(
        json.dumps(
            {
                "repo": REPO,
                "runs": {
                    "10:1": {"seconds": 600, "created": iso(start)},
                    "98:1": other_workflow,
                    "99:1": {"seconds": 60, "created": iso(old)},
                },
            }
        )
    )
    expect(case.check(GH_FUZZ_BUDGET_LEDGER=str(ledger)), 0, "queried=1", "used=15 min")
    assert not any("/runs/10/jobs" in call for call in case.calls()), case.calls()
    written = json.loads(ledger.read_text())
    assert written == {
        "repo": REPO,
        "runs": {
            "10:1": {"seconds": 600, "created": iso(start)},
            "11:2": {"seconds": 300, "created": iso(start)},
            "98:1": other_workflow,
        },
    }, written


def foreign_ledger_is_ignored() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(12, start, start + 600)])
    case.jobs(12, [job(start, start + 600, "runner")])
    ledger = case.dir / "ledger.json"
    ledger.write_text(
        json.dumps({"repo": "other/repo", "runs": {"12:1": {"seconds": 0, "created": iso(start)}}})
    )
    expect(
        case.check(GH_FUZZ_BUDGET_LEDGER=str(ledger)),
        0,
        "ignoring unusable ledger",
        "used=10 min",
    )


def malformed_ledger_is_ignored() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(13, start, start + 600)])
    case.jobs(13, [job(start, start + 600, "runner")])
    ledger = case.dir / "ledger.json"
    ledger.write_text(json.dumps({"repo": REPO, "runs": {"13:1": 0}}))
    expect(
        case.check(GH_FUZZ_BUDGET_LEDGER=str(ledger)),
        0,
        "ignoring unusable ledger",
        "queried=1",
        "used=10 min",
    )


CASES = [
    queued_time_is_not_runner_time,
    parallel_matrix_jobs_each_count,
    cflite_cap_covers_pr_and_batch,
    native_cap_is_separate,
    mutation_lanes_are_reported_not_capped,
    mutation_errors_do_not_fail_the_gate,
    unknown_scope_fails_closed,
    cap_warn_mode_reports_overrun,
    running_job_counts_until_now,
    large_window_is_listed_by_day,
    truncated_day_fails_closed,
    short_listing_fails_closed,
    jobs_api_failure_fails_closed,
    jobs_rate_limit_follows_mode,
    missing_workflow_fails_closed,
    ledger_skips_completed_runs,
    foreign_ledger_is_ignored,
    malformed_ledger_is_ignored,
]


def main() -> int:
    failures = 0
    for case in CASES:
        try:
            case()
        except AssertionError as error:
            failures += 1
            print(f"FAIL {case.__name__}: {error}")
        else:
            print(f"PASS {case.__name__}")
    print(f"{len(CASES) - failures}/{len(CASES)} fuzz budget cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
