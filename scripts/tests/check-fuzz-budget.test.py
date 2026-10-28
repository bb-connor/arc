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

    def listing(self, runs: list[dict], total: int | None = None, slice_: bool = False) -> None:
        suffix = "-slice" if slice_ else ""
        payload = {"total_count": len(runs) if total is None else total, "workflow_runs": runs}
        (self.dir / f"runs-{WORKFLOW}{suffix}.json").write_text(json.dumps(payload))

    def jobs(self, run_id: int, jobs: list[dict]) -> None:
        (self.dir / f"jobs-{run_id}.json").write_text(json.dumps({"jobs": jobs}))

    def error(self, name: str, text: str) -> None:
        (self.dir / f"{name}.err").write_text(text)

    def calls(self) -> list[str]:
        log = self.dir / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def check(self, cap: int, **env: str) -> subprocess.CompletedProcess[str]:
        full_env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "FAKE_GH_DIR": str(self.dir),
            "GH_FUZZ_BUDGET_WORKFLOWS": WORKFLOW,
            "GH_FUZZ_BUDGET_MINUTES": str(cap),
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
    expect(case.check(60), 0, "used=10 min", "workflow=fuzz.yml runs=1 queried=1 executed=10 min")


def parallel_matrix_jobs_each_count() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(2, start, start + 1860)])
    case.jobs(2, [job(start, start + 1800, f"runner-{index}") for index in range(3)])
    expect(case.check(60), 1, "used=90 min", "HALT - used 90 min >= cap 60 min")


def cap_warn_mode_reports_overrun() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(2, start, start + 1860)])
    case.jobs(2, [job(start, start + 1800, "runner")])
    expect(
        case.check(30, GH_FUZZ_BUDGET_CAP_MODE="warn"),
        0,
        "HALT - used 30 min >= cap 30 min",
        "continuing because GH_FUZZ_BUDGET_CAP_MODE=warn",
    )


def running_job_counts_until_now() -> None:
    case = Case()
    start = NOW - 1170
    case.listing([run(3, start, start + 5, status="in_progress")])
    case.jobs(3, [job(start, None, "runner")])
    result = case.check(1000, GH_FUZZ_BUDGET_LEDGER=str(case.dir / "ledger.json"))
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
    expect(case.check(1000), 0, "runs=2 queried=2 executed=30 min", "used=30 min")
    slices = [call for call in case.calls() if "created=" in call and ".." in call]
    assert len(slices) == 30, slices


def truncated_day_fails_closed() -> None:
    case = Case()
    case.listing([], total=1500)
    case.listing([run(6, NOW - 600, NOW - 300)], total=1001, slice_=True)
    expect(case.check(1000), 2, "more than 1000 runs in one day")


def short_listing_fails_closed() -> None:
    case = Case()
    case.listing([run(7, NOW - 600, NOW - 300)], total=2)
    expect(case.check(1000), 2, "returned 1 of 2 runs")


def jobs_api_failure_fails_closed() -> None:
    case = Case()
    case.listing([run(8, NOW - 600, NOW - 300)])
    case.error("jobs-8", "gh: Server Error (HTTP 502)\n")
    expect(case.check(1000), 2, "GitHub API failed")


def jobs_rate_limit_follows_mode() -> None:
    case = Case()
    case.listing([run(9, NOW - 600, NOW - 300)])
    case.error("jobs-9", "gh: API rate limit exceeded (HTTP 403)\n")
    expect(case.check(1000), 2, "rate limited while checking fuzz.yml")
    expect(
        case.check(1000, GH_FUZZ_BUDGET_RATE_LIMIT_MODE="warn"),
        0,
        "continuing because GH_FUZZ_BUDGET_RATE_LIMIT_MODE=warn",
    )


def missing_workflow_fails_closed() -> None:
    case = Case()
    expect(case.check(1000), 2, "workflow fuzz.yml is not registered")


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
    expect(case.check(1000, GH_FUZZ_BUDGET_LEDGER=str(ledger)), 0, "queried=1", "used=15 min")
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
        case.check(1000, GH_FUZZ_BUDGET_LEDGER=str(ledger)),
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
        case.check(1000, GH_FUZZ_BUDGET_LEDGER=str(ledger)),
        0,
        "ignoring unusable ledger",
        "queried=1",
        "used=10 min",
    )


def invalid_cap_fails_closed() -> None:
    case = Case()
    expect(case.check(0), 2, "GH_FUZZ_BUDGET_MINUTES must be a positive integer")


CASES = [
    queued_time_is_not_runner_time,
    parallel_matrix_jobs_each_count,
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
    invalid_cap_fails_closed,
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
