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
import json, os, re, sys
from pathlib import Path
fixtures = Path(os.environ["FAKE_GH_DIR"])
path = sys.argv[-1]
include = "--include" in sys.argv
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


def respond(status, headers, body):
    if include:
        lines = [f"HTTP/2.0 {status} X"] + [f"{key}: {value}" for key, value in headers.items()]
        sys.stdout.write("\n".join(lines) + "\n\n")
    sys.stdout.write(body)
    if status >= 400:
        sys.stderr.write(f"gh: request failed (HTTP {status})\n")
        sys.exit(1)
    sys.exit(0)


sequence = fixtures / (name + ".seq")
if sequence.exists():
    responses = json.loads(sequence.read_text())
    counter = fixtures / (name + ".n")
    served = int(counter.read_text()) if counter.exists() else 0
    if served < len(responses):
        counter.write_text(str(served + 1))
        response = responses[served]
        respond(response["status"], response.get("headers", {}), response.get("body", "{}"))
body = fixtures / (name + ".json")
if not body.exists():
    respond(404, {}, '{"message": "Not Found"}')
respond(200, {"X-Ratelimit-Remaining": "4999"}, body.read_text())
"""


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(
    run_id: int,
    start: int,
    end: int,
    status: str = "completed",
    attempt: int = 1,
    conclusion: str | None = "success",
) -> dict:
    return {
        "id": run_id,
        "run_attempt": attempt,
        "status": status,
        "conclusion": conclusion if status == "completed" else None,
        "created_at": iso(start),
        "run_started_at": iso(start),
        "updated_at": iso(end),
    }


def job(start: int, end: int | None, runner: str | None) -> dict:
    return {
        "status": "in_progress" if end is None else "completed",
        "conclusion": None if end is None else ("success" if runner else "cancelled"),
        "started_at": iso(start),
        "completed_at": None if end is None else iso(end),
        "runner_name": runner,
    }


class Case:
    def __init__(self, epoch: str | None = "2000-01-01T00:00:00Z") -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.script = self.dir / "tree/scripts/check-fuzz-budget.sh"
        self.script.parent.mkdir(parents=True)
        self.script.write_text(SCRIPT.read_text())
        (self.dir / "tree/fuzz").mkdir()
        if epoch is not None:
            self.epoch(epoch)
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
        numbered = [dict(job, id=run_id * 1000 + index) for index, job in enumerate(jobs)]
        self.raw_jobs(run_id, {"total_count": len(numbered), "jobs": numbered})

    def raw_jobs(self, run_id: int, *pages: object) -> None:
        text = "".join(json.dumps(page) for page in pages)
        (self.dir / f"jobs-{run_id}.json").write_text(text)

    def epoch(self, text: str) -> None:
        (self.dir / "tree/fuzz/cflite-budget-epoch").write_text(text)

    def responses(self, name: str, *responses: dict) -> None:
        (self.dir / f"{name}.seq").write_text(json.dumps(list(responses)))

    def error(self, name: str, status: int, headers: dict | None = None, times: int = 3) -> None:
        self.responses(name, *[{"status": status, "headers": headers or {}}] * times)

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
            ["bash", str(self.script), REPO],
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
        "used=10 min, cap=26000 min, remaining=25990 min",
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
        "used=1800 min, cap=1800 min, remaining=0 min",
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
    expect(case.check("all"), 0, "used=25999 min, cap=26000 min")
    case.jobs(22, [job(start, start + 26000 * 60, "runner")])
    result = case.check("all")
    expect(result, 1, "HALT - envelope=native used 26000 min >= cap 26000 min")
    assert "used=0 min, cap=1800 min" in result.stdout, result.stdout


def mutation_lanes_are_reported_not_capped() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(23, start, start + 60)], workflow="mutants.yml")
    case.jobs(23, [job(start, start + 500000 * 60, "runner")])
    case.quiet("mutation")
    expect(
        case.check("mutation"),
        0,
        "used=500000 min, reported only, not capped",
    )
    assert "HALT" not in case.check("mutation").stderr


def mutation_errors_do_not_fail_the_gate() -> None:
    case = Case()
    case.listing([run(24, NOW - 600, NOW - 300)], workflow="proof-mutants.yml")
    case.error("jobs-24", 502)
    case.quiet("mutation", "cflite", "native")
    expect(case.check("mutation"), 0, "envelope=mutation usage is unverified")
    result = case.check("all")
    expect(result, 0, "envelope=mutation usage is unverified", "envelope=native window_start=")


def cflite_epoch_excludes_earlier_runs() -> None:
    start = NOW - 10 * 86400
    case = Case(epoch=iso(NOW - 5 * 86400))
    case.listing([run(30, start, start + 60)], workflow="cflite_pr.yml")
    case.jobs(30, [job(start, start + 5000 * 60, "runner")])
    case.quiet("cflite")
    expect(
        case.check("cflite"),
        0,
        f"envelope=cflite window_start={iso(NOW - 5 * 86400)}",
        "used=0 min, cap=1800 min",
    )
    created = [call for call in case.calls() if "/workflows/cflite_pr.yml/runs" in call]
    assert created and all(f"created=>={iso(NOW - 5 * 86400)}" in call for call in created), created


def cflite_epoch_counts_later_runs() -> None:
    start = NOW - 86400
    case = Case(epoch=iso(NOW - 5 * 86400))
    case.listing([run(31, start, start + 60)], workflow="cflite_batch.yml")
    case.jobs(31, [job(start, start + 1800 * 60, "runner")])
    case.quiet("cflite")
    expect(case.check("cflite"), 1, "HALT - envelope=cflite used 1800 min >= cap 1800 min")


def old_cflite_epoch_keeps_thirty_day_window() -> None:
    case = Case(epoch="2026-01-01T00:00:00Z")
    case.quiet("cflite")
    result = case.check("cflite")
    expect(result, 0, f"envelope=cflite window_start={iso(NOW - 30 * 86400)[:13]}")


def native_window_ignores_cflite_epoch() -> None:
    case = Case(epoch=iso(NOW - 86400))
    case.quiet("native")
    expect(case.check("native"), 0, f"envelope=native window_start={iso(NOW - 30 * 86400)[:13]}")
    created = [call for call in case.calls() if "/workflows/fuzz.yml/runs" in call]
    assert created and all(f"created=>={iso(NOW - 30 * 86400)[:13]}" in call for call in created), created


def bad_cflite_epoch_fails_closed() -> None:
    for text, needle in [
        (None, "cflite budget epoch"),
        ("", "cflite budget epoch"),
        ("2026-10-28", "cflite budget epoch"),
        ("2026-13-40T00:00:00Z", "cflite budget epoch"),
        ("2026-10-28T00:00:00Z\n2026-10-29T00:00:00Z\n", "cflite budget epoch"),
        (iso(NOW + 3600), "is in the future"),
    ]:
        case = Case(epoch=text)
        case.quiet("cflite", "native", "mutation")
        expect(case.check("cflite"), 2, needle)
        expect(case.check("all"), 2, needle)
        expect(case.check("native"), 0, "envelope=native")


def unknown_scope_fails_closed() -> None:
    case = Case()
    expect(case.check("everything"), 2, "unknown GH_FUZZ_BUDGET_SCOPE: everything")


def cflite_pr_exception_is_named_and_scoped() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(2, start, start + 1860)], workflow="cflite_pr.yml")
    case.jobs(2, [job(start, start + 1800 * 60, "runner")])
    case.quiet("cflite", "native")
    exception = {"GH_FUZZ_BUDGET_CAP_EXCEPTION": "cflite-pr-evidence"}
    result = case.check("cflite", **exception)
    expect(
        result,
        0,
        "HALT - envelope=cflite used 1800 min >= cap 1800 min",
        "EXCEPTION cflite-pr-evidence: cflite envelope over cap; PR fuzzing is per-PR "
        "evidence, its minutes still count toward the window, and cflite_batch enforces the cap",
    )
    expect(case.check("cflite"), 1, "HALT - envelope=cflite")
    expect(case.check("cflite", GH_FUZZ_BUDGET_CAP_MODE="warn"), 1, "HALT - envelope=cflite")
    expect(case.check("native", **exception), 2, "only applies to GH_FUZZ_BUDGET_SCOPE=cflite")
    expect(case.check("all", **exception), 2, "only applies to GH_FUZZ_BUDGET_SCOPE=cflite")
    expect(
        case.check("cflite", GH_FUZZ_BUDGET_CAP_EXCEPTION="warn"),
        2,
        "unknown GH_FUZZ_BUDGET_CAP_EXCEPTION: warn",
    )
    under = Case()
    under.quiet("cflite")
    result = under.check("cflite", **exception)
    expect(result, 0, "used=0 min")
    assert "EXCEPTION" not in result.stdout + result.stderr, result


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


def timed_check(case: Case, scope: str = "native", **env: str) -> tuple[subprocess.CompletedProcess[str], float]:
    began = time.monotonic()
    result = case.check(scope, **env)
    return result, time.monotonic() - began


def jobs_api_failure_fails_closed() -> None:
    case = Case()
    case.listing([run(8, NOW - 600, NOW - 300)])
    case.error("jobs-8", 400, times=1)
    expect(case.check(), 2, "GitHub API failed")
    assert sum("/runs/8/jobs" in call for call in case.calls()) == 1, case.calls()


def retry_after_is_honoured() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(60, start, start + 600)])
    case.jobs(60, [job(start, start + 600, "runner")])
    case.responses("jobs-60", {"status": 429, "headers": {"Retry-After": "2"}})
    result, elapsed = timed_check(case)
    expect(result, 0, "used=10 min", "HTTP 429", "retrying in 2s (attempt 1 of 3)")
    assert elapsed >= 2, elapsed
    assert sum("/runs/60/jobs" in call for call in case.calls()) == 2, case.calls()


def rate_limit_reset_is_honoured() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(61, start, start + 600)])
    case.jobs(61, [job(start, start + 600, "runner")])
    reset = int(time.time()) + 2
    case.responses(
        "jobs-61",
        {"status": 403, "headers": {"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": str(reset)}},
    )
    result, elapsed = timed_check(case)
    expect(result, 0, "used=10 min", "HTTP 403")
    assert time.time() >= reset and elapsed >= 1, elapsed


def transient_server_errors_retry() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(62, start, start + 600)])
    case.jobs(62, [job(start, start + 600, "runner")])
    case.responses("jobs-62", {"status": 502}, {"status": 503})
    expect(case.check(), 0, "used=10 min", "retrying in 1s (attempt 1 of 3)", "retrying in 2s (attempt 2 of 3)")
    assert sum("/runs/62/jobs" in call for call in case.calls()) == 3, case.calls()
    listing = Case()
    listing.listing([run(63, start, start + 600)])
    listing.jobs(63, [job(start, start + 600, "runner")])
    listing.responses("runs-fuzz.yml", {"status": 500})
    expect(listing.check(), 0, "used=10 min")


def exhausted_retries_fail_closed() -> None:
    start = NOW - 86400
    for status, headers in [
        (502, {}),
        (429, {"Retry-After": "1"}),
        (403, {"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": str(int(time.time()))}),
    ]:
        case = Case()
        case.listing([run(64, start, start + 600)])
        case.error("jobs-64", status, headers)
        for env in [{}, {"GH_FUZZ_BUDGET_RATE_LIMIT_MODE": "warn"}]:
            (case.dir / "jobs-64.n").unlink(missing_ok=True)
            expect(case.check(**env), 2, f"still failing (HTTP {status}) after 3 attempts")
        assert sum("/runs/64/jobs" in call for call in case.calls()) == 6, case.calls()
        case.listing([run(65, start, start + 600)], workflow="mutants.yml")
        case.error("jobs-65", status, headers)
        case.quiet("mutation")
        expect(case.check("mutation"), 0, "envelope=mutation usage is unverified")


def excessive_wait_fails_closed() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(66, start, start + 600)])
    case.error("jobs-66", 429, {"Retry-After": "3600"})
    result, elapsed = timed_check(case)
    expect(result, 2, "asks for a 3600s wait, longer than 600s")
    assert elapsed < 30, elapsed
    assert sum("/runs/66/jobs" in call for call in case.calls()) == 1, case.calls()


def failed_check_keeps_validated_ledger_entries() -> None:
    case = Case()
    start = NOW - 86400
    case.listing([run(67, start, start + 600), run(68, start, start + 600)])
    case.jobs(67, [job(start, start + 600, "runner")])
    case.error("jobs-68", 502)
    ledger = case.dir / "ledger.json"
    expect(case.check(GH_FUZZ_BUDGET_LEDGER=str(ledger)), 2, "after 3 attempts")
    written = json.loads(ledger.read_text())
    assert list(written["runs"]) == ["67:1"], written


def invalid_job_listings_fail_closed() -> None:
    start = NOW - 86400
    one = dict(job(start, start + 60, "runner"), id=1)
    for pages, needle in [
        (({"total_count": 2, "jobs": [one]},), "returned 1 of 2 jobs"),
        (({"total_count": 1, "jobs": []},), "returned 0 of 1 jobs"),
        (({},), "malformed jobs listing"),
        (({"total_count": 1},), "malformed jobs listing"),
        (({"total_count": 1, "jobs": {"id": 1}},), "malformed jobs listing"),
        (({"total_count": "1", "jobs": [one]},), "malformed jobs listing"),
        (({"total_count": 1, "jobs": [dict(one, id=None)]},), "malformed jobs listing"),
        (({"total_count": 2, "jobs": [one]}, {"total_count": 2, "jobs": [one]}), "returned 1 of 2 jobs"),
        (({"total_count": 2, "jobs": [one]}, {"total_count": 3, "jobs": []}), "malformed jobs listing"),
    ]:
        case = Case()
        case.listing([run(40, start, start + 60)])
        case.raw_jobs(40, *pages)
        ledger = case.dir / "ledger.json"
        before = json.dumps({"repo": REPO, "runs": {}})
        ledger.write_text(before)
        expect(case.check(GH_FUZZ_BUDGET_LEDGER=str(ledger)), 2, needle, "fuzz.yml run 40")
        assert json.loads(ledger.read_text()) == json.loads(before), ledger.read_text()


def jobs_without_accounting_fields_fail_closed() -> None:
    start = NOW - 86400
    complete = job(start, start + 600, "runner")
    for broken, needle in [
        ({"id": 1}, "job 1 lacks accounting fields"),
        ({"id": 1, "runner_name": "assigned-runner"}, "job 1 lacks accounting fields"),
        (dict(complete, id=1, started_at=None), "assigned job 1 has no start time"),
        (dict(complete, id=1, completed_at=None), "completed job 1 has no completion time"),
        (dict(complete, id=1, started_at=1700000000), "job 1 lacks accounting fields"),
        (dict(complete, id=1, runner_name=7), "job 1 lacks accounting fields"),
        (dict(complete, id=1, status="in_progress", completed_at=None), "completed run lists unfinished job 1"),
        (dict(complete, id=1, runner_name=None, conclusion="success"), "unassigned job 1 concluded success"),
    ]:
        case = Case()
        case.listing([run(50, start, start + 700)])
        case.raw_jobs(50, {"total_count": 1, "jobs": [broken]})
        expect(case.check(), 2, needle, "fuzz.yml run 50")
        case.listing([run(51, start, start + 700)], workflow="mutants.yml")
        case.raw_jobs(51, {"total_count": 1, "jobs": [broken]})
        case.quiet("mutation")
        expect(case.check("mutation"), 0, needle, "envelope=mutation usage is unverified")


def unfinished_unassigned_jobs_need_a_waiting_status() -> None:
    start = NOW - 600
    for status, code in [("queued", 0), ("waiting", 0), ("pending", 0), ("in_progress", 2), ("requested", 2)]:
        case = Case()
        case.listing([run(55, start, start + 5, status="in_progress")])
        unassigned = {
            "id": 1,
            "status": status,
            "conclusion": None,
            "runner_name": None,
            "started_at": None,
            "completed_at": None,
        }
        case.raw_jobs(55, {"total_count": 1, "jobs": [unassigned]})
        result = case.check()
        if code == 0:
            expect(result, 0, "runs=1 queried=1 executed=0 min")
        else:
            expect(result, 2, f"unassigned job 1 is {status}")


def unassigned_job_timestamps_must_show_it_never_ran() -> None:
    start = NOW - 600
    root_review_payload = {
        "total_count": 1,
        "jobs": [
            {
                "id": 1,
                "status": "in_progress",
                "runner_name": None,
                "started_at": iso(start),
                "completed_at": None,
                "conclusion": None,
            }
        ],
    }
    queued_but_completed = {
        "id": 1,
        "status": "queued",
        "runner_name": None,
        "started_at": iso(start),
        "completed_at": iso(start + 60),
        "conclusion": None,
    }
    cancelled_without_end = dict(job(start, start + 60, None), id=1, completed_at=None)
    for payload, needle in [
        (root_review_payload, "unassigned job 1 is in_progress"),
        ({"total_count": 1, "jobs": [queued_but_completed]}, "unassigned job 1 is queued but has a completion time"),
        ({"total_count": 1, "jobs": [cancelled_without_end]}, "unassigned job 1 completed without a completion time"),
    ]:
        case = Case()
        case.listing([run(56, start, start + 5, status="in_progress")])
        if payload["jobs"][0]["status"] == "completed":
            case.listing([run(56, start, start + 120, conclusion="cancelled")])
        case.raw_jobs(56, payload)
        expect(case.check(), 2, needle)
    queued = Case()
    queued.listing([run(57, start, start + 5, status="in_progress")])
    queued.raw_jobs(57, {"total_count": 1, "jobs": [dict(queued_but_completed, completed_at=None)]})
    expect(queued.check(), 0, "runs=1 queried=1 executed=0 min")


def never_started_jobs_count_zero() -> None:
    start = NOW - 86400
    case = Case()
    case.listing([run(52, start, start + 86400, conclusion="cancelled")])
    queued_then_cancelled = dict(job(start, start + 86400, None), id=1)
    skipped = dict(job(start, start, ""), id=2, conclusion="skipped")
    ran = dict(job(start, start + 600, "runner"), id=3)
    case.raw_jobs(52, {"total_count": 3, "jobs": [queued_then_cancelled, skipped, ran]})
    expect(case.check(), 0, "runs=1 queried=1 executed=10 min")


def paginated_jobs_sum_across_pages() -> None:
    start = NOW - 86400
    case = Case()
    case.listing([run(41, start, start + 60)])
    first = dict(job(start, start + 1800, "runner"), id=1)
    second = dict(job(start, start + 1800, "runner"), id=2)
    case.raw_jobs(41, {"total_count": 2, "jobs": [first]}, {"total_count": 2, "jobs": [second]})
    expect(case.check(), 0, "runs=1 queried=1 executed=60 min")


def cancelled_run_without_jobs_counts_zero() -> None:
    start = NOW - 86400
    case = Case()
    case.listing([run(42, start, start + 5, conclusion="cancelled")])
    case.raw_jobs(42, {"total_count": 0, "jobs": []})
    expect(case.check(), 0, "runs=1 queried=1 executed=0 min")
    case.listing([run(42, start, start + 5, conclusion="success")])
    expect(case.check(), 2, "fuzz.yml run 42 lists no jobs")


def invalid_mutation_listing_is_not_cached() -> None:
    start = NOW - 86400
    case = Case()
    case.listing(
        [run(43, start, start + 60), run(44, start, start + 60)], workflow="mutants.yml"
    )
    case.jobs(43, [job(start, start + 600, "runner")])
    case.raw_jobs(44, {"total_count": 2, "jobs": [dict(job(start, start + 60, "runner"), id=9)]})
    case.quiet("mutation")
    ledger = case.dir / "ledger.json"
    expect(
        case.check("mutation", GH_FUZZ_BUDGET_LEDGER=str(ledger)),
        0,
        "returned 1 of 2 jobs",
        "envelope=mutation usage is unverified",
    )
    written = json.loads(ledger.read_text())
    assert list(written["runs"]) == ["43:1"], written


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
    cflite_epoch_excludes_earlier_runs,
    cflite_epoch_counts_later_runs,
    old_cflite_epoch_keeps_thirty_day_window,
    native_window_ignores_cflite_epoch,
    bad_cflite_epoch_fails_closed,
    cflite_pr_exception_is_named_and_scoped,
    running_job_counts_until_now,
    large_window_is_listed_by_day,
    truncated_day_fails_closed,
    short_listing_fails_closed,
    jobs_api_failure_fails_closed,
    retry_after_is_honoured,
    rate_limit_reset_is_honoured,
    transient_server_errors_retry,
    exhausted_retries_fail_closed,
    excessive_wait_fails_closed,
    failed_check_keeps_validated_ledger_entries,
    missing_workflow_fails_closed,
    invalid_job_listings_fail_closed,
    paginated_jobs_sum_across_pages,
    jobs_without_accounting_fields_fail_closed,
    never_started_jobs_count_zero,
    unfinished_unassigned_jobs_need_a_waiting_status,
    unassigned_job_timestamps_must_show_it_never_ran,
    cancelled_run_without_jobs_counts_zero,
    invalid_mutation_listing_is_not_cached,
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
