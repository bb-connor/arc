"""A random baseline cannot pass without completion and the selected effects."""

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("benchmark_run", Path(__file__).with_name("run.py"))
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


@pytest.mark.parametrize("completed,publications", [(False, 0), (True, 0)])
def test_random_baseline_requires_completion_and_publication(completed, publications):
    with pytest.raises(AssertionError):
        benchmark.check(
            "random-1", "baseline", {"completed": completed, "publications": publications}
        )


def test_random_baseline_does_not_require_duplicates_before_researcher_dispatch():
    benchmark.check(
        "random-1",
        "baseline",
        {
            "completed": True,
            "publications": 1,
            "duplicate_reads": 0,
            "duplicate_messages": 0,
        },
        {"kill": {"tool": "spawn_researcher"}},
    )


@pytest.mark.parametrize(
    "tool,field,value",
    [
        ("publish", "publications", 1),
        ("read", "duplicate_reads", 1),
        ("send_findings", "duplicate_messages", 0),
    ],
)
def test_random_selected_kill_requires_its_committed_effect(tool, field, value):
    summary = {
        "completed": True,
        "publications": 2 if tool == "publish" else 1,
        "duplicate_reads": 2,
        "duplicate_messages": 1,
    }
    spec = {"kill": {"tool": tool, "ordinal": 2}}
    benchmark.check("random-1", "baseline", summary, spec)
    with pytest.raises(AssertionError):
        benchmark.check("random-1", "baseline", {**summary, field: value}, spec)
