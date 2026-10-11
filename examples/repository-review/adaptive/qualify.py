"""Qualify runtime decomposition, durable joins and recovery with the real CLI."""

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from . import qualification as q
from .qualification_checks import corruption, no_secrets, scopes


def exercise(binary, output, temporary):
    repo, base, head, expanded = q.commits(temporary)
    profiles = {}
    for name, revision, model, count, faults, killed in (
        ("inventory", head, "inventory", 2, {}, False),
        ("inventory-expanded", expanded, "inventory", 3, {}, False),
        (
            "scripted-recovery",
            head,
            "adaptive.model_fixture:create",
            3,
            {"coordinator": "spawn", "reviewer": "handoff", "publisher": "publication"},
            False,
        ),
        (
            "scripted-host-death",
            expanded,
            "adaptive.model_fixture:create",
            4,
            {"coordinator": "spawn"},
            True,
        ),
    ):
        directory = temporary / name
        config = q.prepare(
            binary,
            directory,
            repo,
            base,
            revision,
            model,
            faults=faults,
            fault_hold=killed,
        )
        # Captured commits, including model reads, must survive working tree drift.
        (repo / "api/main.py").write_text("uncommitted = 'must not be reviewed'\n")
        env = q.model_env(directory)
        first = q.crash_host(config, directory, env) if killed else {}
        q.run(directory, env=env)
        first.update(q.first_receipts(directory))
        result = q.evidence(directory, count)
        q.same_receipts(first, result)
        attempts = {
            worker["process"]: worker["attempts"]
            for worker in result["runner"]["workers"]
        }
        if model == "inventory":
            assert attempts["coordinator"] == 2, (
                "one native slot must require a durable join"
            )
            assert all(attempts[child] == 1 for child in result["children"])
        else:
            assert 2 <= attempts["coordinator"] <= 3
            trace = q.model_trace(directory)
            assert trace.count({"role": "coordinator", "kind": "plan"}) == 1
            assert trace.count({"role": "coordinator", "kind": "planning-read"}) == 1
            assert trace.count({"role": "reviewer", "kind": "review-finish"}) == count
        if name == "scripted-recovery":
            assert set(first) == {"coordinator", "publisher", *result["children"]}
            assert attempts["publisher"] == 2
            assert all(attempts[child] == 2 for child in result["children"])
        if killed:
            assert set(first) == {"coordinator"}
        # Erased fault oracles are never needed to preserve completed work.
        q.run(directory, env=env)
        repeated = q.evidence(directory, count)
        assert repeated["runner"] == result["runner"]
        assert repeated["workers"] == result["workers"]
        if name == "scripted-recovery":
            corruption(config, directory, result)
            credentials = scopes(config, directory, result)
        else:
            credentials = []
        no_secrets(directory, credentials)
        profiles[name] = q.export(directory, output, name, result)
        print(json.dumps({"qualified": name, **profiles[name]}), flush=True)

    rejected = {}
    for name, model, rounds, expected in (
        ("invalid-plan", "adaptive.model_fixture:invalid", 8, 2),
        ("round-limit", "adaptive.model_fixture:create", 1, 1),
    ):
        directory = temporary / name
        q.prepare(binary, directory, repo, base, head, model, max_rounds=rounds)
        q.run(directory, success=False, env=q.model_env(directory))
        with sqlite3.connect(directory / "host/process.db") as db:
            assert (
                db.execute("SELECT count(*) FROM process_child_work").fetchone()[0] == 0
            )
        q.no_publication(directory)
        assert len(q.model_trace(directory)) == expected, (
            "checkpoint recovery must not re-plan a rejected response"
        )
        with sqlite3.connect(directory / "host/runner.db") as db:
            assert db.execute(
                "SELECT state,attempts FROM run_workers WHERE process='coordinator'"
            ).fetchone() == ("failed", 4)
        rejected[name] = {"children": 0, "publications": 0, "model_calls": expected}
        print(json.dumps({"rejected": name, **rejected[name]}), flush=True)
    summary = {
        "profiles": profiles,
        "rejected": rejected,
        "live_model": False,
        "initial_workers": ["coordinator", "publisher"],
        "known_spawn_handoff_and_publication_receipts_replayed": True,
        "host_death_after_known_spawn_recovered": True,
        "scope_and_corruption_checks_passed": True,
    }
    (output / "qualification.json").write_text(json.dumps(summary, indent=2) + "\n")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    temporary = Path(tempfile.mkdtemp(prefix="chio-arv-"))
    try:
        exercise(args.chio.resolve(strict=True), args.output, temporary)
    except BaseException:
        print(f"Preserved private failure state: {temporary}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(temporary)
