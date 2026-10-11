#!/usr/bin/env python3
"""Pin the two pheromone fixture-gate workflows to every known facet."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FACET_COMMAND = re.compile(r"cargo xtask check fixtures (\S+)")
CANCEL_SAFE = "${{ !cancelled() }}"
DASHBOARD = "crates/products/chio-cli/dashboard"
CHECKER_PATHS = ("scripts/check-pheromone-ci.py", "scripts/tests/check-pheromone-ci.test.py")

STEP_NAMES = {
    "directory-lifecycle": "Check Chio pheromone directory lifecycle",
    "relay-alert-assurance-archive-hardening": "Check Chio pheromone relay alert assurance archive hardening",
    "relay-alert-assurance-archive-package": "Check Chio pheromone relay alert assurance archive package",
    "relay-alert-assurance-archive": "Check Chio pheromone relay alert assurance archive",
    "relay-alert-assurance-export": "Check Chio pheromone relay alert assurance export",
    "relay-alert-assurance-external-retention": "Check Chio pheromone relay alert assurance external retention",
    "relay-alert-assurance": "Check Chio pheromone relay alert assurance",
    "relay-alert-delivery": "Check Chio pheromone relay alert delivery",
    "relay-alert-handoff": "Check Chio pheromone relay alert handoff",
    "relay-alert-routing": "Check Chio pheromone relay alert routing",
    "relay-observability": "Check Chio pheromone relay observability",
    "relay-ops": "Check Chio pheromone relay operations",
    "relay": "Check Chio pheromone relay",
    "runtime": "Check Chio pheromone runtime",
    "transit": "Run Chio pheromone transit gate",
}

COMPOSITE_FACETS = ("relay-alert-assurance", "relay-alert-delivery", "relay-alert-handoff", "relay-alert-routing")

RELAY_PATHS = (
    "ci-gates/pheromone.toml",
    "crates/observability/chio-metrics-spec/**",
    "crates/products/chio-cli/**",
    "crates/tooling/chio-spec-validate/**",
    "crates/trust/chio-pheromone-relay/**",
    "deploy/prometheus/**",
    "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md",
    "docs/release/chio-pheromone-relay/**",
    "examples/chio-3vendor/fixtures/pheromone/relay/**",
    "spec/schemas/chio-pheromone/v1/**",
    "spec/schemas/registry.json",
    "xtask/**",
)
PINNED_ONLY_PATHS = (
    "crates/trust/chio-federation/**",
    "crates/trust/chio-federation/src/pheromone_gossip.rs",
    "crates/trust/chio-federation/tests/pheromone_gossip.rs",
    "crates/trust/chio-pheromone-runtime/**",
    "crates/trust/chio-pheromone/**",
    "examples/chio-3vendor/**",
    "scripts/check-sre-metrics-registry.sh",
    "spec/CHIO_PHEROMONE.md",
    "spec/schemas/chio-pheromone/**",
)

PINNED_PREFIX = [
    {"uses": "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"},
    {"uses": "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8"},
    {"uses": "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32"},
    {
        "uses": "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
        "with": {
            "node-version": "22",
            "cache": "npm",
            "cache-dependency-path": f"{DASHBOARD}/package-lock.json",
        },
    },
    {"name": "Install dashboard dependencies", "run": "npm ci", "working-directory": DASHBOARD},
]
COMPOSITE_PREFIX = [
    {"uses": "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"},
    {"uses": "./.github/actions/setup-rust", "with": {"toolchain": "stable"}},
    {
        "uses": "./.github/actions/setup-node",
        "with": {
            "node-version": "24",
            "cache-dependency-path": f"{DASHBOARD}/package-lock.json",
            "working-directory": DASHBOARD,
        },
    },
]

# file -> (workflow name, job id, job name, prefix, trigger paths without the file itself)
GROUPS = {
    "chio-pheromone-pinned.yml": (
        "Chio Pheromone Pinned Fixture Gates",
        "pinned-fixture-gates",
        "Pheromone fixture gates (pinned actions)",
        PINNED_PREFIX,
        RELAY_PATHS + PINNED_ONLY_PATHS,
    ),
    "chio-pheromone-composite.yml": (
        "Chio Pheromone Composite Fixture Gates",
        "composite-fixture-gates",
        "Pheromone fixture gates (setup-rust, Node 24)",
        COMPOSITE_PREFIX,
        RELAY_PATHS,
    ),
}


class ContractError(Exception):
    pass


def known_facets(root: Path) -> list[str]:
    source = (root / "xtask/src/fixtures.rs").read_text()
    block = re.search(r"pub\(crate\) const KNOWN_FACETS: \[&str; \d+\] = \[(.*?)\];", source, re.S)
    if block is None:
        raise ContractError("xtask KNOWN_FACETS is not readable")
    facets = re.findall(r'"([a-z0-9-]+)"', block.group(1))
    manifest = tomllib.loads((root / "ci-gates/pheromone.toml").read_text())
    if sorted(facets) != sorted(facet["name"] for facet in manifest["facet"]):
        raise ContractError("xtask KNOWN_FACETS and ci-gates/pheromone.toml disagree")
    if sorted(facets) != sorted(STEP_NAMES):
        raise ContractError("pheromone facets changed without updating this gate")
    return facets


def load_workflows(root: Path) -> dict[str, dict]:
    directory = root / ".github/workflows"
    return {
        path.name: yaml.safe_load(path.read_text())
        for path in sorted((*directory.glob("*.yml"), *directory.glob("*.yaml")))
    }


def facet_steps(workflow: dict):
    for job_id, job in (workflow.get("jobs") or {}).items():
        for step in (job or {}).get("steps") or []:
            match = FACET_COMMAND.search(str(step.get("run", "")))
            if match:
                yield job_id, match.group(1), step


def expected_triggers(file: str, paths: tuple[str, ...]) -> dict:
    listed = sorted({*paths, f".github/workflows/{file}", *CHECKER_PATHS})
    return {"pull_request": {"paths": listed}, "push": {"branches": ["main"], "paths": listed}}


def validate_group(file: str, workflow: dict, facets: list[str]) -> None:
    name, job_id, job_name, prefix, paths = GROUPS[file]
    members = [facet for facet in facets if (file == "chio-pheromone-composite.yml") == (facet in COMPOSITE_FACETS)]
    triggers = workflow.get("on", workflow.get(True))
    if set(workflow) - {"on", True} != {"name", "permissions", "jobs"} or workflow["name"] != name:
        raise ContractError(f"{file}: workflow keys or name changed")
    if workflow["permissions"] != {"contents": "read"}:
        raise ContractError(f"{file}: token permissions changed")
    if triggers != expected_triggers(file, paths):
        raise ContractError(f"{file}: trigger events, branches or paths changed")
    if list(workflow["jobs"]) != [job_id]:
        raise ContractError(f"{file}: job set changed")
    job = workflow["jobs"][job_id]
    concurrency = {
        "group": f"${{{{ github.workflow }}}}-{job_id}-${{{{ github.event.pull_request.number || github.run_id }}}}",
        "cancel-in-progress": "${{ github.event_name == 'pull_request' || github.event_name == 'pull_request_target' }}",
    }
    if job != {**job, "name": job_name, "runs-on": "ubuntu-latest", "concurrency": concurrency} or set(job) != {
        "name", "runs-on", "concurrency", "steps"
    }:
        raise ContractError(f"{file}: job shape, runner or concurrency changed")
    steps = job["steps"]
    if steps[: len(prefix)] != prefix:
        raise ContractError(f"{file}: setup prerequisites changed")
    gates = [
        {"name": STEP_NAMES[facet], "if": CANCEL_SAFE, "run": f"cargo xtask check fixtures {facet}"}
        for facet in members
    ]
    if steps[len(prefix):] != gates:
        raise ContractError(f"{file}: facet gate steps changed")


def validate_documents(workflows: dict[str, dict], facets: list[str]) -> None:
    if any(name.startswith("chio-pheromone-") and name not in GROUPS for name in workflows):
        raise ContractError("a per-facet pheromone workflow file is present")
    seen: dict[str, list[str]] = {}
    for file, workflow in workflows.items():
        for job_id, facet, _ in facet_steps(workflow or {}):
            if facet in STEP_NAMES:
                seen.setdefault(facet, []).append(f"{file}:{job_id}")
    for facet in facets:
        owners = seen.get(facet, [])
        if len(owners) != 1:
            raise ContractError(f"facet {facet} must run exactly once, found {owners}")
    for file in GROUPS:
        if file not in workflows:
            raise ContractError(f"{file} is missing")
        validate_group(file, workflows[file], facets)


def validate(root: Path = ROOT) -> None:
    validate_documents(load_workflows(root), known_facets(root))


def main() -> int:
    try:
        validate()
    except ContractError as error:
        print(f"pheromone CI gate failed: {error}", file=sys.stderr)
        return 1
    print("pheromone CI covers every facet exactly once")
    return 0


if __name__ == "__main__":
    sys.exit(main())
