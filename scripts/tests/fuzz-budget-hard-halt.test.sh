#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PR_WORKFLOW="${REPO_ROOT}/.github/workflows/cflite_pr.yml"
MUTANTS_WORKFLOW="${REPO_ROOT}/.github/workflows/mutants.yml"
DOCS="${REPO_ROOT}/docs/fuzzing/continuous.md"
BUDGET_SCRIPT="${REPO_ROOT}/scripts/check-fuzz-budget.sh"

python3 - <<'PY' "${PR_WORKFLOW}" "${MUTANTS_WORKFLOW}"
from pathlib import Path
import re
import sys

workflows = Path(sys.argv[1]).resolve().parent
expected_steps = {
    "cflite_pr.yml": [("cflite", "cflite-pr-evidence")],
    "cflite_batch.yml": [("cflite", None)],
    "fuzz.yml": [("native", None)],
    "mutants.yml": [("mutation", None), ("mutation", None)],
    "mutants-fuzz-cocoverage.yml": [("mutation", None)],
    "proof-mutants.yml": [("mutation", None)],
}
for name, expected in expected_steps.items():
    text = (workflows / name).read_text(encoding="utf-8")
    steps = [
        block
        for block in re.split(r"\n      - ", text)
        if "check-fuzz-budget.sh \"${{ github.repository }}\"" in block
    ]
    observed = []
    for block in steps:
        scope = re.search(r"GH_FUZZ_BUDGET_SCOPE: (\S+)", block)
        exception = re.search(r"GH_FUZZ_BUDGET_CAP_EXCEPTION: (\S+)", block)
        observed.append((scope and scope.group(1), exception and exception.group(1)))
        for removed in (
            "GH_FUZZ_BUDGET_WORKFLOWS",
            "GH_FUZZ_BUDGET_MINUTES",
            "GH_FUZZ_BUDGET_CAP_MODE",
            "GH_FUZZ_BUDGET_RATE_LIMIT_MODE",
        ):
            if removed in block:
                raise SystemExit(f"{name} budget step still sets {removed}")
        if "GH_FUZZ_BUDGET_LEDGER:" not in block:
            raise SystemExit(f"{name} budget step must use the shared ledger")
    if text.count("uses: actions/cache/restore@") != len(steps):
        raise SystemExit(f"{name} must restore the ledger before each budget step")
    saves = re.findall(r"name: Save fuzz budget ledger\n        if: (always\(\)[^\n]*)", text)
    if len(saves) != len(steps):
        raise SystemExit(f"{name} must save the ledger with if: always() after each budget step")
    if observed != expected:
        raise SystemExit(f"{name} budget steps {observed} != {expected}")

repo = workflows.parent.parent
removed_names = (
    "GH_FUZZ_BUDGET_WORKFLOWS",
    "GH_FUZZ_BUDGET_MINUTES",
    "GH_FUZZ_BUDGET_CAP_MODE",
    "GH_FUZZ_BUDGET_RATE_LIMIT_MODE",
)
callers = sorted(workflows.glob("*.yml")) + sorted((repo / "scripts").glob("*")) + sorted(
    (repo / "docs/fuzzing").glob("*.md")
)
for caller in callers:
    if not caller.is_file():
        continue
    text = caller.read_text(encoding="utf-8", errors="replace")
    for removed in removed_names:
        if removed in text:
            raise SystemExit(f"{caller.relative_to(repo)} still uses removed {removed}")

pr_text = Path(sys.argv[1]).read_text(encoding="utf-8")
on_block = pr_text[pr_text.index("    paths:\n"):pr_text.index("\npermissions:")]
pr_paths = re.findall(r'^      - "([^"]+)"$', on_block, re.M)
def path_covered(path: str) -> bool:
    for pattern in pr_paths:
        regex = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        if re.fullmatch(regex, path):
            return True
    return False
for path in [
    "scripts/select-fuzz-targets.py",
    "scripts/tests/check-fuzz-manifest-selection.test.py",
    "scripts/check-fuzz-budget.sh",
    ".clusterfuzzlite/build.sh",
    ".cargo/config.toml",
    "fuzz/target-map.toml",
    "fuzz/Cargo.lock",
    "Cargo.toml",
    "Makefile",
    "scripts/ci-pr-tier.sh",
    "scripts/spec-drift-check.sh",
    "scripts/check-review-slices.py",
    ".github/workflows/cflite_pr.yml",
]:
    if not path_covered(path):
        raise SystemExit(f"cflite_pr pull_request paths do not trigger on selector input {path}")

fail_start = pr_text.index("name: Fail if no targets fired (changed-target mode)")
fail_block = pr_text[fail_start:pr_text.index("\n      - name:", fail_start)]
if '"${CLASSIFICATION}" == "no-fuzz-relevant-change"' not in fail_block:
    raise SystemExit("cflite_pr must pass an empty selection only on the explicit classification")
if "--classification classification.txt" not in pr_text:
    raise SystemExit("cflite_pr must record the selector classification")

mutants_text = Path(sys.argv[2]).read_text(encoding="utf-8")
mutants_path = Path(sys.argv[2]).resolve()
repo_root = mutants_path.parents[2]
selection_start = mutants_text.index("name: Select changed package")
selection_end = mutants_text.index("name: Install Rust toolchain", selection_start)
selection_block = mutants_text[selection_start:selection_end]
crate_paths = {
    "chio-kernel-core": "crates/kernel/chio-kernel-core",
    "chio-policy": "crates/guards/chio-policy",
    "chio-guards": "crates/guards/chio-guards",
    "chio-credentials": "crates/trust/chio-credentials",
    "chio-attest-verify": "crates/trust/chio-attest-verify",
    "chio-anchor": "crates/economy/chio-anchor",
}
for package, crate_path in crate_paths.items():
    mapping = f'{package}) crate_path="{crate_path}" ;;'
    if mapping not in selection_block:
        raise SystemExit(f"mutants-pr selection is missing grouped path for {package}")
    if not (repo_root / crate_path / "mutants.toml").is_file():
        raise SystemExit(f"mutants-pr config does not exist for {package}")
if 'echo "crate_path=${crate_path}" >> "${GITHUB_OUTPUT}"' not in selection_block:
    raise SystemExit("mutants-pr selection must export its resolved crate path")

mutation_start = mutants_text.index("name: Run cargo-mutants --in-diff against PR base")
mutation_end = mutants_text.index("name: Read survivor issue budget", mutation_start)
mutation_block = mutants_text[mutation_start:mutation_end]
if '--config "${{ steps.select.outputs.crate_path }}/mutants.toml"' not in mutation_block:
    raise SystemExit("mutants-pr must load the selected grouped crate config")
if '--config "crates/${{ matrix.package }}/mutants.toml"' in mutants_text:
    raise SystemExit("mutants-pr still reconstructs a flat crate config path")

PY

if ! grep -q "Named exception \`cflite-pr-evidence\`" "${DOCS}"; then
  echo "FAIL: docs/fuzzing/continuous.md must describe PR CFLite advisory behavior" >&2
  exit 1
fi

if ! grep -q "Mutation and proof-mutation lanes are reported, not capped" "${DOCS}"; then
  echo "FAIL: docs/fuzzing/continuous.md must describe report-only mutation budgets" >&2
  exit 1
fi
if ! grep -q 'proof-mutants.yml' "${DOCS}"; then
  echo "FAIL: docs/fuzzing/continuous.md must include proof-mutants budget accounting" >&2
  exit 1
fi

python3 - <<'PY' "${BUDGET_SCRIPT}"
from pathlib import Path
import sys

script = Path(sys.argv[1]).read_text(encoding="utf-8")
for removed in ("GH_FUZZ_BUDGET_CAP_MODE", "GH_FUZZ_BUDGET_RATE_LIMIT_MODE"):
    if removed in script:
        raise SystemExit(f"fuzz budget gate must not read {removed}")
if "cflite-pr-evidence" not in script or "API_ATTEMPTS=3" not in script:
    raise SystemExit("fuzz budget gate must declare its cap exception and retry bound")
if 'missing_workflow_mode="${GH_FUZZ_BUDGET_MISSING_WORKFLOW_MODE:-fail}"' not in script:
    raise SystemExit("missing workflow mode must default to fail")
if "workflow ${wf} is not registered yet; counting 0 minutes" in script:
    raise SystemExit("missing workflow must not be counted as zero minutes by default")
for line in [
    'CFLITE_WORKFLOWS=("cflite_pr.yml" "cflite_batch.yml")',
    "CFLITE_CAP_MINUTES=1800",
    'NATIVE_WORKFLOWS=("fuzz.yml")',
    "NATIVE_CAP_MINUTES=26000",
    'MUTATION_WORKFLOWS=("mutants.yml" "mutants-fuzz-cocoverage.yml" "proof-mutants.yml")',
    'SCOPE="${GH_FUZZ_BUDGET_SCOPE:-all}"',
    'CFLITE_EPOCH_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/fuzz/cflite-budget-epoch"',
]:
    if line not in script:
        raise SystemExit(f"fuzz budget envelopes must declare {line}")
PY

if ! grep -Eqx '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' "${REPO_ROOT}/fuzz/cflite-budget-epoch"; then
  echo "FAIL: fuzz/cflite-budget-epoch must hold one UTC timestamp" >&2
  exit 1
fi
if ! grep -q 'fuzz/cflite-budget-epoch' "${DOCS}"; then
  echo "FAIL: docs/fuzzing/continuous.md must describe the cflite budget epoch" >&2
  exit 1
fi

echo "PASS: fuzz budget envelopes, workflow scopes and docs agree"
