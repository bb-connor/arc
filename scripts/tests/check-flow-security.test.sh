#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-flow-security.sh"
exact_runner="scripts/run-exact-cargo-test-inventory.sh"
test -x "${runner}"
test -x "${exact_runner}"
bash -n "${runner}" "${exact_runner}"

for model in \
  formal/tla/InformationFlowLattice.tla \
  formal/tla/MCInformationFlowLattice.cfg \
  formal/tla/_negative_tests/InformationFlowLatticeReaderDirectionBroken.tla \
  formal/tla/_negative_tests/MCInformationFlowLatticeReaderDirectionBroken.cfg
do
  test -f "${model}"
  test ! -L "${model}"
done

for required in \
  'formal/tla/MCInformationFlowLattice.cfg' \
  'MCInformationFlowLatticeReaderDirectionBroken.cfg' \
  'wasm32-unknown-unknown' \
  'run_exact_target --label "security types library"' \
  'run_exact_target --label "flow lattice and enforcement engine"' \
  'run_exact_target --label "strict manifest v2"' \
  'run_exact_target --label "security kernel adapters"' \
  'generic_pre_invocation_adapter_fails_closed_without_declassification_store' \
  'run_exact_target --label "durable flow state"' \
  'run_exact_target --label "security runtime composition"' \
  'run_exact_target --label "security schema vectors"'
do
  grep -Fq "${required}" "${runner}"
done

python3 - "${runner}" <<'PY'
import re
import shlex
import sys
from pathlib import Path


def parse(path: Path) -> dict[str, tuple[bool, list[str], list[str]]]:
    logical = path.read_text(encoding="utf-8").replace("\\\n", " ")
    calls: dict[str, tuple[bool, list[str], list[str]]] = {}
    cargo_test_lines = 0
    for raw in logical.splitlines():
        line = raw.strip()
        if "cargo test" in line:
            cargo_test_lines += 1
        if not line.startswith("run_exact_target "):
            continue
        tokens = shlex.split(line)
        try:
            label = tokens[tokens.index("--label") + 1]
            expected_start = tokens.index("--expected") + 1
            separator = tokens.index("--")
        except (ValueError, IndexError) as error:
            raise SystemExit(f"malformed exact flow call: {line}: {error}") from error
        expected = tokens[expected_start:separator]
        command = tokens[separator + 1 :]
        if not expected or len(expected) != len(set(expected)):
            raise SystemExit(f"{label}: expected inventory is empty or duplicated")
        if not all(re.fullmatch(r"[A-Za-z0-9_:]+", name) for name in expected):
            raise SystemExit(f"{label}: invalid Rust test name in exact inventory")
        if command[:2] != ["cargo", "test"]:
            raise SystemExit(f"{label}: exact inventory does not wrap cargo test")
        if label in calls:
            raise SystemExit(f"duplicate flow gate label: {label}")
        calls[label] = ("--allow-filtered" in tokens, expected, command)
    if cargo_test_lines != len(calls):
        raise SystemExit(
            "every flow Cargo test command must be owned by one exact inventory call: "
            f"commands={cargo_test_lines} exact_calls={len(calls)}"
        )
    return calls


calls = parse(Path(sys.argv[1]))
expected_counts = {
    "security types library": 20,
    "security capability-set suspension types": 4,
    "security egress-restriction types": 2,
    "security event types": 3,
    "security issuance-freeze types": 4,
    "security port contracts": 7,
    "security response-dispatch types": 4,
    "security response types": 9,
    "security session-throttle types": 3,
    "flow lattice and enforcement engine": 42,
    "strict manifest v2": 23,
    "security kernel adapters": 23,
    "durable flow state": 33,
    "security runtime composition": 2,
    "OpenAPI bridge canonical flow": 1,
    "MCP flow sidecar": 1,
    "A2A canonical flow": 1,
    "A2A rejected flow sidecar": 1,
    "ACP canonical flow": 1,
    "ACP rejected flow sidecar": 1,
    "OpenAI canonical flow": 1,
    "OpenAI rejected flow sidecar": 1,
    "Anthropic canonical round trip": 1,
    "cross-protocol canonical flow": 1,
    "cross-protocol rejects unadmitted sidecar": 1,
    "cross-protocol rejects forged sidecar": 1,
    "Bedrock canonical flow": 1,
    "Gemini canonical flow": 1,
    "Ollama canonical flow": 1,
    "Mistral canonical stream": 1,
    "Groq canonical stream": 1,
    "Cohere canonical stream": 1,
    "security schema vectors": 2,
}
observed_counts = {label: len(value[1]) for label, value in calls.items()}
if observed_counts != expected_counts:
    raise SystemExit(
        "flow exact inventory labels/counts changed without updating the contract: "
        f"expected={expected_counts!r} observed={observed_counts!r}"
    )

unfiltered = {
    "security types library",
    "security capability-set suspension types",
    "security egress-restriction types",
    "security event types",
    "security issuance-freeze types",
    "security port contracts",
    "security response-dispatch types",
    "security response types",
    "security session-throttle types",
    "flow lattice and enforcement engine",
    "strict manifest v2",
    "security kernel adapters",
    "durable flow state",
    "security schema vectors",
}
for label, (allow_filtered, _, _) in calls.items():
    if allow_filtered == (label in unfiltered):
        raise SystemExit(f"{label}: incorrect filtered-test policy")

required_adapter_commands = {
    "OpenAPI bridge canonical flow": "chio-openapi-mcp-bridge",
    "MCP flow sidecar": "chio-mcp-edge",
    "A2A canonical flow": "chio-a2a-edge",
    "A2A rejected flow sidecar": "chio-a2a-edge",
    "ACP canonical flow": "chio-acp-edge",
    "ACP rejected flow sidecar": "chio-acp-edge",
    "OpenAI canonical flow": "chio-openai-adapter",
    "OpenAI rejected flow sidecar": "chio-openai-adapter",
    "Anthropic canonical round trip": "chio-anthropic-tools-adapter",
    "cross-protocol canonical flow": "chio-cross-protocol",
    "cross-protocol rejects unadmitted sidecar": "chio-cross-protocol",
    "cross-protocol rejects forged sidecar": "chio-cross-protocol",
    "Bedrock canonical flow": "chio-bedrock-converse-adapter",
    "Gemini canonical flow": "chio-gemini-tools-adapter",
    "Ollama canonical flow": "chio-ollama-tools-adapter",
    "Mistral canonical stream": "chio-mistral-tools-adapter",
    "Groq canonical stream": "chio-groq-tools-adapter",
    "Cohere canonical stream": "chio-cohere-tools-adapter",
}
for label, package in required_adapter_commands.items():
    command = calls[label][2]
    if "-p" not in command or command[command.index("-p") + 1] != package:
        raise SystemExit(f"{label}: exact inventory is wired to the wrong package")
PY

mutant="$(mktemp "${TMPDIR:-/tmp}/check-flow-security-mutant.XXXXXX")"
trap 'rm -f "${mutant}"' EXIT
sed '/run_exact_target --label "Cohere canonical stream"/,/cargo test -p chio-cohere-tools-adapter/d' \
  "${runner}" > "${mutant}"
set +e
python3 - "${mutant}" <<'PY'
import shlex
import sys
from pathlib import Path

logical = Path(sys.argv[1]).read_text(encoding="utf-8").replace("\\\n", " ")
labels = []
for line in logical.splitlines():
    tokens = shlex.split(line.strip())
    if tokens and tokens[0] == "run_exact_target" and "--label" in tokens:
        labels.append(tokens[tokens.index("--label") + 1])
if "Cohere canonical stream" not in labels:
    raise SystemExit(1)
PY
status=$?
set -e
if [[ "${status}" -eq 0 ]]; then
  echo "flow gate missing-target mutant unexpectedly passed" >&2
  exit 1
fi

echo "Flow security gate contract passed (33 exact inventories)"
