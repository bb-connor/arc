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
  'umask 022' \
  'export RUST_TEST_THREADS=1' \
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


def parse(source: str) -> dict[str, tuple[bool, list[str], list[str]]]:
    success = 'echo "Flow security gate passed"'
    if source.count(success) != 1 or source.rfind(success) < source.rfind("run_exact_target "):
        raise SystemExit("flow success must follow every required test inventory")
    logical = source.replace("\\\n", " ")
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


expected_counts = {
    "frozen federation context": 13,
    "frozen dispatch participant context": 27,
    "durable caller participant persistence": 3,
    "native compiled catalog identity": 2,
    "native post-join policy": 80,
    "native declassification row semantics": 1,
    "native declassification issuer window": 1,
    "public nested credential custody": 5,
    "native capture accounting deltas": 2,
    "native runtime validity contract": 1,
    "native runtime signed freshness": 3,
    "native input intent contracts": 6,
    "native global journal migration": 4,
    "native nonce issuance custody": 1,
    "native policy clock bounds": 1,
    "security types library": 20,
    "security capability-set suspension types": 4,
    "security egress-restriction types": 2,
    "security event types": 3,
    "security issuance-freeze types": 4,
    "security port contracts": 7,
    "security response-dispatch types": 4,
    "security response types": 9,
    "security session-throttle types": 3,
    "flow lattice and enforcement engine": 46,
    "strict manifest v2": 23,
    "security kernel adapters": 34,
    "durable flow state": 33,
    "native flow custody": 93,
    "native dispatch participant snapshots": 3,
    "native dispatch ledger callbacks": 3,
    "native dispatch attachment contracts": 4,
    "native flow observation contracts": 3,
    "original security authority selection": 22,
    "original operation authority profile": 7,
    "runtime profile non-upgrade": 1,
    "native authority admission integration": 12,
    "physical dispatch hold ownership": 3,
    "kernel-owned native preparation": 11,
    "kernel-owned native egress": 8,
    "qualified recovery lease boundary": 5,
    "runtime recovery lease containment": 1,
    "prepared flow dispatch binding": 13,
    "security runtime composition": 2,
    "security dispatch credential boundaries": 8,
    "durable security release recovery": 25,
    "durable release output binding": 2,
    "frozen durable receipt signing": 9,
    "dispatch rejection payment custody": 8,
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
    "native authority admission integration",
    "durable security release recovery",
    "security schema vectors",
}
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
required_native_commands = {
    "frozen federation context": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "kernel::tests::federation_context::",
    ],
    "frozen dispatch participant context": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "return_context::",
    ],
    "durable caller participant persistence": [
        "cargo", "test", "-p", "chio-store-sqlite", "--test",
        "execution_nonce_caller_execution", "dispatch_context::",
    ],
    "frozen durable receipt signing": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "kernel::tests::return_context::signing::",
    ],
    "durable release output binding": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "tool_outcome::security_release::context::tests::",
    ],
    "durable security release recovery": [
        "cargo", "test", "-p", "chio-store-sqlite", "--test", "security_release_recovery",
    ],
    "native capture accounting deltas": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib",
        "budget_store::composite::native_capture::tests::",
    ],
    "native dispatch attachment contracts": [
        "cargo", "test", "-p", "chio-kernel", "--lib",
        "admission_operation::capture::tests::native_dispatch_attachment_",
    ],
    "native dispatch ledger callbacks": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "kernel::tests::native_dispatch_ledger::",
    ],
    "native dispatch participant snapshots": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib", "ledger_snapshot",
    ],
    "security dispatch credential boundaries": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "kernel::tests::security_dispatch::",
    ],
    "dispatch rejection payment custody": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "kernel::tests::dispatch_commit_failure::",
    ],
    "native global journal migration": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib",
        "serving_owner::global_commit_chain::schema_tests::",
    ],
    "native nonce issuance custody": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib",
        "admission_operation_store::tests::execution_nonce::native_preflight::",
    ],
    "native input intent contracts": [
        "cargo", "test", "-p", "chio-kernel", "--lib",
        "admission_operation::native_input_join::tests::",
    ],
    "native post-join policy": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "security::adapters::tests::native_flow::",
    ],
    "native declassification row semantics": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib",
        "native_declassification_row_commands_match_shared_semantics_and_reject_substitution",
    ],
    "native declassification issuer window": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib",
        "native_declassification_egress_observation_enforces_both_issuer_time_bounds",
    ],
    "native policy clock bounds": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "security::adapters::native_flow::tests::",
    ],
    "kernel-owned native egress": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "kernel::tests::native_egress",
    ],
    "prepared flow dispatch binding": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "security::adapters::tests::prepared_dispatch::",
    ],
    "original operation authority profile": [
        "cargo", "test", "-p", "chio-kernel", "--lib", "authority_profile",
    ],
    "runtime profile non-upgrade": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib",
        "admission_operation_store::tests::runtime_replay::claims::runtime_claim_cannot_upgrade_absent_or_historical_authority_profile",
    ],
    "native flow custody": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib",
        "admission_operation_store::tests::security_participant_state::",
    ],
    "native compiled catalog identity": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib",
        "admission_operation_store::security_participant_state::schema::tests::",
    ],
    "original security authority selection": [
        "cargo", "test", "-p", "chio-kernel", "--lib",
        "kernel::tests::security_binding::",
    ],
    "native authority admission integration": [
        "cargo", "test", "-p", "chio-store-sqlite", "--test",
        "native_authority_binding",
    ],
    "physical dispatch hold ownership": [
        "cargo", "test", "-p", "chio-store-sqlite", "--lib",
        "admission_operation_store::tests::budget_atomicity::capture_owner::",
    ],
}


def validate(calls: dict[str, tuple[bool, list[str], list[str]]]) -> None:
    observed_counts = {label: len(value[1]) for label, value in calls.items()}
    if observed_counts != expected_counts:
        raise SystemExit(
            "flow exact inventory labels/counts changed without updating the contract: "
            f"expected={expected_counts!r} observed={observed_counts!r}"
        )
    for label, (allow_filtered, _, _) in calls.items():
        if allow_filtered == (label in unfiltered):
            raise SystemExit(f"{label}: incorrect filtered-test policy")
    for label, package in required_adapter_commands.items():
        command = calls[label][2]
        if "-p" not in command or command[command.index("-p") + 1] != package:
            raise SystemExit(f"{label}: exact inventory is wired to the wrong package")
    for label, expected_command in required_native_commands.items():
        if calls[label][2] != expected_command:
            raise SystemExit(f"{label}: native authority target is not exact")


source = Path(sys.argv[1]).read_text(encoding="utf-8")
validate(parse(source))


def rejects(name: str, source: str, expected_error: str) -> None:
    try:
        validate(parse(source))
    except SystemExit as error:
        if expected_error not in str(error):
            raise SystemExit(f"{name}: failed for the wrong reason: {error}") from error
    else:
        raise SystemExit(f"{name}: flow gate mutation unexpectedly passed")


# Run mutations through the same parser and validator as the actual script.
# Do not replace the validator with a separate missing-label predicate.
rejects(
    "premature flow success",
    'echo "Flow security gate passed"\n' + source.replace('echo "Flow security gate passed"', ""),
    "flow success must follow every required test inventory",
)
rejects(
    "duplicate premature flow success",
    'echo "Flow security gate passed"\n' + source,
    "flow success must follow every required test inventory",
)
for label in ("Cohere canonical stream", *required_native_commands):
    logical_lines = source.replace("\\\n", " ").splitlines()
    changed = "\n".join(
        line for line in logical_lines if f'--label "{label}"' not in line
    )
    rejects(f"missing {label}", changed, "flow exact inventory labels/counts changed")

native_filter = "admission_operation_store::tests::security_participant_state::"
prepared_filter = "security::adapters::tests::prepared_dispatch::"
for replacement in (
    "security::adapters::tests::flow_dispatch_tests::",
    "security::adapters::tests::",
    prepared_filter + " -- --ignored",
):
    rejects(
        "changed prepared dispatch target",
        source.replace(f"--lib {prepared_filter}", f"--lib {replacement}"),
        "native authority target is not exact",
    )
for replacement in (
    "admission_operation_store_tests::security_participant_state::",
    "admission_operation_store::tests::",
    native_filter + " -- --ignored",
):
    rejects(
        "changed native target",
        source.replace(f"--lib {native_filter}", f"--lib {replacement}"),
        "native authority target is not exact",
    )
rejects(
    "changed native integration target kind",
    source.replace("--test native_authority_binding", "--lib native_authority_binding"),
    "native authority target is not exact",
)
rejects(
    "changed native filtering policy",
    source.replace(
        '--label "native flow custody" --allow-filtered',
        '--label "native flow custody"',
    ),
    "incorrect filtered-test policy",
)
print(f"Flow security gate contract passed ({len(expected_counts)} exact inventories)")
PY
