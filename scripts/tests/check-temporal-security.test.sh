#!/bin/bash -p
set -euo pipefail

if ! builtin shopt -qo privileged; then
  builtin printf '%s\n' "temporal security self-test requires Bash privileged mode" >&2
  builtin exit 64
fi

selftest_source="${BASH_SOURCE[0]}"
if [[ "${selftest_source}" != /* ]]; then
  selftest_source="$(builtin pwd -P)/${selftest_source}"
fi
if [[ -L "${selftest_source}" ]]; then
  builtin printf '%s\n' "temporal security self-test refuses a symlinked script path" >&2
  builtin exit 64
fi
script_dir="$(CDPATH= builtin cd -P -- "${selftest_source%/*}" && builtin pwd -P)"
repo_root="$(CDPATH= builtin cd -P -- "${script_dir}/../.." && builtin pwd -P)"
builtin cd -- "${repo_root}"

runner="scripts/check-temporal-security.sh"
exact_runner="scripts/run-exact-cargo-test-inventory.sh"
verifier="scripts/check-exact-cargo-test-inventory.py"
python_bin="/usr/bin/python3"
expected_runner_sha256="58e9245efb8d19ea1dc672b0463afa762c2355d9f585c132e7a0cf7be9d82554"
test -x "${runner}"
test -x "${exact_runner}"
test -x "${verifier}"
test -x "${python_bin}"
if [[ -L "${runner}" ]]; then
  builtin printf '%s\n' "temporal security gate source must not be a symlink" >&2
  builtin exit 1
fi
observed_runner_sha256="$("${python_bin}" - "${runner}" <<'PY'
import hashlib
import sys
from pathlib import Path

print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
if [[ "${observed_runner_sha256}" != "${expected_runner_sha256}" ]]; then
  builtin printf '%s\n' \
    "temporal security gate source digest mismatch: expected=${expected_runner_sha256} observed=${observed_runner_sha256}" >&2
  builtin exit 1
fi
/bin/bash -p -n "${runner}" "${exact_runner}"

validate_runner() {
  "${python_bin}" - "$1" <<'PY'
import hashlib
import re
import shlex
import sys
from pathlib import Path


TEST_PATTERN = re.compile(
    r"#\[(?:tokio::)?test(?:\([^]]*\))?\]\s*"
    r"(?:#\[[^]]+\]\s*)*(?:async\s+)?fn\s+([A-Za-z0-9_]+)"
)


def source_names(path: str, prefix: str, test_filter: str = "") -> list[str]:
    names = [
        prefix + name
        for name in TEST_PATTERN.findall(Path(path).read_text(encoding="utf-8"))
    ]
    return [name for name in names if test_filter in name]


def commitment(names: list[str]) -> tuple[int, str]:
    canonical = ("\n".join(sorted(names)) + "\n").encode("utf-8")
    return len(names), hashlib.sha256(canonical).hexdigest()


def parse_calls(path: Path) -> dict[str, tuple[bool, int, str, list[str]]]:
    source = path.read_text(encoding="utf-8")
    root_contract = '''script_source="${BASH_SOURCE[0]}"
if [[ "${script_source}" != /* ]]; then
  script_source="$(builtin pwd -P)/${script_source}"
fi
if [[ -L "${script_source}" ]]; then
  builtin printf '%s\\n' "temporal security gate refuses a symlinked script path" >&2
  builtin exit 64
fi
script_dir="$(CDPATH= builtin cd -P -- "${script_source%/*}" && builtin pwd -P)"
repo_root="$(CDPATH= builtin cd -P -- "${script_dir}/.." && builtin pwd -P)"
builtin cd -- "${repo_root}"'''
    if source.count(root_contract) != 1:
        raise SystemExit("temporal gate physical script-root contract changed")
    for helper, allow_filtered in (
        ("run_complete_inventory", False),
        ("run_filtered_inventory", True),
    ):
        match = re.search(
            rf"(?ms)^{helper}\(\) \{{\n(.*?)^\}}$",
            source,
        )
        if match is None:
            raise SystemExit(f"temporal inventory helper is missing: {helper}")
        body = match.group(1)
        for required in (
            "/bin/bash -p ./scripts/run-exact-cargo-test-inventory.sh",
            '--label "${label}"',
            '--expected-count "${expected_count}"',
            '--expected-sha256 "${expected_sha256}" --',
            '"$@"',
            "completed_inventories=$((completed_inventories + 1))",
            "completed_tests=$((completed_tests + expected_count))",
            'return "$?"',
        ):
            if body.count(required) != 1:
                raise SystemExit(f"{helper}: exact runner binding changed: {required}")
        if ("--allow-filtered" in body) != allow_filtered:
            raise SystemExit(f"{helper}: filtered-test policy changed")

    logical = source.replace("\\\n", " ")
    calls: dict[str, tuple[bool, int, str, list[str]]] = {}
    cargo_test_lines = 0
    for raw in logical.splitlines():
        line = raw.strip()
        if "cargo test" in line:
            cargo_test_lines += 1
        if not line.startswith(("run_complete_inventory ", "run_filtered_inventory ")):
            continue
        tokens = shlex.split(line)
        if len(tokens) < 8 or tokens[4:6] != ["cargo", "test"]:
            raise SystemExit(f"malformed temporal inventory call: {line}")
        helper, label, raw_count, digest = tokens[:4]
        if label in calls:
            raise SystemExit(f"duplicate temporal inventory label: {label}")
        if re.fullmatch(r"[1-9][0-9]*", raw_count) is None:
            raise SystemExit(f"{label}: invalid expected test count")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise SystemExit(f"{label}: invalid inventory SHA-256")
        command = tokens[4:]
        if "--" in command:
            raise SystemExit(f"{label}: Cargo command contains a harness separator")
        calls[label] = (
            helper == "run_filtered_inventory",
            int(raw_count),
            digest,
            command,
        )
    if cargo_test_lines != len(calls):
        raise SystemExit(
            "every temporal Cargo test command must use one exact inventory: "
            f"commands={cargo_test_lines} inventories={len(calls)}"
        )
    completion = '''if [[ "${completed_inventories}" -ne 10 ]] || [[ "${completed_tests}" -ne 40 ]]; then
  builtin printf '%s\\n' \\
    "Temporal security gate incomplete (${completed_inventories} inventories, ${completed_tests} tests)" >&2
  builtin exit 1
fi'''
    if source.count(completion) != 1:
        raise SystemExit("temporal gate completion accounting changed")
    success = (
        "builtin printf '%s\\n' "
        '"Temporal security gate passed (10 committed inventories, 40 tests)"'
    )
    if source.count(success) != 1:
        raise SystemExit("temporal gate success contract changed")
    return calls


source_contracts = {
    "temporal rule validation": source_names(
        "crates/security/chio-quarantine/tests/rules.rs", ""
    ),
    "temporal event-time correlation": source_names(
        "crates/security/chio-quarantine/tests/correlation.rs", ""
    ),
    "temporal correlation mutation controls": source_names(
        "crates/security/chio-quarantine/src/correlation.rs",
        "correlation::mutation_tests::",
        "correlation::mutation_tests::",
    ),
    "signed security event verification": source_names(
        "crates/core/chio-core-types/tests/signed_security_event.rs", ""
    ),
    "verified event provenance acceptance": source_names(
        "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_02.inc",
        "security::event_consumer::tests::",
        "security::event_consumer::tests::verifier_accepts",
    ),
    "receipt-backed event provenance rejection": source_names(
        "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_02.inc",
        "security::event_consumer::tests::",
        "security::event_consumer::tests::receipt_provenance",
    ),
    "corrupt event ingress rejection": source_names(
        "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_02.inc",
        "security::event_consumer::tests::",
        "security::event_consumer::tests::corrupt",
    ),
    "untrusted event producer rejection": source_names(
        "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_02.inc",
        "security::event_consumer::tests::",
        "security::event_consumer::tests::otherwise_valid_event",
    ),
    "unconfigured event policy rejection": source_names(
        "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_02.inc",
        "security::event_consumer::tests::",
        "security::event_consumer::tests::trusted_producer_signature",
    ),
    "verified event ingress mutation matrix": source_names(
        "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_02_temporal_ingress.inc",
        "security::event_consumer::tests::",
        "security::event_consumer::tests::verifier_ingress_rejects_",
    ),
}

expected_ingress_cases = sorted(
    "security::event_consumer::tests::" + name
    for name in [
        "verifier_ingress_rejects_cross_tenant_event_without_persistence",
        "verifier_ingress_rejects_forged_event_without_persistence",
        "verifier_ingress_rejects_future_dated_event_without_persistence",
        "verifier_ingress_rejects_invalid_receipt_event_without_persistence",
        "verifier_ingress_rejects_stale_event_without_persistence",
        "verifier_ingress_rejects_unsigned_event_without_persistence",
        "verifier_ingress_rejects_untrusted_producer_event_without_persistence",
    ]
)
if sorted(source_contracts["verified event ingress mutation matrix"]) != expected_ingress_cases:
    raise SystemExit(
        "verified event ingress case inventory changed: "
        f"expected={expected_ingress_cases!r} "
        f"observed={sorted(source_contracts['verified event ingress mutation matrix'])!r}"
    )

expected_commands = {
    "temporal rule validation": [
        "cargo", "test", "-p", "chio-quarantine", "--test", "rules"
    ],
    "temporal event-time correlation": [
        "cargo", "test", "-p", "chio-quarantine", "--test", "correlation"
    ],
    "temporal correlation mutation controls": [
        "cargo", "test", "-p", "chio-quarantine", "--lib",
        "correlation::mutation_tests::",
    ],
    "signed security event verification": [
        "cargo", "test", "-p", "chio-core-types", "--test",
        "signed_security_event",
    ],
    "verified event provenance acceptance": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "security::event_consumer::tests::verifier_accepts",
    ],
    "receipt-backed event provenance rejection": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "security::event_consumer::tests::receipt_provenance",
    ],
    "corrupt event ingress rejection": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "security::event_consumer::tests::corrupt",
    ],
    "untrusted event producer rejection": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "security::event_consumer::tests::otherwise_valid_event",
    ],
    "unconfigured event policy rejection": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "security::event_consumer::tests::trusted_producer_signature",
    ],
    "verified event ingress mutation matrix": [
        "cargo", "test", "-p", "chio-control-plane", "--lib",
        "security::event_consumer::tests::verifier_ingress_rejects_",
    ],
}

expected_filtering = {
    label: label not in {
        "temporal rule validation",
        "temporal event-time correlation",
        "signed security event verification",
    }
    for label in source_contracts
}

calls = parse_calls(Path(sys.argv[1]))
if set(calls) != set(source_contracts):
    raise SystemExit(
        "temporal inventory labels changed: "
        f"missing={sorted(set(source_contracts) - set(calls))!r} "
        f"unexpected={sorted(set(calls) - set(source_contracts))!r}"
    )

for label, names in source_contracts.items():
    filtered, count, digest, command = calls[label]
    if filtered != expected_filtering[label]:
        raise SystemExit(f"{label}: incorrect filtered-test policy")
    if command != expected_commands[label]:
        raise SystemExit(
            f"{label}: Cargo command changed: "
            f"expected={expected_commands[label]!r} observed={command!r}"
        )
    observed = (count, digest)
    expected = commitment(names)
    if observed != expected:
        raise SystemExit(
            f"{label}: inventory commitment drift: "
            f"expected={expected!r} observed={observed!r}"
        )
    if count == 0:
        raise SystemExit(f"{label}: committed inventory is empty")

expected_counts = {
    "temporal rule validation": 2,
    "temporal event-time correlation": 16,
    "temporal correlation mutation controls": 3,
    "signed security event verification": 5,
    "verified event provenance acceptance": 1,
    "receipt-backed event provenance rejection": 2,
    "corrupt event ingress rejection": 2,
    "untrusted event producer rejection": 1,
    "unconfigured event policy rejection": 1,
    "verified event ingress mutation matrix": 7,
}
observed_counts = {label: values[1] for label, values in calls.items()}
if observed_counts != expected_counts:
    raise SystemExit(
        "temporal inventory counts changed: "
        f"expected={expected_counts!r} observed={observed_counts!r}"
    )
PY
}

validate_runner "${runner}"

"${python_bin}" scripts/tests/check-exact-cargo-test-inventory.test.py
/usr/bin/env \
  -u BASH_ENV \
  -u ENV \
  -u SHELLOPTS \
  -u BASHOPTS \
  /bin/bash -p scripts/tests/run-exact-cargo-test-inventory.test.sh >/dev/null

"${python_bin}" - "${verifier}" <<'PY'
import subprocess
import sys
import tempfile
from pathlib import Path


verifier = Path(sys.argv[1]).resolve()
listing = "alpha: test\nbeta: test\n"
valid_run = """running 2 tests
test alpha ... ok
test beta ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""


def invoke(observed_listing: str, observed_run: str) -> int:
    with tempfile.TemporaryDirectory(prefix="chio-temporal-verifier-") as directory:
        root = Path(directory)
        list_path = root / "list.out"
        run_path = root / "run.out"
        list_path.write_text(observed_listing, encoding="utf-8")
        run_path.write_text(observed_run, encoding="utf-8")
        digest = __import__("hashlib").sha256(b"alpha\nbeta\n").hexdigest()
        return subprocess.run(
            [
                sys.executable,
                str(verifier),
                "--label",
                "temporal-hostile-fixture",
                "--list-output",
                str(list_path),
                "--run-output",
                str(run_path),
                "--expected-count",
                "2",
                "--expected-sha256",
                digest,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode


hostile = {
    "missing": ("alpha: test\n", valid_run),
    "extra": (listing + "gamma: test\n", valid_run),
    "ignored": (
        listing,
        valid_run.replace("test beta ... ok", "test beta ... ignored").replace(
            "2 passed; 0 failed; 0 ignored", "1 passed; 0 failed; 1 ignored"
        ),
    ),
    "zero": (
        listing,
        "running 0 tests\n\n"
        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
        "2 filtered out; finished in 0.01s\n",
    ),
}
if invoke(listing, valid_run) != 0:
    raise SystemExit("exact inventory verifier rejected valid temporal evidence")
for mode, (observed_listing, observed_run) in hostile.items():
    if invoke(observed_listing, observed_run) == 0:
        raise SystemExit(f"exact inventory verifier accepted hostile {mode} evidence")
PY

"${python_bin}" - \
  "${runner}" \
  "${exact_runner}" \
  "${verifier}" \
  "${expected_runner_sha256}" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


gate_path = Path(sys.argv[1])
exact_runner_path = Path(sys.argv[2])
verifier_path = Path(sys.argv[3])
expected_gate_sha256 = sys.argv[4]
gate_bytes = gate_path.read_bytes()
observed_gate_sha256 = hashlib.sha256(gate_bytes).hexdigest()
if observed_gate_sha256 != expected_gate_sha256:
    raise SystemExit(
        "temporal gate changed after the trusted source check: "
        f"expected={expected_gate_sha256} observed={observed_gate_sha256}"
    )
gate_source = gate_bytes.decode("utf-8")
exact_runner_source = exact_runner_path.read_text(encoding="utf-8")
verifier_source = verifier_path.read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def exact_args(
    label: str,
    count: int,
    digest: str,
    command: list[str],
    *,
    filtered: bool = False,
) -> list[str]:
    args = ["--label", label]
    if filtered:
        args.append("--allow-filtered")
    args.extend(
        [
            "--expected-count",
            str(count),
            "--expected-sha256",
            digest,
            "--",
            *command,
        ]
    )
    return args


expected_calls = [
    exact_args(
        "temporal rule validation",
        2,
        "a44f2fb52b1e55f9b1e874bbb4f84b92a1e06477ed1478911fe39dcbdd5c2bcd",
        ["cargo", "test", "-p", "chio-quarantine", "--test", "rules"],
    ),
    exact_args(
        "temporal event-time correlation",
        16,
        "755ee67c8cb26f7bec81c62c28b84c7f0c0e00ac139f20d95e2ce36aabd09ef4",
        ["cargo", "test", "-p", "chio-quarantine", "--test", "correlation"],
    ),
    exact_args(
        "temporal correlation mutation controls",
        3,
        "45e153188daf9b432216830a967d6c5a1e7b51078e33f065f1a05b9144536563",
        [
            "cargo",
            "test",
            "-p",
            "chio-quarantine",
            "--lib",
            "correlation::mutation_tests::",
        ],
        filtered=True,
    ),
    exact_args(
        "signed security event verification",
        5,
        "0e475ffcc30b39e6a044fe15e54f5940d3975d3ec64beee5d9ec16b7f9f7aaa0",
        [
            "cargo",
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "signed_security_event",
        ],
    ),
    exact_args(
        "verified event provenance acceptance",
        1,
        "7806a32aafcb999dee16b3ba7fb2f9cd2e6630e1310a8500a85b322022259713",
        [
            "cargo",
            "test",
            "-p",
            "chio-control-plane",
            "--lib",
            "security::event_consumer::tests::verifier_accepts",
        ],
        filtered=True,
    ),
    exact_args(
        "receipt-backed event provenance rejection",
        2,
        "7f58513090b4b1b09841047e9000f92ab0beaa5d786eaabfa91801ee7641710d",
        [
            "cargo",
            "test",
            "-p",
            "chio-control-plane",
            "--lib",
            "security::event_consumer::tests::receipt_provenance",
        ],
        filtered=True,
    ),
    exact_args(
        "corrupt event ingress rejection",
        2,
        "089f9974ccc2d7ac6ab0cf01e7272a549efa3930e73c388a3b4a4b9cc9745eb9",
        [
            "cargo",
            "test",
            "-p",
            "chio-control-plane",
            "--lib",
            "security::event_consumer::tests::corrupt",
        ],
        filtered=True,
    ),
    exact_args(
        "untrusted event producer rejection",
        1,
        "a9e1c7c6377dda82a1747deb7f5bcf0b6190c205fb46accbe75f66f9c3f90e12",
        [
            "cargo",
            "test",
            "-p",
            "chio-control-plane",
            "--lib",
            "security::event_consumer::tests::otherwise_valid_event",
        ],
        filtered=True,
    ),
    exact_args(
        "unconfigured event policy rejection",
        1,
        "b10498bfdde0e6bfae57ad7aa6fb284132c290171263c7c27849dba7ee03a074",
        [
            "cargo",
            "test",
            "-p",
            "chio-control-plane",
            "--lib",
            "security::event_consumer::tests::trusted_producer_signature",
        ],
        filtered=True,
    ),
    exact_args(
        "verified event ingress mutation matrix",
        7,
        "7472d4b71e744bc7c191eda45e9e18ceff0a239bda9963244a16df7f60dc60bb",
        [
            "cargo",
            "test",
            "-p",
            "chio-control-plane",
            "--lib",
            "security::event_consumer::tests::verifier_ingress_rejects_",
        ],
        filtered=True,
    ),
]
success_line = "Temporal security gate passed (10 committed inventories, 40 tests)"


def json_log(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def run_gate(
    source: str,
    *,
    fail_at: int = 0,
    fail_status: int = 0,
    symlink_entry: bool = False,
    privileged: bool = True,
    startup_attack: str = "",
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    with tempfile.TemporaryDirectory(prefix="chio-temporal-behavior-") as directory:
        base = Path(directory)
        repo = base / "repo"
        scripts = repo / "scripts"
        scripts.mkdir(parents=True)
        candidate = scripts / "check-temporal-security.sh"
        write_executable(candidate, source)
        syntax = subprocess.run(
            ["/bin/bash", "-p", "-n", str(candidate)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        require(syntax.returncode == 0, "generated temporal gate mutant is invalid shell")

        spy = base / "gate-spy.py"
        spy.write_text(
            f'''#!{sys.executable}
import json
import os
import sys
from pathlib import Path

log = Path(os.environ["TEMPORAL_CALL_LOG"])
prior = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
index = len(prior) + 1
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
if int(os.environ.get("TEMPORAL_FAIL_AT", "0")) == index:
    raise SystemExit(int(os.environ["TEMPORAL_FAIL_STATUS"]))
''',
            encoding="utf-8",
        )
        stub = scripts / "run-exact-cargo-test-inventory.sh"
        write_executable(
            stub,
            '''#!/bin/bash
exec "${TEMPORAL_STUB_PYTHON:?}" "${TEMPORAL_STUB_LOGGER:?}" "$@"
''',
        )
        entry = candidate
        if symlink_entry:
            counterfeit = base / "counterfeit" / "scripts"
            counterfeit.mkdir(parents=True)
            entry = counterfeit / "check-temporal-security.sh"
            entry.symlink_to(candidate)
            write_executable(
                counterfeit / "run-exact-cargo-test-inventory.sh",
                stub.read_text(encoding="utf-8"),
            )

        fake_bin = base / "hostile-bin"
        fake_bin.mkdir()
        for name in ("bash", "dirname", "pwd", "python3"):
            write_executable(fake_bin / name, "#!/bin/sh\nexit 91\n")
        invocation = base / "invocation"
        invocation.mkdir()
        call_log = base / "gate-calls.jsonl"
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": str(fake_bin),
                "CDPATH": str(base / "counterfeit-cdpath"),
                "TEMPORAL_CALL_LOG": str(call_log),
                "TEMPORAL_FAIL_AT": str(fail_at),
                "TEMPORAL_FAIL_STATUS": str(fail_status),
                "TEMPORAL_STUB_LOGGER": str(spy),
                "TEMPORAL_STUB_PYTHON": sys.executable,
            }
        )
        startup_file = base / "hostile-bash-env"
        startup_file.write_text("exit 73\n", encoding="utf-8")
        for variable in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            environment.pop(variable, None)
        environment.pop("BASH_FUNC_source%%", None)
        if startup_attack:
            environment.update(
                {
                    "BASH_ENV": (
                        str(startup_file) if startup_attack == "bash_env" else "/dev/null"
                    ),
                    "ENV": str(startup_file),
                    "SHELLOPTS": (
                        "braceexpand:hashall:interactive-comments:nounset:pipefail:xtrace"
                    ),
                    "BASHOPTS": "extglob",
                }
            )
        if startup_attack == "imported_function":
            environment["BASH_FUNC_source%%"] = "() { exit 74; }"
        bash_command = ["/bin/bash"]
        if privileged:
            bash_command.append("-p")
        bash_command.extend(
            ["-c", 'source "$1"', "temporal-self-test-shell", str(entry)]
        )
        result = subprocess.run(
            bash_command,
            cwd=invocation,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result, json_log(call_log)


def success_contract(source: str, *, startup_attack: str = "") -> bool:
    result, calls = run_gate(source, startup_attack=startup_attack)
    lines = [line for line in result.stdout.splitlines() if line]
    return (
        result.returncode == 0
        and calls == expected_calls
        and lines
        and lines[-1] == success_line
        and lines.count(success_line) == 1
    )


def failure_contract(source: str, position: int) -> bool:
    status = 70 + position
    result, calls = run_gate(source, fail_at=position, fail_status=status)
    output = result.stdout + result.stderr
    return (
        result.returncode == status
        and calls == expected_calls[:position]
        and success_line not in output
    )


require(success_contract(gate_source), "temporal gate failed the behavioral success contract")
for startup_attack, bare_status in (("bash_env", 73), ("imported_function", 74)):
    bare_result, bare_calls = run_gate(
        gate_source,
        privileged=False,
        startup_attack=startup_attack,
    )
    require(
        bare_result.returncode == bare_status
        and not bare_calls
        and success_line not in bare_result.stdout + bare_result.stderr,
        f"bare Bash did not demonstrate the {startup_attack} startup bypass",
    )
    require(
        success_contract(gate_source, startup_attack=startup_attack),
        f"Bash privileged mode did not suppress the {startup_attack} startup bypass",
    )
for position in range(1, len(expected_calls) + 1):
    require(
        failure_contract(gate_source, position),
        f"temporal gate failed exact exit propagation at inventory {position}",
    )
symlink_result, symlink_calls = run_gate(gate_source, symlink_entry=True)
require(
    symlink_result.returncode != 0
    and not symlink_calls
    and success_line not in symlink_result.stdout + symlink_result.stderr,
    "temporal gate accepted a final-component script symlink",
)


def replace_once(source: str, old: str, new: str, label: str) -> str:
    require(source.count(old) == 1, f"hostile mutation anchor is ambiguous: {label}")
    return source.replace(old, new, 1)


rules_block = '''run_complete_inventory \\
  "temporal rule validation" \\
  2 a44f2fb52b1e55f9b1e874bbb4f84b92a1e06477ed1478911fe39dcbdd5c2bcd \\
  cargo test -p chio-quarantine --test rules'''
correlation_block = '''run_complete_inventory \\
  "temporal event-time correlation" \\
  16 755ee67c8cb26f7bec81c62c28b84c7f0c0e00ac139f20d95e2ce36aabd09ef4 \\
  cargo test -p chio-quarantine --test correlation'''
correlation_digest = "755ee67c8cb26f7bec81c62c28b84c7f0c0e00ac139f20d95e2ce36aabd09ef4"
corrupt_filter = "security::event_consumer::tests::corrupt"
root_completion = 'builtin cd -- "${repo_root}"'
first_call = rules_block

reordered = replace_once(gate_source, rules_block, "__RULES_BLOCK__", "reorder rules")
reordered = replace_once(reordered, correlation_block, rules_block, "reorder correlation")
reordered = replace_once(reordered, "__RULES_BLOCK__", correlation_block, "reorder placeholder")
filtered_helper_index = gate_source.index("run_filtered_inventory() {")
complete_helper = gate_source[:filtered_helper_index]
filtered_and_calls = gate_source[filtered_helper_index:]
complete_helper = replace_once(
    complete_helper,
    "if /bin/bash -p ./scripts/run-exact-cargo-test-inventory.sh",
    "if true || /bin/bash -p ./scripts/run-exact-cargo-test-inventory.sh",
    "skipped exact runner",
)
skipped_exact_runner = complete_helper + filtered_and_calls

success_mutants = {
    "deleted block": replace_once(gate_source, rules_block, "", "deleted block"),
    "duplicated block": replace_once(
        gate_source, rules_block, rules_block + "\n\n" + rules_block, "duplicated block"
    ),
    "renamed inventory": replace_once(
        gate_source,
        "temporal event-time correlation",
        "renamed temporal correlation",
        "renamed inventory",
    ),
    "zero count": replace_once(
        gate_source,
        "2 a44f2fb52b1e55f9b1e874bbb4f84b92a1e06477ed1478911fe39dcbdd5c2bcd",
        "0 a44f2fb52b1e55f9b1e874bbb4f84b92a1e06477ed1478911fe39dcbdd5c2bcd",
        "zero count",
    ),
    "changed digest": replace_once(
        gate_source, correlation_digest, "0" * 64, "changed digest"
    ),
    "ignored harness": replace_once(
        gate_source, corrupt_filter, corrupt_filter + " -- --ignored", "ignored harness"
    ),
    "early exit": replace_once(
        gate_source, first_call, "exit 0\n\n" + first_call, "early exit"
    ),
    "early false success": replace_once(
        gate_source,
        first_call,
        "printf '%s\\n' \"" + success_line + "\"\nexit 0\n\n" + first_call,
        "early false success",
    ),
    "complete helper return": replace_once(
        gate_source,
        "run_complete_inventory() {\n",
        "run_complete_inventory() {\n  return 0\n",
        "complete helper return",
    ),
    "filtered helper return": replace_once(
        gate_source,
        "run_filtered_inventory() {\n",
        "run_filtered_inventory() {\n  return 0\n",
        "filtered helper return",
    ),
    "skipped exact runner": skipped_exact_runner,
    "if false block": replace_once(
        gate_source,
        rules_block,
        "if false; then\n" + rules_block + "\nfi",
        "if false block",
    ),
    "reordered inventories": reordered,
    "root override": replace_once(
        gate_source,
        root_completion,
        root_completion + "\nbuiltin cd -- /",
        "root override",
    ),
    "dollar zero root": replace_once(
        gate_source, '${BASH_SOURCE[0]}', "$0", "dollar zero root"
    ),
    "post-definition helper replacement": replace_once(
        gate_source,
        first_call,
        "run_complete_inventory() { return 0; }\n\n" + first_call,
        "post-definition helper replacement",
    ),
}
for label, mutant in success_mutants.items():
    require(
        not success_contract(mutant),
        f"temporal gate accepted hostile {label} mutation",
    )

command_endings = [
    "cargo test -p chio-quarantine --test rules",
    "cargo test -p chio-quarantine --test correlation",
    "correlation::mutation_tests::",
    "cargo test -p chio-core-types --test signed_security_event",
    "security::event_consumer::tests::verifier_accepts",
    "security::event_consumer::tests::receipt_provenance",
    "security::event_consumer::tests::corrupt",
    "security::event_consumer::tests::otherwise_valid_event",
    "security::event_consumer::tests::trusted_producer_signature",
    "security::event_consumer::tests::verifier_ingress_rejects_",
]
for position, ending in enumerate(command_endings, start=1):
    mutant = replace_once(
        gate_source, ending, ending + " || true", f"or-true inventory {position}"
    )
    require(
        not failure_contract(mutant, position),
        f"temporal gate accepted || true at inventory {position}",
    )

complete_status_helper = gate_source[:filtered_helper_index]
complete_status_helper = replace_once(
    complete_status_helper,
    '      "$@"; then',
    '      "$@" || true; then',
    "complete helper swallowed status",
)
complete_swallowed_status = complete_status_helper + filtered_and_calls
failure_mutants = {
    "disabled errexit": (
        replace_once(
            gate_source,
            "set -euo pipefail",
            "set -euo pipefail\nset +e",
            "disabled errexit",
        ),
        1,
    ),
    "success ERR trap": (
        replace_once(
            gate_source,
            "set -euo pipefail",
            "set -euo pipefail\ntrap 'exit 0' ERR",
            "success ERR trap",
        ),
        1,
    ),
    "complete helper swallowed status": (complete_swallowed_status, 1),
}
filtered_anchor = 'run_filtered_inventory() {'
filtered_index = gate_source.index(filtered_anchor)
filtered_prefix = gate_source[:filtered_index]
filtered_body = gate_source[filtered_index:]
filtered_body = replace_once(
    filtered_body,
    '      "$@"; then',
    '      "$@" || true; then',
    "filtered helper swallowed status",
)
failure_mutants["filtered helper swallowed status"] = (
    filtered_prefix + filtered_body,
    3,
)
for label, (mutant, position) in failure_mutants.items():
    require(
        not failure_contract(mutant, position),
        f"temporal gate accepted hostile {label} mutation",
    )


def run_exact_runner(
    source: str,
    *,
    cargo_failure: str = "",
    verifier_failure: int = 0,
) -> tuple[subprocess.CompletedProcess[str], list[list[str]], list[list[str]]]:
    with tempfile.TemporaryDirectory(prefix="chio-exact-wrapper-behavior-") as directory:
        base = Path(directory)
        repo = base / "repo"
        scripts = repo / "scripts"
        scripts.mkdir(parents=True)
        candidate = scripts / "run-exact-cargo-test-inventory.sh"
        write_executable(candidate, source)
        write_executable(
            scripts / "check-exact-cargo-test-inventory.py", verifier_source
        )
        syntax = subprocess.run(
            ["/bin/bash", "-p", "-n", str(candidate)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        require(syntax.returncode == 0, "generated exact-wrapper mutant is invalid shell")

        fake_bin = base / "bin"
        fake_bin.mkdir()
        cargo_log = base / "cargo.jsonl"
        python_log = base / "python.jsonl"
        write_executable(
            fake_bin / "cargo",
            f'''#!{sys.executable}
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["EXACT_CARGO_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\\n")
listing = args[-2:] == ["--", "--list"]
phase = "list" if listing else "run"
if os.environ.get("EXACT_CARGO_FAILURE") == phase:
    raise SystemExit(int(os.environ["EXACT_FAILURE_STATUS"]))
if listing:
    print("alpha: test")
    print("beta: test")
else:
    print("running 2 tests")
    print("test alpha ... ok")
    print("test beta ... ok")
    print()
    print("test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s")
''',
        )
        write_executable(
            fake_bin / "python3",
            f'''#!{sys.executable}
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["EXACT_PYTHON_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\\n")
failure = int(os.environ.get("EXACT_VERIFIER_FAILURE", "0"))
if failure:
    raise SystemExit(failure)
os.execv({sys.executable!r}, [{sys.executable!r}, *args])
''',
        )
        temporary = base / "tmp"
        temporary.mkdir()
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                "TMPDIR": str(temporary),
                "EXACT_CARGO_LOG": str(cargo_log),
                "EXACT_PYTHON_LOG": str(python_log),
                "EXACT_CARGO_FAILURE": cargo_failure,
                "EXACT_FAILURE_STATUS": "82",
                "EXACT_VERIFIER_FAILURE": str(verifier_failure),
            }
        )
        result = subprocess.run(
            [
                "/bin/bash",
                "-p",
                str(candidate),
                "--label",
                "shared-wrapper-selftest",
                "--expected",
                "alpha",
                "beta",
                "--",
                "cargo",
                "test",
                "-p",
                "fixture",
                "--test",
                "inventory",
            ],
            cwd=repo,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result, json_log(cargo_log), json_log(python_log)


list_call = [
    "test",
    "-p",
    "fixture",
    "--test",
    "inventory",
    "--",
    "--list",
]
run_call = ["test", "-p", "fixture", "--test", "inventory"]


def verifier_call_is_exact(calls: list[list[str]]) -> bool:
    if len(calls) != 1:
        return False
    args = calls[0]
    return (
        len(args) == 9
        and args[:4]
        == [
            "scripts/check-exact-cargo-test-inventory.py",
            "--label",
            "shared-wrapper-selftest",
            "--list-output",
        ]
        and Path(args[4]).name.startswith("chio-exact-test-list.")
        and args[5] == "--run-output"
        and Path(args[6]).name.startswith("chio-exact-test-run.")
        and args[7:] == ["alpha", "beta"]
    )


def exact_success_contract(source: str) -> bool:
    result, cargo_calls, python_calls = run_exact_runner(source)
    return (
        result.returncode == 0
        and cargo_calls == [list_call, run_call]
        and verifier_call_is_exact(python_calls)
        and result.stdout.count("shared-wrapper-selftest passed (2 exact tests)") == 1
    )


def exact_failure_contract(source: str, phase: str) -> bool:
    if phase == "verifier":
        status = 83
        result, cargo_calls, python_calls = run_exact_runner(
            source, verifier_failure=status
        )
        expected_cargo = [list_call, run_call]
        expected_python = verifier_call_is_exact(python_calls)
    else:
        status = 82
        result, cargo_calls, python_calls = run_exact_runner(
            source, cargo_failure=phase
        )
        expected_cargo = [list_call] if phase == "list" else [list_call, run_call]
        expected_python = not python_calls
    return (
        result.returncode == status
        and cargo_calls == expected_cargo
        and expected_python
        and "shared-wrapper-selftest passed" not in result.stdout + result.stderr
    )


require(
    exact_success_contract(exact_runner_source),
    "shared exact-inventory wrapper failed its behavioral success contract",
)
for phase in ("list", "run", "verifier"):
    require(
        exact_failure_contract(exact_runner_source, phase),
        f"shared exact-inventory wrapper failed {phase} status propagation",
    )

verifier_invocation = '"${verifier[@]}"'
exact_success_mutants = {
    "early exit": replace_once(
        exact_runner_source,
        "set -euo pipefail",
        "set -euo pipefail\nexit 0",
        "exact wrapper early exit",
    ),
    "skipped verifier": replace_once(
        exact_runner_source,
        verifier_invocation,
        "true",
        "exact wrapper skipped verifier",
    ),
    "if false verifier": replace_once(
        exact_runner_source,
        verifier_invocation,
        'if false; then\n  "${verifier[@]}"\nfi',
        "exact wrapper if false verifier",
    ),
}
for label, mutant in exact_success_mutants.items():
    require(
        not exact_success_contract(mutant),
        f"shared exact-inventory wrapper accepted hostile {label} mutation",
    )
swallowed_verifier = replace_once(
    exact_runner_source,
    verifier_invocation,
    '"${verifier[@]}" || true',
    "exact wrapper swallowed verifier",
)
require(
    not exact_failure_contract(swallowed_verifier, "verifier"),
    "shared exact-inventory wrapper accepted a swallowed verifier failure",
)
PY

builtin printf '%s\n' "Temporal security gate self-test passed (10 committed inventories, 40 tests)"
