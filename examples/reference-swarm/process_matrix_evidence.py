"""Portable local scenario evidence with independently retained operator pins.

Kernel and launch signatures prove their stated observations. File/socket/PID
observations remain assertions by the operator who captured and pinned the bundle.
They are never converted into tool receipts or platform authorization.
"""

import hashlib
import json
import copy
import subprocess
import tempfile
from pathlib import Path


SCENARIOS = (
    "reference",
    "authority",
    "revocation",
    "filesystem",
    "network",
    "host-crash",
    "budget",
)
SCHEMA = "chio.reference-swarm.local-matrix.v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def read(path, limit=64 * 1024 * 1024):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "evidence exceeds size limit")
    return json.loads(data, object_pairs_hook=unique_object)


def write(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def invoke(chio, *args):
    result = subprocess.run(
        [str(chio), *map(str, args)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    require(result.returncode == 0, result.stderr or result.stdout)
    return json.loads(result.stdout, object_pairs_hook=unique_object)


def collect_case(chio, name, folder, plan):
    state = folder / "state"
    output = folder / "worker-outcomes.json"
    invoke(
        chio,
        "process",
        "attest-outcomes",
        "--state",
        state,
        "--plan",
        plan,
        "--out",
        output,
    )
    host = read(state / "host.json")
    pins = {
        "runtime_id": read(state / "swarm-calls.json")["runtime_id"],
        "kernel_public_key": (state / "authority.db.kernel.pub").read_text().strip(),
        "policy_signers": {
            server["id"]: server["launch_policy_signer"]
            for server in host["config"]["servers"]
        },
    }
    case = {
        "outcomes": read(output),
        "observation": read(
            folder
            / (
                "repository-report.json"
                if name == "reference"
                else "qualification.json"
            )
        ),
    }
    if name == "reference":
        case["inputs"] = read(folder / "inputs.json")
    if name in ("reference", "filesystem", "authority"):
        completed = folder / (
            "completed-run.json"
            if name == "authority"
            else "evidence/completed-run.json"
        )
        case["completed_run"] = read(completed)
    if name == "filesystem":
        case["positive_controls"] = read(folder / "controls.json")
    if name == "authority":
        case["denials"] = {
            f"{worker}-{index}": {
                field: read(folder / f"{worker}-denial-{index}" / f"{field}.json")
                for field in ("request", "context", "response")
            }
            for worker in ("alice", "bob")
            for index in range(4)
        }
    if name in ("host-crash", "budget"):
        originals = folder / "original-native-launches"
        observation = read(originals / "observation.json")
        pins["original_launches"] = observation["launches"]
        case["original_launches"] = {
            server: {
                "policy": (originals / f"{server}-policy.json").read_text(),
                "enforcement": read(originals / f"{server}-receipt.ndjson"),
            }
            for server in observation["launches"]
        }
    return case, pins


def response(call):
    return call["action"]["parameters"]["response"]


def signed_response(call):
    return json.loads(response(call)["receipt_json"], object_pairs_hook=unique_object)


def verify_authority_probes(case):
    """Bind each signed denial to the planned isolation probe it represents."""
    run = case["outcomes"]["action"]["parameters"]
    workers = run["runner"]["plan"]["workers"]
    require(
        len(workers) == 2 and {item["process"] for item in workers} == {"alice", "bob"},
        "authority probe worker inventory differs",
    )
    inputs = {item["process"]: item["input"] for item in workers}
    fields = (
        "process", "operation_key", "server_id", "tool_name", "arguments",
        "governed_intent", "request_id", "capability_sha256",
    )
    request_fields = ("operation_key", "server_id", "tool_name", "arguments")
    for worker, peer in (("alice", "bob"), ("bob", "alice")):
        own_input, peer_input = inputs[worker], inputs[peer]
        require(
            own_input["process"] == worker
            and own_input["expected_verdict"] == "allow"
            and own_input["check_replay"] is True
            and own_input["crash_after_checkpoint"] is (worker == "alice"),
            "authority worker plan omits replay or deliberate recovery",
        )
        own = {field: own_input[field] for field in fields}
        other = {field: peer_input[field] for field in fields}
        require(
            own["arguments"] != other["arguments"]
            and own["governed_intent"] != other["governed_intent"]
            and own["capability_sha256"] != other["capability_sha256"]
            and own["request_id"] != other["request_id"],
            "authority peer challenge is not distinct",
        )
        probes = (
            dict(own, operation_key="scope-widening", tool_name="write_file"),
            dict(other, process=worker, operation_key="peer-authority"),
            dict(own, operation_key="changed-intent", arguments=other["arguments"]),
            dict(own, operation_key="reused-continuation"),
        )
        require(
            own_input["probes"] == list(probes[:3]),
            "authority probe plan differs from isolation challenges",
        )
        for index, probe in enumerate(probes):
            request = {field: probe[field] for field in request_fields}
            request["known_outcome_only"] = False
            require(
                case["denials"][f"{worker}-{index}"]["request"] == request,
                "authority denial differs from its planned isolation probe",
            )


def verify_observations(name, case, verified, identity):
    """Join pinned external observations to independently verified runtime facts."""
    run = case["outcomes"]["action"]["parameters"]
    calls, observed = run["calls"], case["observation"]
    states = verified["observed_operations"]
    require(
        verified["artifact_schema"] in (
            "chio.process.worker-outcomes.v2", "chio.process.worker-outcomes.v3"
        ),
        "matrix requires native-bound outcomes v2 or v3",
    )
    if verified["artifact_schema"] == "chio.process.worker-outcomes.v3":
        require(
            {"execution_nonces", "receipt_log_inclusion"} <= set(verified["checks"]),
            "nonce-aware outcomes require nonce custody and receipt-log verification",
        )
    require(
        set(verified["native_launches"]) == set(calls),
        "matrix requires a verified native launch for every worker",
    )
    require(
        all(
            worker["container"]["image"] == identity["worker_image"]
            for worker in run["runner"]["plan"]["workers"]
        ),
        "worker image differs across matrix",
    )
    if name == "reference":
        inputs = case["inputs"]
        require(
            observed["schema"] == "chio.reference-swarm.repository-report.v1",
            "reference report schema differs",
        )
        require(
            inputs["runtime_id"] == verified["runtime_id"],
            "reference input runtime differs",
        )
        require(
            len(inputs["files"]) == len(calls)
            and {item["process"] for item in inputs["files"]} == set(calls),
            "reference input worker inventory differs",
        )
        require(
            len(observed["files"]) == len(calls)
            and {item["process"] for item in observed["files"]} == set(calls),
            "reference report worker inventory differs",
        )
        for item in inputs["files"]:
            call = calls[item["process"]]
            request = call["action"]["parameters"]["request"]
            require(
                request["server_id"] == "reference-reader"
                and request["tool_name"] == "read_file"
                and request["operation_key"] == "read-source"
                and request["arguments"] == {"path": item["path"]},
                "reference request differs from original input plan",
            )
            result = response(call)["output"]["value"]["structuredContent"]
            content = result["content"].encode("utf-8")
            require(
                (
                    result["path"],
                    result["truncated"],
                    len(content),
                    hashlib.sha256(content).hexdigest(),
                )
                == (item["path"], False, item["bytes"], item["sha256"]),
                "reference result differs from captured input",
            )
            require(
                response(call)["request_id"] == item["request_id"]
                and call["action"]["parameters"]["context"]["capability_id"]
                == item["capability_id"],
                "reference request differs",
            )
            reported = next(
                value
                for value in observed["files"]
                if value["process"] == item["process"]
            )
            require(
                all(reported[field] == value for field, value in item.items())
                and reported["lines"] == len(result["content"].splitlines()),
                "reference report differs from checked content",
            )
        require(
            observed["total_bytes"] == sum(item["bytes"] for item in inputs["files"]),
            "reference byte total differs",
        )
        require(
            verified["captured_invocations"] == len(calls),
            "reference accounting differs",
        )
        return
    require(
        observed["schema"] == f"chio.reference-swarm.{name}-qualification.v1",
        "scenario observation schema differs",
    )
    require(
        observed["worker_image"] == identity["worker_image"],
        "observed worker image differs",
    )
    if name == "authority":
        for field in (
            "scope_widening_denied",
            "peer_authority_denied",
            "changed_intent_denied",
            "continuation_reuse_denied",
            "logical_replay_identical",
            "protected_files_unchanged",
        ):
            require(observed[field] is True, f"authority observation lacks {field}")
        require(
            set(calls) == {"alice", "bob"}
            and all(state == "completed" for state in states.values())
            and verified["captured_invocations"]
            == observed["captured_invocations"]
            == 2,
            "authority outcome inventory differs",
        )
        require(
            observed["runtime_id"] == verified["runtime_id"],
            "authority runtime differs",
        )
        attempts = {
            worker["process"]: worker["attempts"] for worker in run["runner"]["workers"]
        }
        require(
            attempts == {"alice": 2, "bob": 1}
            and observed["crashed_worker_attempts"] == 2,
            "worker crash recovery differs",
        )
    elif name == "filesystem":
        controls = case["positive_controls"]
        require(
            controls["read_succeeded"] is True
            and controls["write_succeeded"] is True
            and controls["probe_sha256"] == identity["binaries"]["probe"],
            "filesystem positive controls differ",
        )
        require(
            set(calls) == {"canary", "forbidden-read", "forbidden-write"},
            "filesystem worker inventory differs",
        )
        for worker, call in calls.items():
            result = response(call)["output"]["value"]["structuredContent"]
            require(
                result == observed["observations"][worker],
                "filesystem result substituted",
            )
            if worker != "canary":
                require(
                    result == {"effect": "refused", "os_errno": 13},
                    "forbidden filesystem effect was not refused",
                )
            else:
                require(result["effect"] == "succeeded", "filesystem canary failed")
        require(
            verified["captured_invocations"] == 3
            and observed["protected_file_unchanged"] is True
            and observed["secret_not_returned"] is True,
            "filesystem external observation failed",
        )
        require(
            observed["cli_sha256"] == identity["binaries"]["chio"]
            and observed["probe_sha256"] == identity["binaries"]["probe"],
            "filesystem binaries differ",
        )
    elif name == "network":
        require(
            set(calls) == {"canary", "network"}
            and states
            == {"canary": "completed", "network": "outcome_unknown_after_dispatch"},
            "network outcomes differ",
        )
        call = signed_response(calls["network"])
        launch = run["confinement"][observed["native_launch_receipt_id"]]
        require(
            call["id"] == observed["caller_receipt_id"]
            and call["decision"]["verdict"] == "incomplete"
            and response(calls["network"])["verdict"]
            == observed["caller_verdict"]
            == "deny",
            "network interruption receipt differs",
        )
        require(
            call["metadata"]["native_launch"]["receipt_id"]
            == launch["enforcement"]["id"],
            "network launch differs",
        )
        require(
            launch["terminal"]["id"] == observed["terminal_receipt_id"]
            and launch["terminal"]["metadata"]["cage_receipt"]["enforcement_record"][
                "exit"
            ]["signal"]
            == observed["exit_signal"]
            == 31,
            "network terminal signal differs",
        )
        require(
            observed["positive_control_connected"] is True
            and observed["confined_connection_absent"] is True,
            "network external observation failed",
        )
        require(verified["captured_invocations"] == 2, "network accounting differs")
    elif name == "revocation":
        require(
            set(calls) == {"canary", "revoked"}
            and states == {"canary": "completed", "revoked": None},
            "revocation outcomes differ",
        )
        call = signed_response(calls["revoked"])
        revoked = observed["issued_capability_revoked"]
        require(
            call["id"] == observed["caller_receipt_id"]
            and revoked["capability_id"] == call["capability_id"]
            and revoked["process"] == "revoked"
            and revoked["capability_revoked"] is True,
            "revocation identity differs",
        )
        require(
            response(calls["revoked"])["verdict"] == "deny"
            and response(calls["revoked"])["output"] is None
            and verified["captured_invocations"] == 1,
            "revoked call spent an invocation",
        )
        for field in (
            "revocation_survived_host_reopen",
            "unspent_planned_call_denied",
            "protected_files_unchanged",
            "secret_not_returned",
        ):
            require(observed[field] is True, f"revocation observation lacks {field}")
    elif name == "host-crash":
        require(
            set(calls) == {"canary", "writer"}
            and states
            == {"canary": "completed", "writer": "outcome_unknown_after_dispatch"},
            "host-crash outcomes differ",
        )
        writer = calls["writer"]["action"]["parameters"]
        require(
            signed_response(calls["writer"])["id"] == observed["caller_receipt_id"]
            and writer["response"]["request_id"] == observed["request_id"],
            "host-crash caller identity differs",
        )
        require(
            writer["operation"]["dispatch_commit"]
            == observed["retained_dispatch_commit"],
            "host-crash retained dispatch differs",
        )
        require(
            writer["operation"]["binding"]["operation_id"] == observed["operation_id"]
            and observed["state"] == states["writer"],
            "host-crash original operation differs",
        )
        attempts = {
            worker["process"]: worker["attempts"] for worker in run["runner"]["workers"]
        }
        require(
            attempts == {"canary": 1, "writer": 2}
            and observed["recovered_worker_attempts"] == 2,
            "host-crash worker recovery differs",
        )
        require(
            verified["captured_invocations"] == 2
            and observed["aggregate_projection"] == [[2, 0, 2]]
            and observed["protected_effect_count"] == 1
            and observed["confined_targets_terminated_on_host_death"] == 2
            and observed["original_request_preserved"] is True,
            "host-crash external observation differs",
        )
    elif name == "budget":
        require(
            set(calls) == {"alice", "bob", "carol", "dave"}
            and verified["graphs"] == observed["independent_graphs"] == 2
            and observed["competing_workers"] == 4,
            "budget task graph inventory differs",
        )
        denied = {
            worker
            for worker, state in states.items()
            if state == "compensated_before_dispatch"
        }
        uncertain = {
            worker
            for worker, state in states.items()
            if state == "outcome_unknown_after_dispatch"
        }
        require(
            len(denied) == len(uncertain) == 2 and denied | uncertain == set(calls),
            "budget outcome inventory differs",
        )
        require(
            denied == set(observed["quota_denial_workers"])
            and uncertain == set(observed["uncertain_effect_workers"]),
            "budget observed workers differ",
        )
        require(
            verified["captured_invocations"]
            == run["aggregate"]["max_invocations"]
            == observed["family_max_invocations"]
            == observed["protected_effect_count"]
            == 2
            and observed["aggregate_projection"] == [[2, 0, 2]],
            "budget accounting differs",
        )
        require(
            observed["overlap_observed"] is True
            and observed["confined_targets_terminated_on_host_death"] == 4,
            "budget external contention or death observation missing",
        )
        attempts = {
            worker["process"]: worker["attempts"] for worker in run["runner"]["workers"]
        }
        require(
            all(
                attempts[worker] == (2 if worker in uncertain else 1)
                for worker in calls
            ),
            "budget worker recovery differs",
        )


def verify_bundle(chio, artifact, trusted_pins):
    pins = read(trusted_pins, 1024 * 1024)
    require(pins["schema"] == SCHEMA + ".pins", "unsupported operator pins")
    require(
        digest(artifact) == pins["bundle_sha256"],
        "bundle differs from independently retained capture digest",
    )
    bundle = read(artifact)
    require(
        bundle["schema"] == SCHEMA
        and set(bundle["scenarios"]) == set(pins["scenarios"]) == set(SCENARIOS),
        "matrix scenario inventory differs",
    )
    require(bundle["identity"] == pins["identity"], "matrix execution identity differs")
    reports = {}
    with tempfile.TemporaryDirectory(prefix="chio-matrix-verify-") as temporary:
        root = Path(temporary)
        for name in SCENARIOS:
            case, pin = bundle["scenarios"][name], pins["scenarios"][name]
            folder = root / name
            folder.mkdir(mode=0o700)
            key = folder / "kernel.pub"
            key.write_text(pin["kernel_public_key"])
            outcome = folder / "outcomes.json"
            write(outcome, case["outcomes"])
            args = ["--trusted-kernel-pubkey", key, "--runtime-id", pin["runtime_id"]]
            for server, public_key in sorted(pin["policy_signers"].items()):
                args.extend(
                    ["--trusted-launch-policy-signer", server + "=" + public_key]
                )
            verified = invoke(
                chio, "process", "verify-outcomes", "--artifact", outcome, *args
            )
            verify_observations(name, case, verified, bundle["identity"])
            if name in ("reference", "filesystem", "authority"):
                completed = folder / "completed.json"
                write(completed, case["completed_run"])
                joined = invoke(
                    chio, "process", "verify-run", "--artifact", completed, *args
                )
                require(
                    joined["runtime_id"] == verified["runtime_id"]
                    and set(joined["verified_workers"])
                    == set(verified["observed_operations"]),
                    "completed run differs from outcomes",
                )
                if verified["artifact_schema"] == "chio.process.worker-outcomes.v3":
                    require(
                        {"execution_nonces", "receipt_log_inclusion"} <= set(joined["checks"]),
                        "completed run omits verified nonce custody or receipt-log inclusion",
                    )
                completed_calls = case["completed_run"]["action"]["parameters"][
                    "results"
                ]
                require(
                    all(
                        completed_calls[worker]["response"] == response(call)
                        for worker, call in case["outcomes"]["action"]["parameters"][
                            "calls"
                        ].items()
                    ),
                    "completed run substituted worker responses",
                )
            if name == "authority":
                denials = case["denials"]
                require(
                    set(denials)
                    == {
                        f"{worker}-{index}"
                        for worker in ("alice", "bob")
                        for index in range(4)
                    },
                    "authority denial inventory differs",
                )
                verify_authority_probes(case)
                caps = case["outcomes"]["action"]["parameters"]["bootstrap"]["action"][
                    "parameters"
                ]["capabilities"]
                for index, (label, denied) in enumerate(sorted(denials.items())):
                    worker = label.split("-")[0]
                    require(
                        denied["context"]
                        == {
                            "runtime_id": pin["runtime_id"],
                            "process_id": worker,
                            "capability_id": caps[worker]["id"],
                        },
                        "denial caller differs",
                    )
                    command = []
                    for field in ("request", "context", "response"):
                        path = folder / f"denial-{index}-{field}.json"
                        write(path, denied[field])
                        command.extend(["--" + field, path])
                    invoke(
                        chio,
                        "--json",
                        "receipt",
                        "verify-process-response",
                        *command,
                        "--trusted-kernel-pubkey",
                        key,
                    )
                    require(
                        denied["response"]["verdict"] == "deny"
                        and denied["response"]["output"] is None,
                        "authority probe was not denied",
                    )
            if name in ("host-crash", "budget"):
                originals = case["original_launches"]
                require(
                    set(originals)
                    == set(pin["original_launches"])
                    == set(pin["policy_signers"]),
                    "original launch inventory differs",
                )
                require(
                    case["observation"]["original_native_launches"]
                    == pin["original_launches"],
                    "original launch observation differs from operator pins",
                )
                require(
                    len(
                        {
                            item["process_id"]
                            for item in pin["original_launches"].values()
                        }
                    )
                    == len(originals),
                    "original target is attributed to multiple launches",
                )
                launches = case["outcomes"]["action"]["parameters"][
                    "confinement"
                ].values()
                for index, (server, original) in enumerate(sorted(originals.items())):
                    expected = pin["original_launches"][server]
                    require(
                        expected["policy_signer"] == pin["policy_signers"][server]
                        and expected["target_sha256"]
                        == bundle["identity"]["binaries"]["probe"],
                        "original launch operator identity differs",
                    )
                    require(
                        any(
                            launch["enforcement"]["tool_server"] == server
                            and launch["signed_policy"] == original["policy"]
                            for launch in launches
                        ),
                        "original policy differs from response-bound host route",
                    )
                    policy, receipt = (
                        folder / f"original-{index}-policy.json",
                        folder / f"original-{index}-receipt.json",
                    )
                    policy.write_text(original["policy"])
                    write(receipt, original["enforcement"])
                    require(
                        digest(policy) == expected["policy_sha256"],
                        "original policy bytes differ",
                    )
                    start = invoke(
                        chio,
                        "receipt",
                        "verify-native-start",
                        "--signed-policy",
                        policy,
                        "--enforcement",
                        receipt,
                        "--server-id",
                        server,
                        "--trusted-policy-signer",
                        expected["policy_signer"],
                        "--expected-receipt-id",
                        expected["receipt_id"],
                        "--expected-target-sha256",
                        expected["target_sha256"],
                    )
                    require(
                        start["process_id"] == expected["process_id"]
                        and start["trace_session_digest"]
                        == expected["trace_session_digest"],
                        "original launch differs from pinned process observation",
                    )
            reports[name] = verified
    joined_checks = {"execution_nonces", "receipt_log_inclusion"}
    checked = sorted(
        check for check in joined_checks
        if all(check in report["checks"] for report in reports.values())
    )
    return {
        "schema": SCHEMA + ".verification",
        "scenarios": reports,
        "verifier_sha256": digest(chio),
        "local_matrix_verified": True,
        "m5_acceptance_complete": False,
        "external_observation_authority": "independently retained operator bundle digest",
        "checks": checked,
        "unchecked": [
            "designated_runner_authorization",
            "combined_foundation_qualification",
        ] + sorted(joined_checks - set(checked)),
    }


def verify_negative_cases(chio, artifact, trusted_pins):
    """Repin mutations to test intrinsic signatures and cross-links as well as transport integrity."""
    verify_bundle(chio, artifact, trusted_pins)
    original, original_pins = read(artifact), read(trusted_pins)
    mutations = [
        (
            "reference-capability",
            ["scenarios", "reference", "inputs", "files", 0, "capability_id"],
            "another-capability",
        ),
        (
            "authority-accounting",
            ["scenarios", "authority", "observation", "captured_invocations"],
            99,
        ),
        (
            "filesystem-effect",
            [
                "scenarios",
                "filesystem",
                "observation",
                "observations",
                "forbidden-read",
                "os_errno",
            ],
            0,
        ),
        (
            "network-receipt",
            ["scenarios", "network", "observation", "caller_receipt_id"],
            "another-receipt",
        ),
        (
            "revoked-capability",
            [
                "scenarios",
                "revocation",
                "observation",
                "issued_capability_revoked",
                "capability_id",
            ],
            "another-capability",
        ),
        (
            "host-crash-operation",
            ["scenarios", "host-crash", "observation", "operation_id"],
            "another-operation",
        ),
        (
            "budget-graph-count",
            ["scenarios", "budget", "observation", "independent_graphs"],
            1,
        ),
        (
            "budget-effect-count",
            ["scenarios", "budget", "observation", "protected_effect_count"],
            3,
        ),
        (
            "signed-outcome-edit",
            [
                "scenarios",
                "reference",
                "outcomes",
                "action",
                "parameters",
                "aggregate",
                "captured_invocations",
            ],
            99,
        ),
        (
            "completed-run-substitution",
            ["scenarios", "authority", "completed_run"],
            original["scenarios"]["reference"]["completed_run"],
        ),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix="chio-matrix-mutations-") as temporary:
        root = Path(temporary)

        def reject(name, changed, selected, repin=True):
            candidate, pin_file = root / (name + ".json"), root / (name + "-pins.json")
            write(candidate, changed)
            if repin:
                selected["bundle_sha256"] = digest(candidate)
            write(pin_file, selected)
            try:
                verify_bundle(chio, candidate, pin_file)
            except ValueError as error:
                results.append({"case": name, "rejected": True, "reason": str(error)})
            else:
                raise ValueError(f"matrix verifier accepted {name}")

        for name, path, replacement in mutations:
            changed = copy.deepcopy(original)
            value = changed
            for part in path[:-1]:
                value = value[part]
            value[path[-1]] = replacement
            reject(name, changed, copy.deepcopy(original_pins))
        changed = copy.deepcopy(original)
        denials = changed["scenarios"]["authority"]["denials"]
        denials["alice-0"], denials["alice-1"] = denials["alice-1"], denials["alice-0"]
        reject("authority-denial-order", changed, copy.deepcopy(original_pins))
        changed = copy.deepcopy(original)
        changed["scenarios"]["budget"]["observation"]["overlap_observed"] = False
        reject("capture-digest", changed, copy.deepcopy(original_pins), repin=False)
        reject("contention-observation", changed, copy.deepcopy(original_pins))
        changed = copy.deepcopy(original)
        del changed["scenarios"]["network"]
        reject("missing-scenario", changed, copy.deepcopy(original_pins))
        changed = copy.deepcopy(original)
        first, second = sorted(changed["scenarios"]["budget"]["original_launches"])[:2]
        changed["scenarios"]["budget"]["original_launches"][first]["enforcement"] = (
            changed["scenarios"]["budget"]["original_launches"][second]["enforcement"]
        )
        reject("original-launch-substitution", changed, copy.deepcopy(original_pins))
        selected = copy.deepcopy(original_pins)
        selected["scenarios"]["reference"]["runtime_id"] = "another-runtime"
        reject("runtime-pin", copy.deepcopy(original), selected)
    return {
        "schema": SCHEMA + ".negative-verification",
        "checks": results,
        "all_rejected": True,
        "m5_acceptance_complete": False,
    }
