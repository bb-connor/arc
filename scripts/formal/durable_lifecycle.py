"""Validate the bounded real-port lifecycle fixture, including its signed evidence.

This test key is public. Passing this checker is regression evidence, not a
production attestation or proof that an untrusted artifact actually ran Rust.
"""
import hashlib
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIXTURE_SIGNER = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
SCENARIOS = {"happy", "effect_ack_loss", "receipt_ack_loss"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical_fixture(value):
    """RFC 8785 for this deliberately ASCII/integer-only fixture vocabulary."""
    if isinstance(value, dict):
        for key, child in value.items():
            require(isinstance(key, str) and key.isascii(), "non-ASCII fixture key")
            canonical_fixture(child)
    elif isinstance(value, list):
        for child in value:
            canonical_fixture(child)
    elif isinstance(value, str):
        require(value.isascii(), "non-ASCII fixture string")
    elif type(value) is int:
        require(abs(value) <= 9007199254740991, "unsafe fixture integer")
    else:
        require(value is None or type(value) is bool, "unsupported fixture value")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def signed_receipt(entry, evidence_id):
    require(set(entry) == {"signing_bytes", "signature"}, "unexpected receipt fields")
    raw = bytes.fromhex(entry["signing_bytes"])
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(FIXTURE_SIGNER)).verify(
            bytes.fromhex(entry["signature"]), raw)
    except InvalidSignature as error:
        raise ValueError("invalid receipt signature") from error
    signed = json.loads(raw)
    require(canonical_fixture(signed) == raw, "noncanonical receipt signing bytes")
    outer = signed["body"]
    require(outer["kernel_key"] == FIXTURE_SIGNER, "receipt signer mismatch")
    metadata = outer["metadata"]
    body = metadata["active_defense_body"]
    require(metadata["active_defense_evidence_id"] == evidence_id, "signed evidence id mismatch")
    digest = hashlib.sha256(b"chio:active-defense-receipt:" + body["kind"].replace("_", "-").encode()
                            + b":v1\0" + canonical_fixture(body)).hexdigest()
    require(outer["content_hash"] == digest, "receipt content digest mismatch")
    expected_id = "active_defense_evidence_" + hashlib.sha256(
        b"chio:active-defense-evidence-id:v1\0" + body["kind"].encode() + b"\0" + bytes.fromhex(digest)).hexdigest()
    require(expected_id == evidence_id, "evidence id is not content bound")
    return body, digest


def receipt_transition(record):
    return record.get("effect_transition_id") or record["transition_id"]


def validate_scenario(name, trace, validate_runtime_trace):
    require(set(trace) == {"snapshot", "snapshot_canonical", "committed_snapshots", "events", "commands", "receipts"}, "unexpected scenario fields")
    snapshot, events = trace["snapshot"], trace["events"]
    raw = bytes.fromhex(trace["snapshot_canonical"])
    require(canonical_fixture(snapshot) == raw, "snapshot bytes differ from readback")
    plan, mutations = snapshot["plan"], snapshot["mutations"]
    require(snapshot["state"] == "lifted", "durable scenario is incomplete")
    states = ["planned"] + [m["record"].get("to_state", m["record"].get("final_state"))
                             for m in mutations if m["record_type"] in {"transition", "failed", "final"}]
    validate_runtime_trace(dict(mode=plan["execution"]["mode"], generation=snapshot["generation"],
                                mutations=mutations, states=states))
    require({"active", "rolling_back", "lifted"} <= set(states), "missing lifecycle states")
    require(len(plan["effects"]) == 1 and plan["effects"][0]["kind"] == "throttle_session", "unexpected fixture effect")
    planned = plan["effects"][0]
    expected_effect = {field: planned[field] for field in ["effect_id", "ordinal", "kind", "target", "contribution_hash", "observed_base_version_hash"]}
    expected_response = {field: plan[field] for field in ["action_id", "plan_hash", "trigger_finding_id", "trigger_finding_hash", "trigger_finding_receipt_id", "affected_set_hash"]}
    expected_response.update(plan_expires_at_unix_ms=plan["expires_at_unix_ms"],
                             policy={field: plan[field] for field in ["policy_hash", "policy_version"]})
    commands = {}
    for command in trace["commands"]:
        require(set(command) == {"request", "result"}, "unexpected native command fields")
        req, result = command["request"], command["result"]
        require(set(req) == {"tenant_id", "action_id", "plan_hash", "effect_id", "effect_kind", "target",
                             "plan_expires_at_unix_ms", "operation", "idempotency_key", "expected_version_hash",
                             "scheduler_lease_owner_id", "scheduler_fencing_token", "canonical_contribution", "contribution_hash"}
                and set(result) == {"effect_id", "resulting_version_hash", "applied"}, "unexpected native request/result fields")
        require(req["effect_kind"] == planned["kind"] and req["plan_expires_at_unix_ms"] == plan["expires_at_unix_ms"],
                "native command kind or expiry mismatch")
        # These fixtures exercise first-attempt apply/removal, including replay
        # of the same command after lost acknowledgement, never a new attempt.
        identity = {field: req[field] for field in ["tenant_id", "action_id", "plan_hash", "effect_id", "operation"]}
        identity["attempt"] = 0
        expected_id = "response_effect_command:" + hashlib.sha256(
            b"chio.response-effect-command.v1\0" + canonical_fixture(identity)).hexdigest()
        require(req["idempotency_key"] == expected_id, "native command identity mismatch")
        key = req["effect_id"], req["operation"]
        require(key not in commands, "duplicate native command")
        require(req["tenant_id"] == plan["tenant_id"] and req["action_id"] == plan["action_id"]
                and req["plan_hash"] == plan["plan_hash"] and req["effect_id"] == planned["effect_id"]
                and req["contribution_hash"] == planned["contribution_hash"] and req["target"] == planned["target"],
                "native command substitution")
        require(result["effect_id"] == req["effect_id"] and result["applied"] == (req["operation"] == "apply"), "native result mismatch")
        contribution = bytes(req["canonical_contribution"])
        require(contribution == bytes(planned["canonical_contribution"])
                and hashlib.sha256(contribution).digest() == bytes(req["contribution_hash"]), "native contribution mismatch")
        commands[key] = command
    require(set(commands) == {(planned["effect_id"], "apply"), (planned["effect_id"], "remove")}, "missing native command")
    require(commands[planned["effect_id"], "apply"]["request"]["expected_version_hash"] == planned["observed_base_version_hash"]
            and commands[planned["effect_id"], "remove"]["request"]["expected_version_hash"] == commands[planned["effect_id"], "apply"]["result"]["resulting_version_hash"], "native command version chain mismatch")
    receipts = {key: signed_receipt(value, key) for key, value in trace["receipts"].items()}
    transitions = {receipt_transition(m["record"]): m for m in mutations}
    require(len(transitions) == len(mutations), "duplicate mutation transition")
    committed, persisted, external, restarts = {}, {}, {}, []
    current_state = "planned"
    for index, event in enumerate(events):
        boundary = event["boundary"]
        fields = {
            "restart": {"boundary"},
            "response_commit": {"boundary", "tenant_id", "action_id", "first_generation", "generation", "state", "body_hash"},
            "effect_commit": {"boundary", "backend", "tenant_id", "action_id", "effect_id", "idempotency_key", "plan_hash", "operation", "resulting_version_hash", "applied"},
            "receipt_persisted": {"boundary", "tenant_id", "transition_id", "evidence_id", "body_hash"},
        }
        require(boundary in fields and set(event) == fields[boundary], "unexpected event fields")
        if boundary == "restart":
            restarts.append(index)
            continue
        require(event["tenant_id"] == plan["tenant_id"], "cross-tenant event")
        if boundary == "response_commit":
            first, generation = event["first_generation"], event["generation"]
            require(type(first) is int and type(generation) is int and first == len(committed)
                    and first <= generation < len(mutations), "missing or reordered commit")
            require((first == 0 and generation == 1) or (first > 0 and first == generation),
                    "unexpected atomic commit range")
            require(event["action_id"] == plan["action_id"], "cross-action commit")
            observed_raw = bytes.fromhex(trace["committed_snapshots"][str(generation)])
            observed_snapshot = json.loads(observed_raw)
            require(canonical_fixture(observed_snapshot) == observed_raw
                    and hashlib.sha256(observed_raw).hexdigest() == event["body_hash"], "intermediate commit hash mismatch")
            require(set(observed_snapshot) == set(snapshot)
                    and observed_snapshot["generation"] == generation
                    and observed_snapshot["mutations"] == mutations[:generation+1], "committed mutation prefix mismatch")
            for field in ["schema_version", "plan", "execution_dispatch", "dispatch_authorization_hash"]:
                require(observed_snapshot[field] == snapshot[field], f"committed {field} substitution")
            require(observed_snapshot["state"] == event["state"], "committed snapshot state mismatch")
            for covered in range(first, generation + 1):
                mutation = mutations[covered]
                kind, record = mutation["record_type"], mutation["record"]
                if kind in {"transition", "failed", "final"}:
                    current_state = record.get("to_state", record.get("final_state"))
                if kind == "effect_applied" or (kind == "rollback" and record["outcome"]["outcome"] == "restored"):
                    operation = "apply" if kind == "effect_applied" else "remove"
                    key = record["effect_id"], operation
                    require(key in external, "effect acknowledged before native commit")
                    result = commands[key]["result"]
                    observed = record if operation == "apply" else record["outcome"]
                    require(result["resulting_version_hash"] == observed["resulting_version_hash"], "effect acknowledgement version mismatch")
                committed[covered] = (index, event)
            require(event["state"] == current_state, "committed state mismatch")
        elif boundary == "effect_commit":
            key = event["effect_id"], event["operation"]
            require(key in commands and key not in external, "missing or duplicate native journal event")
            request, result = commands[key]["request"], commands[key]["result"]
            require(event["backend"] == "session_throttle", "unexpected backend")
            for field in ["tenant_id", "action_id", "plan_hash", "effect_id", "operation", "idempotency_key"]:
                expected = bytes(request[field]).hex() if field == "plan_hash" else request[field]
                require(event[field] == expected, f"native journal {field} mismatch")
            for field in ["resulting_version_hash", "applied"]:
                expected = bytes(result[field]).hex() if field == "resulting_version_hash" else result[field]
                require(event[field] == expected, f"native result {field} mismatch")
            candidates = [m["record"] for m in mutations[:len(committed)]
                          if m["record"].get("effect_id") == key[0] and (
                              m["record_type"] == "effect_requested" if key[1] == "apply" else
                              m["record_type"] == "rollback" and m["record"]["outcome"]["outcome"] == "requested")]
            require(len(candidates) == 1 and receipt_transition(candidates[0]) in persisted, "native effect before durable signed request")
            for field in ["scheduler_fencing_token", "scheduler_lease_owner_id"]:
                require(request[field] == candidates[0][field], f"native command {field} authority mismatch")
            external[key] = index
        elif boundary == "receipt_persisted":
            transition = event["transition_id"]
            require(transition in transitions and transition not in persisted, "unknown or duplicate receipt transition")
            mutation = transitions[transition]
            record, kind = mutation["record"], mutation["record_type"]
            generation = record["generation"]
            require(generation in committed, "receipt before response commit")
            require(generation == len(persisted), "missing or reordered signed receipt")
            require(event["evidence_id"] in receipts, "missing durable signed receipt")
            signed, digest = receipts[event["evidence_id"]]
            body = signed["body"]
            require(event["body_hash"] == digest, "receipt event digest mismatch")
            header, response = body["header"], body["response"]
            require(header["transition_id"] == transition and header["tenant_id"] == plan["tenant_id"]
                    and header["occurred_at_unix_ms"] == record["occurred_at_unix_ms"]
                    and record["prior_receipt_id"] in header["prior_receipt_ids"], "signed mutation header mismatch")
            require(response == expected_response, "signed response substitution")
            if kind in {"effect_requested", "effect_applied", "rollback"}:
                require(signed["kind"] == "effect_transition" and body["effect"] == expected_effect
                        and body["generation"] == record["effect_generation"], "signed effect substitution")
                for field in ["scheduler_fencing_token", "scheduler_lease_owner_id"]:
                    require(body[field] == record[field], f"signed effect {field} mismatch")
                outcome = "requested" if kind == "effect_requested" else "applied" if kind == "effect_applied" else {
                    "requested": "rollback_requested", "restored": "restored"}[record["outcome"]["outcome"]]
                require(body["outcome"]["state"] == outcome, "signed effect outcome mismatch")
                if outcome in {"applied", "restored"}:
                    observed = record if outcome == "applied" else record["outcome"]
                    require(body["outcome"]["resulting_version_hash"] == observed["resulting_version_hash"], "signed effect version mismatch")
            elif kind == "requested":
                require(signed["kind"] == "response_plan" and body["effects"] == [expected_effect], "missing signed plan")
            elif signed["kind"] in {"response_completion", "lift_rollback_completion"}:
                require(body["response_generation"] == generation and body["final_state"] == committed[generation][1]["state"]
                        and bytes(body["response_body_hash"]).hex() == committed[generation][1]["body_hash"], "signed completion mismatch")
            else:
                require(signed["kind"] == "response_state_transition" and body["generation"] == generation
                        and body["from_state"] == record["from_state"] and body["to_state"] == record["to_state"], "signed state mismatch")
            persisted[transition] = (index, event["evidence_id"])
        else:
            raise ValueError("unexpected durable trace boundary")
    require(len(committed) == len(mutations) == len(persisted) == len(receipts), "incomplete durable generations")
    require(set(external) == set(commands), "incomplete external journal linkage")
    require(set(trace["committed_snapshots"]) == {str(e["generation"]) for e in events if e["boundary"] == "response_commit"},
            "incomplete committed snapshot inventory")
    require(trace["committed_snapshots"][str(snapshot["generation"])] == trace["snapshot_canonical"], "final reopen snapshot mismatch")
    require(committed[len(mutations)-1][1]["body_hash"] == hashlib.sha256(raw).hexdigest(), "final committed body differs from reopened store")
    require(len(restarts) == 2 and restarts[1] > max(p[0] for p in persisted.values()), "missing final restart readback")
    first_effect = external[(planned["effect_id"], "apply")]
    applied = next(m["record"] for m in mutations if m["record_type"] == "effect_applied")
    if name == "effect_ack_loss":
        require(first_effect < restarts[0] < committed[applied["generation"]][0], "effect lost acknowledgement was not recovered across restart")
    elif name == "receipt_ack_loss":
        require(persisted[mutations[0]["record"]["transition_id"]][0] < restarts[0] < first_effect, "receipt lost acknowledgement was not recovered across restart")
    else:
        require(committed[applied["generation"]][0] < restarts[0], "happy restart precedes activation")
    return dict(generations=len(committed), signed_receipts=len(receipts), native_commands=len(commands), restarts=len(restarts))


def validate_durable_trace(document, validate_runtime_trace):
    require(set(document) == {"schema", "scope", "scenarios"}, "unexpected durable trace fields")
    require(document.get("schema") == "chio.response-durable-trace.v1", "unsupported durable trace schema")
    require(set(document["scenarios"]) == SCENARIOS, "incomplete durable scenario inventory")
    try:
        return {name: validate_scenario(name, trace, validate_runtime_trace)
                for name, trace in document["scenarios"].items()}
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError(f"malformed durable trace: {error}") from error
