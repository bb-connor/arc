"""Independent checks for the native unknown projection in the paid-review profile.

An incident is historical evidence. It authorizes neither a retry nor a release.
"""
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import protocol as p
import review

SCHEMA = "chio.example.review-incident.v1"
NATIVE = "chio.signed-admission-terminal-projection.v1"
UNKNOWN = "outcome_unknown_after_dispatch"


def domain_digest(domain, body):
    return hashlib.sha256(domain.encode() + b"\0" + p.canonical(body)).hexdigest()


def encoded(value):
    p.require(type(value) is str and len(value) <= 256 * 1024, "incident component exceeds profile")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise p.ProtocolError("invalid incident base64") from error
    result = p.load_json(raw)
    p.require(base64.b64encode(raw).decode() == value and p.canonical(result) == raw,
              "incident component is not canonical")
    return result


def identifier(value):
    p.require(type(value) is str and 1 <= len(value.encode()) <= 256
              and all(32 <= ord(c) < 127 for c in value), "invalid incident identifier")


def fence(value):
    p.fields(value, ("store_uuid", "lease_id", "owner_epoch"))
    identifier(value["store_uuid"])
    identifier(value["lease_id"])
    p.integer(value["owner_epoch"], 1)


def verify(work, value, peers):
    agreement = review.request(work, peers)
    accepted = work["acceptance"]
    p.fields(value, ("schema", "agreementSha256", "acceptedBidSha256", "projection"))
    p.require(value["schema"] == SCHEMA and value["agreementSha256"] == p.digest(agreement)
              and value["acceptedBidSha256"] == p.digest(accepted["accepted"]), "incident changes agreement")
    envelope = p.fields(value["projection"], ("body", "signature"))
    body = p.fields(envelope["body"], ("schema", "signer_key", "context", "source_operation", "terminal_operation",
                                      "projection_json", "manifest_json", "records", "authorization_consumption", "observer"))
    p.require(body["schema"] == NATIVE and body["signer_key"] == peers["provider"], "incident changes provider")
    try:
        Ed25519PublicKey.from_public_bytes(p.hex_bytes(peers["provider"])).verify(
            p.hex_bytes(envelope["signature"], 64), NATIVE.encode() + b"\0" + p.canonical(body))
    except Exception as error:
        raise p.ProtocolError("native incident signature does not verify") from error
    source = p.fields(body["source_operation"], ("schema", "binding", "attachments", "state", "dispatch_state",
                                               "dispatch_commit", "coordinator_lease_epoch", "version", "last_error", "terminal_replay"))
    p.require(source["schema"] == "chio.admission-operation.v1" and source["state"] == "dispatch_committed"
              and source["dispatch_state"] == "committed" and source["last_error"] is None
              and source["terminal_replay"] is None, "incident has no supported dispatch predecessor")
    version = p.integer(source["version"], 1, p.MAX_INT - 1)
    epoch = p.integer(source["coordinator_lease_epoch"], 1)
    binding = p.fields(source["binding"], ("kind", "operation_id", "coordinator_authority_id", "authenticated_tenant_id",
                                          "request_namespace_digest", "request_id", "capability_id", "authorization_capability_hash",
                                          "request_binding", "policy_hash", "effect_class"))
    for name in ("operation_id", "request_namespace_digest", "authorization_capability_hash", "policy_hash"):
        p.hex_bytes(binding[name])
    for name in ("coordinator_authority_id", "request_id", "capability_id"):
        identifier(binding[name])
    cap = accepted["ask"]["body"]["tokenOffer"]
    p.require(binding["kind"] == "tool_dispatch" and binding["effect_class"] == "monetary"
              and binding["authenticated_tenant_id"] == "local-system" and binding["capability_id"] == cap["id"]
              and binding["authorization_capability_hash"] == p.digest(cap), "incident changes paid authority")
    request = p.fields(binding["request_binding"], ("immutable_request_hash", "action_parameter_hash", "participant_requirements", "request_binding_hash"))
    p.hex_bytes(request["immutable_request_hash"])
    requirements = {name: name in ("broker_attempt", "budget_capture", "payment") for name in (
        "broker_attempt", "budget_capture", "approval", "execution_nonce", "outcome_eligibility", "payment",
        "authorization_consumption", "observation_attempt_zero", "obligation")}
    p.require(p.same(request["participant_requirements"], requirements) and request["action_parameter_hash"] == p.digest(work),
              "incident changes work or participants")
    p.require(request["request_binding_hash"] == domain_digest("chio.admission-request-binding.v1",
              {k: v for k, v in request.items() if k != "request_binding_hash"}), "request binding hash mismatch")
    p.require(binding["request_namespace_digest"] == domain_digest("chio.admission-request-namespace.v1",
              {k: binding[k] for k in ("authenticated_tenant_id", "coordinator_authority_id")}), "request namespace mismatch")
    operation_body = {k: v for k, v in binding.items() if k not in ("operation_id", "request_binding", "authenticated_tenant_id")}
    operation_body["request_binding_hash"] = request["request_binding_hash"]
    operation_id = domain_digest("chio.admission-operation.v1", operation_body)
    p.require(binding["operation_id"] == operation_id, "incident operation id mismatch")
    commit = p.fields(source["dispatch_commit"], ("committed_version", "coordinator_lease_id", "coordinator_lease_epoch", "store_fence", "provider_attempt"))
    p.integer(commit["committed_version"], 1, version)
    p.integer(commit["coordinator_lease_epoch"], epoch, epoch)
    identifier(commit["coordinator_lease_id"])
    fence(commit["store_fence"])
    attempt = {"attempt_id": "attempt:" + operation_id, "operation_id": operation_id,
               "transport_id": "kernel-tool-server:" + p.SERVER, "transport_key_epoch": 1}
    p.require(p.same(commit["provider_attempt"], attempt) and commit["coordinator_lease_epoch"] == epoch,
              "incident changes dispatch attempt")
    p.require(p.same(source["attachments"], [{"BrokerAttempt": attempt},
              {"BudgetHoldId": "admission-budget:" + operation_id + ":0"}, {"PaymentParticipantId": operation_id}]),
              "incident changes retained participants or attaches a tool outcome")
    context = p.fields(body["context"], ("operation_id", "request_id", "expected_operation_version", "trusted_time_unix_ms",
                                         "coordinator_lease_id", "coordinator_lease_epoch", "store_fence"))
    p.integer(context["trusted_time_unix_ms"], 1)
    p.integer(context["expected_operation_version"], version, version)
    p.integer(context["coordinator_lease_epoch"], epoch, epoch)
    fence(context["store_fence"])
    old, current = commit["store_fence"], context["store_fence"]
    p.require(old["store_uuid"] == current["store_uuid"] == binding["coordinator_authority_id"]
              and (current["owner_epoch"] > old["owner_epoch"] or p.same(old, current)), "incident regresses store fence")
    p.require(context["operation_id"] == operation_id and context["request_id"] == binding["request_id"]
              and context["expected_operation_version"] == version and context["coordinator_lease_epoch"] == epoch
              and context["coordinator_lease_id"] == commit["coordinator_lease_id"], "incident changes recovery context")
    replay = {"operation_id": operation_id, "operation_version": version, "request_binding_hash": request["request_binding_hash"],
              "dispatch_commit": commit, "context": context}
    incident_id = domain_digest("chio.outcome-unknown-after-dispatch.v1", replay)
    exact = {k: v for k, v in context.items() if k != "expected_operation_version"}
    exact.update(source_operation_version=version, projected_operation_version=version + 1, projected_state=UNKNOWN,
                 request_binding_hash=request["request_binding_hash"], retained_dispatch_commit=commit)
    incident = {"binding": exact, "record_id": incident_id, "record_digest": incident_id}
    projection = {"terminal": UNKNOWN, "context": context, "incident": incident}
    manifest = {"schema": "chio.admission-projection-manifest.v1", "projection_body_digest": p.digest(projection),
                "records": [{"kind": "incident", "record_id": incident_id, "record_digest": p.digest(incident)}]}
    p.require(p.same(encoded(body["projection_json"]), projection) and p.same(encoded(body["manifest_json"]), manifest),
              "incident projection does not reproduce this dispatch")
    record = {**manifest["records"][0], "canonical_json": base64.b64encode(p.canonical(incident)).decode()}
    p.require(p.same(body["records"], [record]) and body["authorization_consumption"] is None and body["observer"] is None,
              "incident carries incompatible records")
    terminal = {**source, "state": UNKNOWN, "dispatch_state": "terminal", "version": version + 1,
                "terminal_replay": {"incident": {"incident_id": incident_id, "projection_digest": p.digest(manifest)}}}
    p.require(p.same(body["terminal_operation"], terminal), "incident rewrites its terminal operation")
    return operation_id
