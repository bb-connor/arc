"""Independent verification of mutual release after a retained unknown incident."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import incident
import protocol as p

SCHEMA = "chio.unknown-payment-release.v1"
RECEIPT = "chio.unknown-payment-release-receipt.v1"


def policy(peers):
    return {"receiverKey": peers["provider"], "counterpartyKey": peers["buyer"],
            "rail": "finding-operator-ledger", "currency": "TST"}


def preimage(body, role):
    raw = p.canonical(body)
    p.require(len(raw) <= 256 * 1024, "release terms exceed profile")
    return SCHEMA.encode() + b"\0" + role.encode() + b"\0" + raw


def signature(body, role, value, pin):
    try:
        Ed25519PublicKey.from_public_bytes(p.hex_bytes(pin)).verify(p.hex_bytes(value, 64), preimage(body, role))
    except Exception as error:
        raise p.ProtocolError("release role signature does not verify") from error


def proposal(work, artifact, value, peers, at):
    operation_id = incident.verify(work, artifact, peers)
    p.fields(value, ("body", "receiverSignature"))
    body = p.fields(value["body"], ("schema", "policyDigest", "operationId", "terminalProjectionDigest", "incident",
                                  "capability", "authorizedJournal", "issuedAtUnixMs", "expiresAtUnixMs"))
    native = artifact["projection"]["body"]
    terminal = native["terminal_operation"]
    binding = terminal["binding"]
    p.require(body["schema"] == SCHEMA and body["policyDigest"] == p.digest(policy(peers))
              and body["operationId"] == operation_id and p.same(body["incident"], artifact["projection"])
              and body["terminalProjectionDigest"] == terminal["terminal_replay"]["incident"]["projection_digest"]
              and p.same(body["capability"], work["acceptance"]["ask"]["body"]["tokenOffer"]),
              "release changes local policy, work authority or incident")
    journal = p.fields(body["authorizedJournal"], ("operationId", "journalVersion", "requestNamespaceDigest", "requestId",
        "capabilityId", "grantIndex", "holdId", "rail", "railMode", "authorizationId", "amountUnits", "currency", "state", "createdAtUnixMs"))
    expected = {"operationId": operation_id, "journalVersion": 2, "requestNamespaceDigest": binding["request_namespace_digest"],
                "requestId": binding["request_id"], "capabilityId": binding["capability_id"], "grantIndex": 0,
                "holdId": "admission-budget:" + operation_id + ":0", "rail": policy(peers)["rail"],
                "railMode": "reversible_hold", "amountUnits": 100, "currency": "TST", "state": "authorized"}
    p.require(p.same({k: journal[k] for k in expected}, expected), "release changes original monetary hold")
    incident.identifier(journal["authorizationId"])
    p.integer(journal["createdAtUnixMs"], 1, native["context"]["trusted_time_unix_ms"])
    issued = p.integer(body["issuedAtUnixMs"], native["context"]["trusted_time_unix_ms"])
    expires = p.integer(body["expiresAtUnixMs"], issued + 1, min(p.MAX_INT, issued + 86_400_000))
    p.integer(at, issued, expires - 1)
    signature(body, "receiver", value["receiverSignature"], peers["provider"])
    return body


def consent(work, artifact, value, peers, at):
    p.fields(value, ("proposal", "counterpartySignature"))
    body = proposal(work, artifact, value["proposal"], peers, at)
    signature(body, "counterparty", value["counterpartySignature"], peers["buyer"])
    return body


def countersign(work, artifact, value, peers, identity, at):
    body = proposal(work, artifact, value, peers, at)
    result = {"proposal": value, "counterpartySignature": identity.sign(preimage(body, "counterparty")).hex()}
    consent(work, artifact, result, peers, at)
    return result


def fence_successor(old, new):
    incident.fence(old)
    incident.fence(new)
    p.require(old["store_uuid"] == new["store_uuid"] and
              (new["owner_epoch"] > old["owner_epoch"] or p.same(old, new)), "release regresses serving authority")


def verify(public, peers):
    p.fields(public, ("request", "incident", "consent", "receipt"))
    body = p.envelope(public["receipt"], peers["provider"])
    p.fields(body, ("schema", "record"))
    p.require(body["schema"] == RECEIPT, "not a completed release receipt")
    record = p.fields(body["record"], ("policy", "request", "operation", "acceptedAtUnixMs", "acceptedFence",
                                     "transactionId", "completedAtUnixMs", "completedFence"))
    accepted = p.integer(record["acceptedAtUnixMs"], 1)
    p.require(p.same(record["policy"], policy(peers)) and p.same(record["request"], public["consent"]),
              "release receipt changes locally selected policy or retained consent")
    terms = consent(public["request"], public["incident"], public["consent"], peers, accepted)
    native = public["incident"]["projection"]["body"]
    p.require(p.same(record["operation"], native["terminal_operation"]), "release receipt rewrites historical unknown")
    fence_successor(native["context"]["store_fence"], record["acceptedFence"])
    p.integer(record["completedAtUnixMs"], accepted)
    fence_successor(record["acceptedFence"], record["completedFence"])
    incident.identifier(record["transactionId"])
    return terms["operationId"]
