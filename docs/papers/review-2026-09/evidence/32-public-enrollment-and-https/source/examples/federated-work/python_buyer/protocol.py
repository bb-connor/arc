"""Public artifact checks for the bounded Chio checked-review agreement.

This implementation uses JSON objects and standard cryptographic libraries.
It does not load Chio's Rust implementation or invoke a verifier subprocess.
"""
from __future__ import annotations

import hashlib
import json
import re

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = "chio.example.security-review-agreement.v3"
CREDIT = "provider-local-credit-checked-or-zero-v1"
SERVER = "security-review-provider"
LISTING = "security-review-v1"
CHECKER = "openapi-explicit-auth-v1"
PRICE = {"currency": "TST", "units": 100}
REJECTION_REASON = "returned output failed the agreed zero-charge check"
REJECTION_CONTENT = b"chio.output-guard-rejection.redacted.v1\0"
MAX_JSON = 1024 * 1024
MAX_INT = 2**53 - 1


class ProtocolError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ProtocolError(message)


def fields(value, required, optional=()):
    require(type(value) is dict, "expected an object")
    require(set(required) <= value.keys() <= set(required) | set(optional),
            "object fields differ from the supported profile")
    return value


def integer(value, low=0, high=MAX_INT):
    require(type(value) is int and low <= value <= high, "integer outside profile")
    return value


def hex_bytes(value, size=32, prefix=""):
    require(type(value) is str and re.fullmatch(re.escape(prefix) + "[0-9a-f]{" + str(size * 2) + "}", value),
            "noncanonical hexadecimal value")
    return bytes.fromhex(value[len(prefix):])


def canonical(value):
    try:
        encoded = rfc8785.dumps(value)
    except (ValueError, TypeError, RecursionError) as error:
        raise ProtocolError("value is not canonicalizable I-JSON") from error
    require(len(encoded) <= MAX_JSON, "canonical object exceeds profile limit")
    return encoded


def load_json(encoded):
    require(len(encoded) <= MAX_JSON, "JSON exceeds profile limit")
    if isinstance(encoded, bytes):
        try:
            encoded = encoded.decode("utf-8")
        except UnicodeError as error:
            raise ProtocolError("JSON wire encoding must be UTF-8") from error
    def unique(pairs):
        value = {}
        for key, child in pairs:
            require(key not in value, "duplicate JSON key")
            value[key] = child
        return value
    try:
        value = json.loads(encoded, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ProtocolError("invalid JSON") from error
    canonical(value)
    return value


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def same(left, right):
    return canonical(left) == canonical(right)


def amount(value):
    fields(value, ("currency", "units"))
    integer(value["units"], 100, 100)
    require(value["currency"] == "TST", "unsupported currency")


def sign(body, key, envelope=True):
    signature = key.sign(canonical(body)).hex()
    if envelope:
        return {"body": body, "signerKey": key.public_key().public_bytes_raw().hex(), "signature": signature}
    return {"body": body, "signature": signature}


def verify_signature(body, signature, pin):
    try:
        public = hex_bytes(pin)
        require(any(public), "zero public key")
        Ed25519PublicKey.from_public_bytes(public).verify(hex_bytes(signature, 64), canonical(body))
    except Exception as error:
        raise ProtocolError("signature does not verify under the configured key") from error


def envelope(value, pin):
    fields(value, ("body", "signature", "signerKey"))
    require(value["signerKey"] == pin, "envelope signer differs from configured peer")
    verify_signature(value["body"], value["signature"], pin)
    return value["body"]


def agreement(value, peers):
    fields(peers, ("buyer", "provider"))
    fields(value, ("profile", "creditProfile", "buyer", "provider", "jobId", "inputSha256",
                   "checker", "subcontracting", "priceCeiling", "deadline"))
    require(value["profile"] == PROFILE and value["creditProfile"] == CREDIT, "unsupported work agreement")
    require(value["buyer"] == peers["buyer"] and value["provider"] == peers["provider"], "peer substitution")
    hex_bytes(peers["buyer"])
    hex_bytes(peers["provider"])
    hex_bytes(value["inputSha256"])
    require(type(value["jobId"]) is str and re.fullmatch("[A-Za-z0-9_-]{1,128}", value["jobId"]), "invalid job id")
    require(value["checker"] == CHECKER and value["subcontracting"] is False, "unsupported checker or subcontracting")
    integer(value["priceCeiling"], 100, 1000)
    integer(value["deadline"], 1)
    return value


def bid_body(a, issued_at):
    integer(issued_at, 1, a["deadline"] - 1)
    return {"schema": "chio.marketplace.bid-request.v1", "agentId": a["buyer"],
            "listingId": LISTING, "maxPricePerCall": {"currency": "TST", "units": a["priceCeiling"]},
            "windowSeconds": a["deadline"] - issued_at, "issuedAt": issued_at,
            "requestedScope": {"serverId": SERVER, "toolName": "review", "maxInvocations": 1,
                               "capabilityScopePrefix": "tools:security-review:" + digest(a)}}


def verify_quote(quote, peers):
    fields(quote, ("agreement", "bid"))
    a = agreement(quote["agreement"], peers)
    bid = envelope(quote["bid"], peers["buyer"])
    require(same(bid, bid_body(a, bid.get("issuedAt"))), "bid changes the agreed work")
    integer(bid["maxPricePerCall"]["units"], a["priceCeiling"], a["priceCeiling"])
    integer(bid["requestedScope"]["maxInvocations"], 1, 1)
    return a


def verify_ask(quote, ask, peers):
    a = verify_quote(quote, peers)
    body = envelope(ask, peers["provider"])
    fields(body, ("schema", "agentId", "listingId", "bidDigest", "quotedPrice", "issuedAt", "expiresAt", "tokenOffer"))
    require(body["schema"] == "chio.marketplace.ask-response.v1" and body["agentId"] == peers["buyer"]
            and body["listingId"] == LISTING and body["bidDigest"] == digest(quote["bid"]["body"])
            and body["quotedPrice"] == PRICE, "offer changes the bid or price")
    amount(body["quotedPrice"])
    integer(body["issuedAt"], quote["bid"]["body"]["issuedAt"], a["deadline"] - 1)
    integer(body["expiresAt"], body["issuedAt"] + 1, a["deadline"])
    token = body["tokenOffer"]
    fields(token, ("schema", "id", "issuer", "subject", "issued_at", "expires_at", "scope", "signature"))
    require(token["schema"] == "chio.capability.v1" and token["issuer"] == peers["provider"]
            and token["subject"] == peers["buyer"] and token["issued_at"] == body["issuedAt"]
            and token["expires_at"] == body["expiresAt"], "offered capability changes authority or validity")
    require(type(token["id"]) is str and 1 <= len(token["id"]) <= 256, "invalid capability id")
    integer(token["issued_at"], 1)
    integer(token["expires_at"], 1)
    verify_signature({key: value for key, value in token.items() if key != "signature"}, token["signature"], peers["provider"])
    require(same(token["scope"], {"grants": [{"server_id": SERVER, "tool_name": "review", "operations": ["invoke"],
                "max_invocations": 1, "max_cost_per_invocation": PRICE, "max_total_cost": PRICE, "dpop_required": True}]}),
            "offered capability widens the work or liability")
    grant = token["scope"]["grants"][0]
    integer(grant["max_invocations"], 1, 1)
    amount(grant["max_cost_per_invocation"])
    amount(grant["max_total_cost"])
    return body


def reservation_body(a, ask):
    return {"schema": "chio.marketplace.reservation-receipt.v1", "receiptId": "hold-" + digest(a),
            "agentId": a["buyer"], "listingId": LISTING, "askDigest": digest(ask["body"]), "reservedAmount": PRICE}


def accepted_body(ask, reservation, accepted_at):
    body = ask["body"]
    integer(accepted_at, body["issuedAt"], body["expiresAt"] - 1)
    return {"schema": "chio.marketplace.accepted-bid.v1", "listingId": LISTING, "agentId": body["agentId"],
            "bidDigest": body["bidDigest"], "askDigest": digest(body), "bidReceiptId": reservation["body"]["receiptId"],
            "quotedPrice": PRICE, "acceptedAt": accepted_at, "tokenId": body["tokenOffer"]["id"],
            "tokenSubject": body["tokenOffer"]["subject"], "tokenExpiresAt": body["tokenOffer"]["expires_at"]}


def acceptance(value, peers):
    fields(value, ("quote", "ask", "reservation", "accepted"))
    verify_ask(value["quote"], value["ask"], peers)
    reserved = envelope(value["reservation"], peers["buyer"])
    amount(reserved.get("reservedAmount"))
    require(same(reserved, reservation_body(value["quote"]["agreement"], value["ask"])), "reservation changes the offer")
    accepted = envelope(value["accepted"], peers["buyer"])
    amount(accepted.get("quotedPrice"))
    integer(accepted.get("tokenExpiresAt"), 1)
    require(same(accepted, accepted_body(value["ask"], value["reservation"], accepted.get("acceptedAt"))), "acceptance changes the offer")
    return value["quote"]["agreement"]


def acknowledgement(value, accepted, peers):
    body = envelope(value, peers["provider"])
    a = acceptance(accepted, peers)
    require(same(body, {"schema": "chio.example.work-acknowledgement.v1", "jobId": a["jobId"],
                    "agreementSha256": digest(a), "acceptedBidSha256": digest(accepted["accepted"]),
                    "state": "accepted", "workExecuted": False, "settled": False}),
            "provider has not acknowledged this exact acceptance")


def receipt(value, pin, tool, args):
    required = ("id", "timestamp", "capability_id", "tool_server", "tool_name", "action", "decision",
                "content_hash", "policy_hash", "kernel_key", "signature", "receipt_kind", "boundary_class",
                "tool_origin", "redaction_mode", "trust_level")
    optional = ("actor_chain", "evidence", "metadata", "tenant_id")
    fields(value, required, optional)
    require(value["kernel_key"] == pin and value["tool_server"] == SERVER and value["tool_name"] == tool,
            "receipt names a different authority or tool")
    require(value["receipt_kind"] == "mediated_decision" and value["boundary_class"] == "prevent"
            and value["trust_level"] == "mediated" and value["redaction_mode"] == "none"
            and value["tool_origin"] == "caller_executed", "unsupported receipt semantics")
    require(same(value["action"], {"parameter_hash": digest(args), "parameters": args}), "receipt changes the action")
    body = {key: child for key, child in value.items() if key not in ("id", "signature")}
    require(digest(body) == value["id"], "receipt id is not content-addressed")
    verify_signature({"id": value["id"], "body": body}, value["signature"], pin)
    integer(value["timestamp"], 1)
    hex_bytes(value["content_hash"])
    return value


def inclusion(receipt_value, checkpoint, proof, pin):
    fields(checkpoint, ("body", "signature"))
    body = checkpoint["body"]
    fields(body, ("schema", "kernel_key", "checkpoint_seq", "batch_start_seq", "batch_end_seq", "tree_size",
                  "merkle_root", "chain_root", "issued_at"), ("previous_checkpoint_sha256",))
    require(body["schema"] == "chio.checkpoint_statement.v2" and body["kernel_key"] == pin, "unsupported checkpoint")
    verify_signature(body, checkpoint["signature"], pin)
    start = integer(body["batch_start_seq"], 1)
    end = integer(body["batch_end_seq"], start)
    size = integer(body["tree_size"], 1, 4096)
    require(size == end - start + 1, "checkpoint tree size differs from receipt interval")
    integer(body["issued_at"], 1)
    integer(body["checkpoint_seq"], 1)
    if "previous_checkpoint_sha256" in body:
        hex_bytes(body["previous_checkpoint_sha256"])
    hex_bytes(body["chain_root"], prefix="0x")
    fields(proof, ("checkpoint_seq", "leaf_index", "merkle_root", "proof", "receipt_seq"))
    index = integer(proof["leaf_index"], 0, size - 1)
    integer(proof["checkpoint_seq"], 1)
    integer(proof["receipt_seq"], 1)
    require(proof["checkpoint_seq"] == body["checkpoint_seq"] and proof["receipt_seq"] == start + index
            and proof["merkle_root"] == body["merkle_root"], "inclusion coordinates do not match checkpoint")
    inner = fields(proof["proof"], ("audit_path", "leaf_index", "tree_size"))
    integer(inner["leaf_index"], 0, size - 1)
    integer(inner["tree_size"], 1, 4096)
    require(inner["leaf_index"] == index and inner["tree_size"] == size, "inner inclusion coordinates differ")
    require(type(inner["audit_path"]) is list and len(inner["audit_path"]) <= 12, "invalid audit path")
    path = iter(hex_bytes(item, prefix="0x") for item in inner["audit_path"])
    leaf = hashlib.sha256(b"\x00" + canonical(receipt_value)).digest()
    def root(position, count):
        if count == 1:
            return leaf
        split = 1 << ((count - 1).bit_length() - 1)
        if position < split:
            left, right = root(position, split), next(path)
        else:
            right, left = root(position - split, count - split), next(path)
        return hashlib.sha256(b"\x01" + left + right).digest()
    try:
        calculated = root(index, size)
    except StopIteration as error:
        raise ProtocolError("short inclusion proof") from error
    require(next(path, None) is None and calculated == hex_bytes(body["merkle_root"], prefix="0x"), "inclusion proof does not verify")
