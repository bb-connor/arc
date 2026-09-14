"""Example-local, fail-closed signed artifacts for funded W0 work.

These artifacts provide no native execution, receipt, finality or runtime assurance.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from reference_checker import BUYER, SOURCE_HASHES, protocol as legacy, review as reference_review

ProtocolError = legacy.ProtocolError
require = legacy.require
fields = legacy.fields
integer = legacy.integer
hex_bytes = legacy.hex_bytes
MAX_JSON = 256 * 1024
MAX_OBJECT = 64 * 1024
MAX_INT = 2**53 - 1
RECOVERY_SECONDS = 30 * 24 * 60 * 60


def _depth(value, depth=0):
    if isinstance(value, (dict, list)):
        require(depth < 16, "JSON exceeds depth 16")
        for child in (value.values() if isinstance(value, dict) else value):
            _depth(child, depth + 1)


def canonical(value):
    _depth(value)
    encoded = legacy.canonical(value)
    require(len(encoded) <= MAX_JSON, "artifact exceeds 256 KiB")
    return encoded


def load(encoded, limit=MAX_JSON):
    require(type(encoded) is bytes and len(encoded) <= limit, "wire bytes exceed limit")
    value = legacy.load_json(encoded)
    canonical(value)
    return value


def sha256(encoded):
    return hashlib.sha256(encoded).hexdigest()


def digest(value):
    return sha256(canonical(value))


def sign(body, key):
    return {"body": body, "signerKey": key.public_key().public_bytes_raw().hex(),
            "signature": key.sign(canonical(body)).hex()}


def envelope(value, pin):
    canonical(value)
    return legacy.envelope(value, pin)


def decimal(value, low=1):
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,15}", value), "noncanonical amount")
    integer(int(value), low, MAX_INT)
    return value


def address(value):
    require(any(hex_bytes(value, 20, "0x")), "zero address")
    return value


def hash256(value, prefix=""):
    require(any(hex_bytes(value, 32, prefix)), "zero digest")
    return value


def verify_agreement(value, pins):
    canonical(value)
    fields(value, ("body", "buyerSignature", "providerSignature"))
    fields(pins, ("buyer", "provider", "verifier", "custodian"))
    body = fields(value["body"], ("schema", "workId", "buyerKey", "providerKey", "verifierKey",
        "custodianKey", "inputSha256", "checkerSha256", "assurance", "parentAgreementSha256",
        "rail", "deadlines", "custody"))
    require(body["schema"] == "chio.experimental.funded-w0-agreement.v1", "unsupported agreement")
    require(body["assurance"] == "artifact-only-v1", "unsupported assurance")
    require(body["checkerSha256"] == CHECKER_SHA256, "unsupported checker profile")
    require(type(body["workId"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", body["workId"]), "invalid work id")
    for role, pin in pins.items():
        hash256(pin)
        require(body[role + "Key"] == pin, "party differs from local pin")
    require(len(set(pins.values())) == 4, "artifact roles must be distinct")
    hash256(body["inputSha256"])
    if body["parentAgreementSha256"] is not None:
        hash256(body["parentAgreementSha256"])
    rail = fields(body["rail"], ("chainId", "escrow", "runtimeKeccak256", "token", "payer", "beneficiary", "verifier", "amount"))
    decimal(rail["chainId"])
    decimal(rail["amount"])
    hash256(rail["runtimeKeccak256"], "0x")
    for name in ("escrow", "token", "payer", "beneficiary", "verifier"):
        address(rail[name])
    require(len({rail[k] for k in ("payer", "beneficiary", "verifier", "escrow")}) == 4, "rail role collision")
    deadlines = fields(body["deadlines"], ("submitBy", "challengeUntil", "resolveBy", "refundAfter"))
    times = [integer(deadlines[k], 1) for k in ("submitBy", "challengeUntil", "resolveBy", "refundAfter")]
    require(all(a < b for a, b in zip(times, times[1:])), "deadlines must strictly increase")
    custody = fields(body["custody"], ("policy", "retainUntil"))
    require(custody["policy"] == "local-retain-indefinitely-v1", "unsupported custody policy")
    integer(custody["retainUntil"], deadlines["refundAfter"] + RECOVERY_SECONDS)
    for role in ("buyer", "provider"):
        legacy.verify_signature(body, value[role + "Signature"], pins[role])
    return body


def output(operations):
    return {"schema": "chio.experimental.funded-w0-output.v1", "operations": operations}


def verify_output(encoded):
    value = fields(load(encoded, MAX_OBJECT), ("schema", "operations"))
    require(value["schema"] == "chio.experimental.funded-w0-output.v1", "unsupported output")
    rows = value["operations"]
    require(type(rows) is list and 1 <= len(rows) <= 512, "unsupported operation count")
    for row in rows:
        fields(row, ("path", "method", "authenticationRequired"))
        require(type(row["path"]) is str and row["path"].startswith("/") and len(row["path"].encode()) <= 256,
                "invalid operation path")
        require(row["method"] in ("get", "put", "post", "delete", "options", "head", "patch", "trace")
                and type(row["authenticationRequired"]) is bool, "invalid operation result")
    return value


def receipt_body(agreement, output_sha):
    return {"schema": "chio.experimental.funded-w0-custody.v1", "agreementSha256": digest(agreement),
            "inputSha256": agreement["inputSha256"], "outputSha256": hash256(output_sha),
            **agreement["custody"]}


def submission_body(agreement, allocation, receipt):
    return {"schema": "chio.experimental.funded-w0-submission.v1", "agreementSha256": digest(agreement),
            "allocationId": hash256(allocation, "0x"), "inputSha256": agreement["inputSha256"],
            "outputSha256": receipt["body"]["outputSha256"], "checkerSha256": agreement["checkerSha256"],
            "custody": receipt}


def verify_submission(value, agreement, allocation):
    body = envelope(value, agreement["providerKey"])
    fields(body, ("schema", "agreementSha256", "allocationId", "inputSha256", "outputSha256", "checkerSha256", "custody"))
    receipt = envelope(body["custody"], agreement["custodianKey"])
    require(canonical(receipt) == canonical(receipt_body(agreement, body["outputSha256"])), "custody changes work or retention")
    require(canonical(body) == canonical(submission_body(agreement, allocation, body["custody"])), "submission changes funded work")
    return body


def decision_body(agreement, submission, accepted):
    require(type(accepted) is bool, "decision must be boolean")
    body = submission["body"]
    return {"schema": "chio.experimental.funded-w0-decision.v1", "agreementSha256": digest(agreement),
            "allocationId": body["allocationId"], "commitment": "0x" + digest(submission),
            "inputSha256": body["inputSha256"], "outputSha256": body["outputSha256"],
            "checkerSha256": agreement["checkerSha256"], "custodyReceiptSha256": digest(body["custody"]),
            "retainUntil": agreement["custody"]["retainUntil"], "retentionPolicy": agreement["custody"]["policy"],
            "assurance": "artifact-only-v1", "accepted": accepted,
            "predicate": "match" if accepted else "mismatch", "rail": agreement["rail"]}


def verify_decision(value, agreement, submission):
    verify_submission(submission, agreement, submission["body"]["allocationId"])
    body = envelope(value, agreement["verifierKey"])
    require(canonical(body) == canonical(decision_body(agreement, submission, body.get("accepted"))), "decision changes claim or verdict")
    return body


CHECKER_PROFILE = load((Path(__file__).parent / "checker-profile.json").read_bytes())
CHECKER_SHA256 = digest(CHECKER_PROFILE)


def check_implementation(checker=None):
    if checker is not None:
        require(checker is reference_review, 'checker is not the selected reference implementation')
    require(CHECKER_PROFILE["pythonSourceSha256"] == SOURCE_HASHES['review'] and
            CHECKER_PROFILE["pythonProtocolSha256"] == SOURCE_HASHES['protocol'],
            "loaded checker or parser differs from pinned source")
    require(CHECKER_PROFILE["pythonSourceSha256"] == sha256((BUYER / "review.py").read_bytes()),
            "Python checker differs from pinned source")
    require(CHECKER_PROFILE["pythonProtocolSha256"] == sha256((BUYER / "protocol.py").read_bytes()),
            "Python checker parser differs from pinned source")
