"""Diagnostic-only verifier changes do not change receipt integrity evidence."""

import copy
import json

import pytest
from test_repository_review import bundle as bundle

from chio_mini_swe import repository_proof as proof
from chio_mini_swe import repository_review as review


@pytest.fixture
def verification_bundle(bundle, monkeypatch):
    output, arguments = bundle
    original = review.verified_receipts
    checks = ["signature", "signer_pin", "action_parameter_hash"]
    path = output / "receipt-binding.json"
    proof = json.loads(path.read_text())
    proof["verification"].update(schema="chio.receipt.signatures.v1", checks=checks)
    path.write_text(json.dumps(proof))
    calls = []

    def authenticate(binary, data, trusted):
        calls.append((data, trusted))
        receipts, verification = original(binary, data, trusted)
        return receipts, verification | {"schema": "chio.receipt.signatures.v1", "checks": checks}

    monkeypatch.setattr(review, "verified_receipts", authenticate)
    return output, arguments, calls


@pytest.mark.parametrize("change", ["reorder", "added_check", "added_field"])
def test_advisory_diagnostic_changes_do_not_reject_independently_reverified_receipts(
    verification_bundle, change
):
    output, arguments, calls = verification_bundle
    path = output / "receipt-binding.json"
    proof = json.loads(path.read_text())
    cached = proof["verification"]
    if change == "reorder":
        cached["checks"].reverse()
    elif change == "added_check":
        cached["checks"].append("bounded_input")
    else:
        cached["diagnostic_version"] = "compatible-producer"
    path.write_text(json.dumps(proof))
    result = review.verify_export(output, **arguments)
    assert result["verified_transitions"] == 2
    assert result["verification"]["checks"] == ["signature", "signer_pin", "action_parameter_hash"]
    assert calls == [
        ((output / "receipts.ndjson").read_bytes(), arguments["key_path"].read_bytes())
    ]


def test_fresh_advisory_details_are_returned_without_rewriting_producer_evidence(
    verification_bundle, monkeypatch
):
    output, arguments, calls = verification_bundle
    path = output / "receipt-binding.json"
    historical = path.read_bytes()
    original = review.verified_receipts
    fresh = None

    def authenticate(binary, data, trusted):
        nonlocal fresh
        receipts, report = original(binary, data, trusted)
        fresh = report | {
            "checks": ["signature", "bounded_input", "signer_pin", "action_parameter_hash"],
            "diagnostic_version": "fresh-verifier",
        }
        return receipts, fresh

    monkeypatch.setattr(review, "verified_receipts", authenticate)
    result = review.verify_export(output, **arguments)
    assert result["verification"] == fresh
    assert result["verified_transitions"] == 2
    assert path.read_bytes() == historical
    assert calls == [
        ((output / "receipts.ndjson").read_bytes(), arguments["key_path"].read_bytes())
    ]


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "other.v1"),
        ("receipts_verified", 999),
        ("receipts_verified", True),
        ("trusted_kernel_key", "different-key"),
    ],
)
def test_stable_verification_fields_still_reject_changed_evidence(
    verification_bundle, field, value
):
    output, arguments, calls = verification_bundle
    path = output / "receipt-binding.json"
    proof = json.loads(path.read_text())
    proof["verification"][field] = value
    path.write_text(json.dumps(proof))
    with pytest.raises(ValueError):
        review.verify_export(output, **arguments)
    assert len(calls) == 1


def test_receipt_tamper_is_rejected_before_advisory_comparison(verification_bundle):
    output, arguments, calls = verification_bundle
    original = (output / "receipts.ndjson").read_bytes()
    changed = copy.deepcopy(json.loads(original.splitlines()[0]))
    changed["content_hash"] = "0" * 64
    (output / "receipts.ndjson").write_bytes(json.dumps(changed).encode() + b"\n")
    with pytest.raises(ValueError, match="Receipt authentication failed"):
        review.verify_export(output, **arguments)
    assert calls[0][1] == arguments["key_path"].read_bytes()


@pytest.fixture
def native_report(monkeypatch):
    data = b'{"id":"fixture-receipt"}\n'
    key = b"independently-trusted-key"
    report = {
        "schema": "chio.receipt.signatures.v1",
        "receipts_verified": 1,
        "trusted_kernel_key": "fixture-key",
        "checks": ["signature", "signer_pin", "action_parameter_hash"],
    }
    protected, calls = [], []
    monkeypatch.setattr(proof, "protected_executable", protected.append)

    def authenticate(binary, *arguments):
        assert binary == "/fixture/chio"
        assert arguments[:4] == ("--json", "receipt", "verify", "--input")
        assert arguments[5] == "--trusted-kernel-pubkey"
        assert arguments[4].read_bytes() == data
        assert arguments[6].read_bytes() == key
        calls.append((data, key))
        return report

    monkeypatch.setattr(proof, "command", authenticate)
    return report, data, key, protected, calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "other.v1"),
        ("schema", None),
        ("receipts_verified", True),
        ("receipts_verified", 0),
        ("trusted_kernel_key", None),
        ("trusted_kernel_key", ""),
        ("trusted_kernel_key", "k" * 1025),
    ],
    ids=["schema", "missing-schema", "boolean-count", "count", "key-type", "empty-key", "key-size"],
)
def test_native_report_requires_typed_complete_stable_evidence(native_report, field, value):
    report, data, key, protected, calls = native_report
    report[field] = value
    with pytest.raises(ValueError):
        proof.verified_receipts("/fixture/chio", data, key)
    assert protected == ["/fixture/chio"]
    assert calls == [(data, key)]


def test_native_verification_failure_is_not_replaced_by_cached_evidence(native_report, monkeypatch):
    _, data, key, protected, _ = native_report

    def refuse(*_):
        raise RuntimeError("Native receipt verification failed")

    monkeypatch.setattr(proof, "command", refuse)
    with pytest.raises(RuntimeError, match="Native receipt verification failed"):
        proof.verified_receipts("/fixture/chio", data, key)
    assert protected == ["/fixture/chio"]


def test_native_report_keeps_fresh_advisory_fields(native_report):
    report, data, key, protected, calls = native_report
    report["checks"].append("bounded_input")
    report["diagnostic_version"] = "fresh-native-report"
    receipts, fresh = proof.verified_receipts("/fixture/chio", data, key)
    assert receipts == [{"id": "fixture-receipt"}]
    assert fresh == report
    assert protected == ["/fixture/chio"]
    assert calls == [(data, key)]
