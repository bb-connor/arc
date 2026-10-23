"""Check the interceptor's canonical bytes and digests against Rust kernel vectors.

``fixtures/caller_delivery_golden_v1.json`` was produced by ``chio-kernel``
(``SignedCallerDispatchAuthorizationV1::sign``,
``SignedCallerDeliveryReportV1::sign`` and ``ChioReceipt::sign``) with
Ed25519 seeds of 32 bytes of ``0x29`` (kernel) and ``0x2a`` (executor).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chio_temporal import CallerExecutor
from chio_temporal.executor import canonical_json_bytes, signing_wrapper
from chio_temporal.interceptor import _kernel_receipt_signing_bytes

GOLDEN = json.loads(
    (Path(__file__).parent / "fixtures" / "caller_delivery_golden_v1.json").read_text(
        encoding="utf-8"
    )
)


def _private_key(seed_byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def _public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


class Ed25519Executor:
    """Reference ``CallerExecutor`` built on ``cryptography`` Ed25519 keys."""

    def __init__(
        self, *, private_key: Ed25519PrivateKey, executor_id: str, key_epoch: int, kernel: str
    ) -> None:
        self._key = private_key
        self._identity = {
            "executor_id": executor_id,
            "public_key": _public_hex(private_key),
            "key_epoch": key_epoch,
        }
        self._kernel = kernel

    @property
    def identity(self) -> dict[str, Any]:
        return dict(self._identity)

    @property
    def kernel_public_key(self) -> str:
        return self._kernel

    def sign(self, message: bytes) -> str:
        return self._key.sign(message).hex()

    def verify_kernel_signature(self, message: bytes, signature: str) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self._kernel)).verify(
                bytes.fromhex(signature), message
            )
        except Exception:
            return False
        return True


@pytest.fixture
def executor() -> Ed25519Executor:
    authorization = GOLDEN["authorization"]["authorization"]
    return Ed25519Executor(
        private_key=_private_key(GOLDEN["executor_seed_byte"]),
        executor_id=authorization["executor"]["executor_id"],
        key_epoch=authorization["executor"]["key_epoch"],
        kernel=_public_hex(_private_key(GOLDEN["kernel_seed_byte"])),
    )


def test_reference_executor_satisfies_the_protocol(executor: Ed25519Executor) -> None:
    assert isinstance(executor, CallerExecutor)


def test_seeds_reproduce_the_kernel_and_executor_keys(executor: Ed25519Executor) -> None:
    body = GOLDEN["authorization"]["authorization"]
    assert body["kernel_public_key"] == executor.kernel_public_key
    assert body["executor"] == executor.identity


def test_authorization_canonical_bytes_and_digest_match_the_kernel() -> None:
    authorization = GOLDEN["authorization"]
    assert canonical_json_bytes(authorization["authorization"]) == GOLDEN[
        "authorization_body_canonical"
    ].encode("utf-8")
    canonical = canonical_json_bytes(authorization)
    assert canonical == GOLDEN["authorization_canonical"].encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == GOLDEN["authorization_digest"]


def test_kernel_authorization_signature_verifies(executor: Ed25519Executor) -> None:
    authorization = GOLDEN["authorization"]
    body = canonical_json_bytes(authorization["authorization"])
    message = signing_wrapper("chio.caller-dispatch-authorization.v1", body)
    assert executor.verify_kernel_signature(message, authorization["signature"])
    assert not executor.verify_kernel_signature(
        signing_wrapper("chio.caller-dispatch-authorization.v1", body + b" "),
        authorization["signature"],
    )
    assert not executor.verify_kernel_signature(body, authorization["signature"])


def test_report_bytes_and_signature_reproduce_the_kernel_report(
    executor: Ed25519Executor,
) -> None:
    report = GOLDEN["report"]
    body_bytes = canonical_json_bytes(report["report"])
    assert body_bytes == GOLDEN["report_body_canonical"].encode("utf-8")
    assert report["report"]["authorization_digest"] == GOLDEN["authorization_digest"]
    # Ed25519 is deterministic: the Python signer must emit the kernel's bytes.
    wrapper = signing_wrapper("chio.caller-delivery-report.v1", body_bytes)
    assert executor.sign(wrapper) == report["signature"]


def test_receipt_signing_body_and_id_match_the_kernel(executor: Ed25519Executor) -> None:
    receipt = GOLDEN["receipt"]
    signing, id_input = _kernel_receipt_signing_bytes(receipt)
    assert hashlib.sha256(id_input).hexdigest() == receipt["id"]
    assert executor.verify_kernel_signature(signing, receipt["signature"])
    forged = dict(receipt, tool_name="other")
    forged_signing, forged_id = _kernel_receipt_signing_bytes(forged)
    assert hashlib.sha256(forged_id).hexdigest() != receipt["id"]
    assert not executor.verify_kernel_signature(forged_signing, receipt["signature"])


def test_receipt_with_an_algorithm_member_is_not_the_kernel_receipt(
    executor: Ed25519Executor,
) -> None:
    receipt = dict(GOLDEN["receipt"], algorithm="ed25519")
    signing, id_input = _kernel_receipt_signing_bytes(receipt)
    assert hashlib.sha256(id_input).hexdigest() != receipt["id"]
    assert not executor.verify_kernel_signature(signing, receipt["signature"])
