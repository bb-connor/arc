"""Caller-executor identity for the mediated ``chio.caller-delivery.v1`` route.

The interceptor acts as the caller executor named in the sidecar's
dispatch authorization. It needs three things the host must supply: the
executor identity the sidecar was configured with, the pinned kernel
public key, and an Ed25519 (or other kernel-supported) signer. Keys never
come from a sidecar response.

The interceptor does not keep a durable executor ledger. A worker that
dies between ``/v1/caller/start`` and ``/v1/caller/report`` leaves the
committed hold for the kernel to expire or recover.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol, runtime_checkable

SIGNING_WRAPPER_PREFIX = b"chio.signing-wrapper.v1\x00"


@runtime_checkable
class CallerExecutor(Protocol):
    """Trusted executor key material supplied by the worker host."""

    @property
    def identity(self) -> dict[str, Any]:
        """``{"executor_id": str, "public_key": str, "key_epoch": int}``.

        Must equal the executor identity the sidecar was configured with.
        """
        ...

    @property
    def kernel_public_key(self) -> str:
        """Pinned kernel public key that must sign every dispatch authorization."""
        ...

    def sign(self, message: bytes) -> str:
        """Sign the report's signing-wrapper bytes with the executor key; return the wire signature."""
        ...

    def verify_kernel_signature(self, message: bytes, signature: str) -> bool:
        """Verify ``signature`` over ``message`` against :attr:`kernel_public_key`."""
        ...


def canonical_json_bytes(value: Any) -> bytes:
    """RFC 8785 canonical bytes for values built from strings, integers, bools and null.

    Floats are rejected: their RFC 8785 number form is not reproduced here,
    and a digest over a different encoding than the kernel's must never be
    signed or compared.
    """
    _reject_floats(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("canonical caller-delivery JSON does not admit floats")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("canonical caller-delivery JSON requires string keys")
            _reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item)


def signing_wrapper(schema_id: str, canonical: bytes) -> bytes:
    """The 88 bytes every Chio signature covers.

    ``SIGNING_WRAPPER_PREFIX || SHA-256(schema_id) || SHA-256(canonical)``,
    where ``canonical`` is the RFC 8785 body signed under ``schema_id``.
    """
    return (
        SIGNING_WRAPPER_PREFIX
        + hashlib.sha256(schema_id.encode("utf-8")).digest()
        + hashlib.sha256(canonical).digest()
    )


__all__ = ["CallerExecutor", "canonical_json_bytes", "signing_wrapper"]
