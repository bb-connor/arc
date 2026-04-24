"""Deterministic capability issuance for the offline web3 agent scenario."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from .artifacts import now_epoch

Json = dict[str, Any]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class Identity:
    name: str
    signing_key: SigningKey

    @classmethod
    def deterministic(cls, namespace: str, name: str) -> "Identity":
        seed = hashlib.sha256(f"{namespace}:{name}:seed".encode()).digest()
        return cls(
            name=name,
            signing_key=SigningKey(seed),
        )

    @property
    def public_key(self) -> str:
        return self.signing_key.verify_key.encode(encoder=HexEncoder).decode("utf-8")

    @property
    def seed_hex(self) -> str:
        return self.signing_key.encode(encoder=HexEncoder).decode("utf-8")

    def public_document(self) -> Json:
        return {"name": self.name, "public_key": self.public_key, "identity_scheme": "ed25519"}

    def sign(self, body: Json) -> str:
        return self.signing_key.sign(_canonical(body)).signature.hex()


def grant(
    server: str,
    tool: str,
    operations: list[str],
    max_minor_units: int | None = None,
) -> Json:
    document: Json = {
        "server_id": server,
        "tool_name": tool,
        "operations": operations,
        "constraints": [],
    }
    if max_minor_units is not None:
        document["maxTotalCost"] = {"units": max_minor_units, "currency": "USDC"}
        document["maxCostPerInvocation"] = {"units": max_minor_units, "currency": "USDC"}
    return document


def scope(*grants: Json) -> Json:
    return {"grants": list(grants), "resource_grants": [], "prompt_grants": []}


class CapabilityIssuer:
    """Creates a signed, attenuated delegation tree for the scenario actors."""

    def __init__(self, namespace: str = "chio-ioa-web3") -> None:
        self.namespace = namespace

    def identity(self, name: str) -> Identity:
        return Identity.deterministic(self.namespace, name)

    def issue_root(self, identity: Identity, capability_scope: Json, ttl_seconds: int) -> Json:
        issued_at = now_epoch()
        cap = {
            "id": "cap-ioa-web3-root",
            "issuer": identity.public_key,
            "subject": identity.public_key,
            "scope": capability_scope,
            "issued_at": issued_at,
            "expires_at": issued_at + ttl_seconds,
            "delegation_chain": [],
        }
        cap["signature"] = identity.sign(capability_body(cap))
        return cap

    def delegate(
        self,
        *,
        parent: Json,
        delegator: Identity,
        delegatee: Identity,
        capability_scope: Json,
        capability_id: str,
        ttl_seconds: int,
        attenuations: list[Json] | None = None,
    ) -> Json:
        issued_at = now_epoch()
        link = {
            "capability_id": parent["id"],
            "delegator": delegator.public_key,
            "delegatee": delegatee.public_key,
            "attenuations": attenuations or [],
            "timestamp": issued_at,
        }
        link["signature"] = delegator.sign(delegation_link_body(link))
        cap = {
            "id": capability_id,
            "issuer": delegator.public_key,
            "subject": delegatee.public_key,
            "scope": capability_scope,
            "issued_at": issued_at,
            "expires_at": min(parent["expires_at"], issued_at + ttl_seconds),
            "delegation_chain": [*parent.get("delegation_chain", []), link],
        }
        cap["signature"] = delegator.sign(capability_body(cap))
        return cap


def capability_body(capability: Json) -> Json:
    body = {
        "id": capability["id"],
        "issuer": capability["issuer"],
        "subject": capability["subject"],
        "scope": capability["scope"],
        "issued_at": capability["issued_at"],
        "expires_at": capability["expires_at"],
    }
    if capability.get("delegation_chain"):
        body["delegation_chain"] = capability["delegation_chain"]
    return body


def delegation_link_body(link: Json) -> Json:
    return {
        "capability_id": link["capability_id"],
        "delegator": link["delegator"],
        "delegatee": link["delegatee"],
        "attenuations": link["attenuations"],
        "timestamp": link["timestamp"],
    }
