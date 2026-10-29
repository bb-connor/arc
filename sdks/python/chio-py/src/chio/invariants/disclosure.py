from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any

from ..errors import ChioInvariantError, parse_json_text_unique_keys
from .json import canonicalize_json

RECEIPT_DISCLOSURE_SCHEMA = "chio.receipt-disclosure.v1"
MAX_DISCLOSURE_OPENINGS = 64

_PARAMETERS_DOMAIN = b"chio.receipt.parameters.v1\x00"
_CONTENT_DOMAIN = b"chio.receipt.content.v1\x00"
_RECEIPT_ID = re.compile(r"\A[0-9a-f]{64}\Z")
_SALT_REF = re.compile(r"\A[a-z][a-z0-9_]*(\.[a-z0-9_]+)*\Z")
_SALT = re.compile(r"\Ab64u:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\Z")
_DISCLOSURE_MEMBERS = frozenset({"schema", "receipt_id", "openings"})
_OPENING_MEMBERS = frozenset({"salt_ref", "salt", "payload"})
_COMMITMENT_MEMBERS = frozenset({"alg", "value", "salt_ref"})

VERIFIED = "verified"
REJECTED = "rejected"
UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class Opening:
    """One salt opening. ``payload`` is opaque to the opener; ``None`` is a salt-only opening."""

    salt_ref: str
    salt: bytes
    payload: Any


@dataclass(frozen=True)
class ReceiptDisclosure:
    receipt_id: str
    openings: tuple[Opening, ...]


def _refuse(message: str) -> ChioInvariantError:
    return ChioInvariantError("disclosure", message)


def _require_exact_members(value: dict[str, Any], members: frozenset[str], path: str) -> None:
    for key in sorted(value):
        if key not in members:
            raise _refuse(f"unknown disclosure member: {path}/{key}")
    for key in sorted(members):
        if key not in value:
            raise _refuse(f"missing disclosure member: {path}/{key}")


def decode_salt(encoded: Any) -> bytes:
    """Accept only the canonical ``b64u:`` form of 32 bytes."""
    if not isinstance(encoded, str) or _SALT.fullmatch(encoded) is None:
        raise _refuse("salt is not the canonical b64u form of 32 bytes")
    raw = base64.urlsafe_b64decode(encoded[len("b64u:"):] + "=")
    if len(raw) != 32:
        raise _refuse("salt is not the canonical b64u form of 32 bytes")
    return raw


def parse_receipt_disclosure(value: Any) -> ReceiptDisclosure:
    """Decode a parsed ``chio.receipt-disclosure.v1`` document; refuse anything outside its wire form."""
    if not isinstance(value, dict):
        raise _refuse("disclosure must be a JSON object")
    _require_exact_members(value, _DISCLOSURE_MEMBERS, "")
    if value["schema"] != RECEIPT_DISCLOSURE_SCHEMA:
        raise _refuse("schema is not chio.receipt-disclosure.v1")
    receipt_id = value["receipt_id"]
    if not isinstance(receipt_id, str) or _RECEIPT_ID.fullmatch(receipt_id) is None:
        raise _refuse("receipt_id is not 64 lowercase hex characters")
    entries = value["openings"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_DISCLOSURE_OPENINGS:
        raise _refuse("openings must hold 1 to 64 entries")
    openings = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise _refuse("opening must be a JSON object")
        _require_exact_members(entry, _OPENING_MEMBERS, f"/openings/{index}")
        salt_ref = entry["salt_ref"]
        if not isinstance(salt_ref, str) or len(salt_ref) > 64 or _SALT_REF.fullmatch(salt_ref) is None:
            raise _refuse("salt_ref is not a valid salt reference")
        openings.append(Opening(salt_ref, decode_salt(entry["salt"]), entry["payload"]))
    return ReceiptDisclosure(receipt_id, tuple(openings))


def parse_receipt_disclosure_json(input_text: str) -> ReceiptDisclosure:
    """Decode disclosure text; a repeated object key at any depth is refused."""
    return parse_receipt_disclosure(parse_json_text_unique_keys(input_text))


def _structurally_valid(receipt_id: str, disclosure: ReceiptDisclosure) -> bool:
    if disclosure.receipt_id != receipt_id:
        return False
    openings = disclosure.openings
    for index, opening in enumerate(openings):
        for other in openings[index + 1:]:
            if opening.salt_ref == other.salt_ref or hmac.compare_digest(opening.salt, other.salt):
                return False
    return True


def _open_field(
    disclosure: ReceiptDisclosure,
    commitment: Any,
    position: str,
    domain: bytes,
    preimage: bytes | None,
) -> str:
    if (
        not isinstance(commitment, dict)
        or set(commitment) != _COMMITMENT_MEMBERS
        or commitment["alg"] != "sha256-salted"
        or commitment["salt_ref"] != position
        or not isinstance(commitment["value"], str)
    ):
        return REJECTED
    opening = next((entry for entry in disclosure.openings if entry.salt_ref == position), None)
    if opening is None or preimage is None:
        return UNVERIFIABLE
    expected = "sha256:" + hashlib.sha256(domain + opening.salt + preimage).hexdigest()
    return VERIFIED if hmac.compare_digest(expected, commitment["value"]) else REJECTED


def open_commitments(
    receipt_id: str,
    parameter_commitment: Any,
    content_commitment: Any,
    disclosure: ReceiptDisclosure,
    own_parameters: Any = None,
    own_content: bytes | None = None,
) -> dict[str, Any]:
    """Open a receipt's parameter and content commitments over the caller's own arguments and
    content preimage; a payload never supplies a preimage. An absent own preimage leaves that
    field unverifiable. A document for another receipt, a repeated salt_ref or a salt shared by
    two openings rejects every field; any rejected field marks the disclosure invalid. The report
    covers only the parameter and content commitments: the delegation-context anchor commitments
    (anchor_subject, anchor_tenant) are outside it, and a disclosure that opens them is accepted
    only after they are judged separately."""
    if not _structurally_valid(receipt_id, disclosure):
        return {"content": REJECTED, "disclosure_valid": False, "parameters": REJECTED}
    if own_parameters is None:
        parameters_preimage = None
    else:
        try:
            parameters_preimage = canonicalize_json(own_parameters).encode("utf-8")
        except ChioInvariantError:
            return {"content": REJECTED, "disclosure_valid": False, "parameters": REJECTED}
    parameters = _open_field(disclosure, parameter_commitment, "params", _PARAMETERS_DOMAIN, parameters_preimage)
    content = _open_field(disclosure, content_commitment, "content", _CONTENT_DOMAIN, own_content)
    return {
        "content": content,
        "disclosure_valid": REJECTED not in (parameters, content),
        "parameters": parameters,
    }
