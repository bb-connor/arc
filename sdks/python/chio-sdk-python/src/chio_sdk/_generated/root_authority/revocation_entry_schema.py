# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

import hashlib
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr, model_validator


class RevocationReason(Enum):
    """
    Closed set of revocation reasons. The first write's reason stands.
    """

    operator_request = "operator_request"
    credential_compromise = "credential_compromise"
    principal_offboarded = "principal_offboarded"
    tenant_offboarded = "tenant_offboarded"
    policy_withdrawn = "policy_withdrawn"
    incident_response = "incident_response"


class TargetKind(Enum):
    """
    Target kinds whose value is an identifier.
    """

    capability_id = "capability_id"
    root_policy_rule = "root_policy_rule"


def _derived_entry_id(kind: str, value: str) -> str:
    preimage = b"chio.revocation-entry-id.v1\x00" + kind.encode() + b"\x00" + value.encode()
    return "rev_" + hashlib.sha256(preimage).hexdigest()


class NamedRevocationEntry(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.revocation-entry.v1"] = Field(..., alias="schema")
    entry_id: constr(pattern=r"^rev_[0-9a-f]{64}$") = Field(
        ...,
        description="`rev_` and 64 lowercase hex characters, derived from `target_kind` and `target_value`; the reason is not part of it.",
    )
    target_kind: TargetKind = Field(
        ..., description="Target kinds whose value is an identifier."
    )
    target_value: constr(pattern=r"^[^\u0000]+$", min_length=1, max_length=512) = Field(
        ...,
        description="The capability id or root policy rule id: 1 to 512 NUL-free characters.",
    )
    revoked_at: conint(ge=1, le=9223372036854775807) = Field(
        ...,
        description="Unix seconds at which the first write of this entry took effect.",
    )
    reason: RevocationReason

    @model_validator(mode="after")
    def _entry_id_is_derived(self) -> "NamedRevocationEntry":
        if self.entry_id != _derived_entry_id(self.target_kind.value, self.target_value):
            raise ValueError("entry_id is not the id the target derives")
        return self


class TargetKind1(Enum):
    """
    Target kinds whose value is a 64-hex digest.
    """

    anchor_subject = "anchor_subject"
    tenant_tag = "tenant_tag"
    replay_key = "replay_key"


class TaggedRevocationEntry(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.revocation-entry.v1"] = Field(..., alias="schema")
    entry_id: constr(pattern=r"^rev_[0-9a-f]{64}$") = Field(
        ...,
        description="`rev_` and 64 lowercase hex characters, derived from `target_kind` and `target_value`; the reason is not part of it.",
    )
    target_kind: TargetKind1 = Field(
        ..., description="Target kinds whose value is a 64-hex digest."
    )
    target_value: constr(pattern=r"^[0-9a-f]{64}$") = Field(
        ...,
        description="The keyed subject tag, tenant tag or replay key digest: 64 lowercase hex characters.",
    )
    revoked_at: conint(ge=1, le=9223372036854775807) = Field(
        ...,
        description="Unix seconds at which the first write of this entry took effect.",
    )
    reason: RevocationReason

    @model_validator(mode="after")
    def _entry_id_is_derived(self) -> "TaggedRevocationEntry":
        if self.entry_id != _derived_entry_id(self.target_kind.value, self.target_value):
            raise ValueError("entry_id is not the id the target derives")
        return self


class ChioRevocationEntry(RootModel[NamedRevocationEntry | TaggedRevocationEntry]):
    root: NamedRevocationEntry | TaggedRevocationEntry = Field(
        ...,
        description="`chio.revocation-entry.v1`, unsigned. One stored revocation: its target is a closed kind and value, `entry_id` is `rev_` and the lowercase hex of SHA-256(`chio.revocation-entry-id.v1` NUL, kind, NUL, value), so retrying the same target names the same entry. A `capability_id` target revokes that capability and every descendant; the other kinds revoke every anchored root they match. Subject and tenant targets hold keyed tags, never plaintext. Operators write entries through `POST /admin/revocations` and trust-control `POST /v1/revocations`; a denial names the matching `entry_id`. A decoder also checks that `entry_id` is the id the target derives, which a schema cannot express.",
        title="Chio Revocation Entry",
    )
