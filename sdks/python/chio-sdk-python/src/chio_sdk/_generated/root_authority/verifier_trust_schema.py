# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 06789f7cc8fb9ed55f9aba55aadcbf4ec7c60d519627433209cdf916fda34f0d
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, constr

from . import root_anchor_schema


class RequiredColumn(Enum):
    identity_root = "identity_root"
    delegation_chain = "delegation_chain"
    decision = "decision"
    content = "content"
    settlement = "settlement"


class Kind(Enum):
    local_log = "local_log"
    transparency_service = "transparency_service"
    immutable_record = "immutable_record"
    chain_anchor = "chain_anchor"


class PublicationIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind
    identity: constr(min_length=1, max_length=2048)


class Kind20(Enum):
    operator_root = "operator_root"
    did = "did"
    x509_root = "x509_root"
    transparency_root = "transparency_root"
    chain_root = "chain_root"


class TrustAnchorIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind20
    identity: constr(min_length=1, max_length=2048)


class CheckpointTrustAnchorBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    publicationIdentity: PublicationIdentity
    trustAnchorIdentity: TrustAnchorIdentity
    trustAnchorRef: constr(min_length=1, max_length=2048)
    signerCertRef: constr(min_length=1, max_length=2048)
    publicationProfileVersion: constr(min_length=1, max_length=2048)


class ChioVerifierTrust(BaseModel):
    """
    `chio.verifier-trust.v1`: a local, unsigned file the verifying party writes and controls. It pins the keys a verifier accepts and the report columns that must be `verified`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.verifier-trust.v1"] = Field(..., alias="schema")
    kernel_keys: list[root_anchor_schema.PublicKeyHex] = Field(
        ..., max_length=64, min_length=1
    )
    exchange_keys: list[root_anchor_schema.PublicKeyHex] = Field(
        ...,
        description="Keys that may sign anchored roots.",
        max_length=64,
        min_length=0,
    )
    root_policy_keys: list[root_anchor_schema.PublicKeyHex] = Field(
        ...,
        description="Keys that may sign root policies.",
        max_length=64,
        min_length=0,
    )
    idp_keys: dict[str, list[root_anchor_schema.Jwk]] | None = Field(
        None,
        description="Issuer to the identity-provider keys the verifier pins itself.",
    )
    pep_keys: dict[str, root_anchor_schema.PublicKeyHex] | None = Field(
        None, description="Policy enforcement point id to its pinned key."
    )
    checkpoint_keys: list[root_anchor_schema.PublicKeyHex] | None = Field(
        None, max_length=64
    )
    checkpoint_trust_anchor: CheckpointTrustAnchorBinding | None = Field(
        None,
        description="The checkpoint publication binding the verifier accepts as a trust anchor. Absent: publication claims stay transparency previews.",
    )
    required_columns: list[RequiredColumn] | None = Field(None, max_length=5)
