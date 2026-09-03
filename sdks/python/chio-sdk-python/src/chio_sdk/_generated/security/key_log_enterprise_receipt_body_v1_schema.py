# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: bab930356fcbf944c42cdbdaef62cc82db4c242eee4942218590770e15ff1c0e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import key_log_witness_signature_v1_schema


class Stage(Enum):
    pending = "pending"
    active = "active"


class Outcome(Enum):
    pending_committed = "pending_committed"
    activated = "activated"


class KeyLogIdentifier(
    RootModel[constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)]
):
    root: constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)


class Hash(RootModel[constr(pattern=r"^0x[0-9a-f]{64}$")]):
    root: constr(pattern=r"^0x[0-9a-f]{64}$")


class EventSigner1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    role: Literal["bootstrap"]
    key_id: Hash


class EventSigner2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    role: Literal["old_key"]
    key_id: Hash


class EventSigner3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    role: Literal["new_key"]
    key_id: Hash


class EventSigner4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    role: Literal["recovery"]
    authorizer_id: KeyLogIdentifier


class EventSigner(RootModel[EventSigner1 | EventSigner2 | EventSigner3 | EventSigner4]):
    root: EventSigner1 | EventSigner2 | EventSigner3 | EventSigner4


class ChioKeyLogEnterpriseReceiptBodyV11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.key-log.enterprise-receipt.v1"] = Field(..., alias="schema")
    receipt_id: KeyLogIdentifier
    transaction_id: KeyLogIdentifier
    issued_at: conint(ge=1)
    log_id: KeyLogIdentifier
    event_id: KeyLogIdentifier
    event_sequence: conint(ge=0)
    event_envelope_hash: Hash
    event_signers: list[EventSigner] = Field(..., max_length=66, min_length=1)
    stage: Literal["pending"]
    tree_size: conint(ge=1)
    root_hash: Hash
    checkpoint_hash: Hash
    checkpoint_sequence: conint(ge=0)
    operator_key_id: Hash
    witness_roster_id: KeyLogIdentifier
    witness_signatures: list[
        key_log_witness_signature_v1_schema.ChioKeyLogWitnessSignatureV1
    ] = Field(..., max_length=0)
    activation_commit_hash: Hash | None = None
    signing_epoch: conint(ge=1) | None = None
    source_receipt_ids: list[KeyLogIdentifier] | None = Field(None, max_length=64)
    outcome: Literal["pending_committed"]


class ChioKeyLogEnterpriseReceiptBodyV12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.key-log.enterprise-receipt.v1"] = Field(..., alias="schema")
    receipt_id: KeyLogIdentifier
    transaction_id: KeyLogIdentifier
    issued_at: conint(ge=1)
    log_id: KeyLogIdentifier
    event_id: KeyLogIdentifier
    event_sequence: conint(ge=0)
    event_envelope_hash: Hash
    event_signers: list[EventSigner] = Field(..., max_length=66, min_length=1)
    stage: Literal["active"]
    tree_size: conint(ge=1)
    root_hash: Hash
    checkpoint_hash: Hash
    checkpoint_sequence: conint(ge=0)
    operator_key_id: Hash
    witness_roster_id: KeyLogIdentifier
    witness_signatures: list[
        key_log_witness_signature_v1_schema.ChioKeyLogWitnessSignatureV1
    ] = Field(..., max_length=64, min_length=1)
    activation_commit_hash: Hash
    signing_epoch: conint(ge=1)
    source_receipt_ids: list[KeyLogIdentifier] = Field(..., max_length=1, min_length=1)
    outcome: Literal["activated"]


class ChioKeyLogEnterpriseReceiptBodyV1(
    RootModel[ChioKeyLogEnterpriseReceiptBodyV11 | ChioKeyLogEnterpriseReceiptBodyV12]
):
    root: ChioKeyLogEnterpriseReceiptBodyV11 | ChioKeyLogEnterpriseReceiptBodyV12 = (
        Field(..., title="Chio key-log enterprise receipt body v1")
    )
