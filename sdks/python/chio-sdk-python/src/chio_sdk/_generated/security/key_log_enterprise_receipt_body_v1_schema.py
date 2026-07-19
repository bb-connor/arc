# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import key_log_witness_signature_v1_schema


class Outcome(Enum):
    pending_committed = "pending_committed"
    activated = "activated"


class Stage(Enum):
    pending = "pending"
    active = "active"


class Hash(RootModel[str]):
    root: Annotated[str, Field(pattern="^0x[0-9a-f]{64}$")]


class KeyLogIdentifier(RootModel[str]):
    root: Annotated[
        str, Field(max_length=128, min_length=1, pattern="^[A-Za-z0-9._:/-]+$")
    ]


class EventSigner1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    key_id: Hash
    role: Literal["bootstrap"]


class EventSigner2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    key_id: Hash
    role: Literal["old_key"]


class EventSigner3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    key_id: Hash
    role: Literal["new_key"]


class EventSigner4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorizer_id: KeyLogIdentifier
    role: Literal["recovery"]


class EventSigner(RootModel[EventSigner1 | EventSigner2 | EventSigner3 | EventSigner4]):
    root: EventSigner1 | EventSigner2 | EventSigner3 | EventSigner4


class ChioKeyLogEnterpriseReceiptBodyV11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activation_commit_hash: Hash | None = None
    checkpoint_hash: Hash
    checkpoint_sequence: Annotated[int, Field(ge=0)]
    event_envelope_hash: Hash
    event_id: KeyLogIdentifier
    event_sequence: Annotated[int, Field(ge=0)]
    event_signers: Annotated[list[EventSigner], Field(max_length=66, min_length=1)]
    issued_at: Annotated[int, Field(ge=1)]
    log_id: KeyLogIdentifier
    operator_key_id: Hash
    outcome: Literal["pending_committed"]
    receipt_id: KeyLogIdentifier
    root_hash: Hash
    schema_: Annotated[
        Literal["chio.key-log.enterprise-receipt.v1"], Field(alias="schema")
    ]
    signing_epoch: Annotated[int | None, Field(ge=1)] = None
    source_receipt_ids: Annotated[
        list[KeyLogIdentifier] | None, Field(max_length=64)
    ] = None
    stage: Literal["pending"]
    transaction_id: KeyLogIdentifier
    tree_size: Annotated[int, Field(ge=1)]
    witness_roster_id: KeyLogIdentifier
    witness_signatures: Annotated[
        list[key_log_witness_signature_v1_schema.ChioKeyLogWitnessSignatureV1],
        Field(max_length=0),
    ]


class ChioKeyLogEnterpriseReceiptBodyV12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activation_commit_hash: Hash
    checkpoint_hash: Hash
    checkpoint_sequence: Annotated[int, Field(ge=0)]
    event_envelope_hash: Hash
    event_id: KeyLogIdentifier
    event_sequence: Annotated[int, Field(ge=0)]
    event_signers: Annotated[list[EventSigner], Field(max_length=66, min_length=1)]
    issued_at: Annotated[int, Field(ge=1)]
    log_id: KeyLogIdentifier
    operator_key_id: Hash
    outcome: Literal["activated"]
    receipt_id: KeyLogIdentifier
    root_hash: Hash
    schema_: Annotated[
        Literal["chio.key-log.enterprise-receipt.v1"], Field(alias="schema")
    ]
    signing_epoch: Annotated[int, Field(ge=1)]
    source_receipt_ids: Annotated[
        list[KeyLogIdentifier], Field(max_length=1, min_length=1)
    ]
    stage: Literal["active"]
    transaction_id: KeyLogIdentifier
    tree_size: Annotated[int, Field(ge=1)]
    witness_roster_id: KeyLogIdentifier
    witness_signatures: Annotated[
        list[key_log_witness_signature_v1_schema.ChioKeyLogWitnessSignatureV1],
        Field(max_length=64, min_length=1),
    ]


class ChioKeyLogEnterpriseReceiptBodyV1(
    RootModel[ChioKeyLogEnterpriseReceiptBodyV11 | ChioKeyLogEnterpriseReceiptBodyV12]
):
    root: Annotated[
        ChioKeyLogEnterpriseReceiptBodyV11 | ChioKeyLogEnterpriseReceiptBodyV12,
        Field(title="Chio key-log enterprise receipt body v1"),
    ]
