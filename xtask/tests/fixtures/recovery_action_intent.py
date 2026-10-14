# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 727bbe00c61147790088d6773d308b57a11a6cc87415eab079f58e191be383d8
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import authorization_requirements_schema, observation_schema


class OpaqueId(
    RootModel[
        constr(
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
        )
    ]
):
    root: constr(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
    )


class RecoveryDigest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title="Recovery digest octet")


class RecoveryDigest32(RootModel[list[RecoveryDigest32Item]]):
    root: list[RecoveryDigest32Item] = Field(
        ..., max_length=32, min_length=32, title="Recovery digest32"
    )


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId


class Origin(BaseModel):
    """
    Verified original effect-free denial. Historical actions may omit this field; fresh native recovery authorization requires it.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    operation: observation_schema.Operation
    request_id: OpaqueId
    closure: OpaqueId


class RecoveryExactActionIntentV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.recovery.action-intent.v1"] = Field(..., alias="schema")
    version: Literal[1]
    workflow_id: OpaqueId
    step_id: OpaqueId
    continuation_id: OpaqueId
    request_id: OpaqueId
    origin: Origin | None = Field(
        None,
        description="Verified original effect-free denial. Historical actions may omit this field; fresh native recovery authorization requires it.",
    )
    isolation_lineage: OpaqueId
    scope: Scope
    capability_id: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=256,
    )
    authorization_requirements: (
        authorization_requirements_schema.RecoveryAuthorizationRequirementsV1
    )
    request_namespace: RecoveryDigest32
    capability_body: RecoveryDigest32
    semantic_request: RecoveryDigest32
    policy_digest: RecoveryDigest32
    contract_digest: RecoveryDigest32
    authority_scope: RecoveryDigest32
    basis: RecoveryDigest32
    output_disposition: RecoveryDigest32
    source_generation: SafeInteger
    isolation_epoch: SafeInteger
