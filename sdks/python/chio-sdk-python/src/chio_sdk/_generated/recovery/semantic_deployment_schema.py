# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b1327961d337a6880e1c267862d3778078a72c85788c98de91fd5bb2d4c74079
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


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
    process_id: OpaqueId
    tenant_id: OpaqueId


class SemanticAnnotator(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    facts: list[OpaqueId] = Field(..., max_length=8, min_length=0)
    key: RecoveryDigest32
    may_attest_facts: bool


class SemanticOverride(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    fixture_digests: list[RecoveryDigest32] = Field(..., max_length=8, min_length=1)
    reason: constr(min_length=1, max_length=512)
    selector_index: SafeInteger


class SemanticSelector1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field: OpaqueId
    kind: Literal["present"]


class SemanticSelector3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bytes: SafeInteger
    field: OpaqueId
    kind: Literal["text_bytes_at_most"]


class SemanticValue1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["text"]
    value: constr(min_length=1, max_length=4096)


class SemanticValue2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["integer"]
    value: SafeInteger


class SemanticValue3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["boolean"]
    value: bool


class SemanticValue(RootModel[SemanticValue1 | SemanticValue2 | SemanticValue3]):
    root: SemanticValue1 | SemanticValue2 | SemanticValue3


class SemanticDestination(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    account: OpaqueId
    acl_query: RecoveryDigest32
    audience: information_label_schema.InformationLabel
    destination: OpaqueId
    endpoint: constr(min_length=1, max_length=2048)
    provider: OpaqueId
    purpose: constr(min_length=1, max_length=256)
    require_provider_precondition: bool
    resource: OpaqueId
    subject_mapping: RecoveryDigest32


class SemanticSelector2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field: OpaqueId
    kind: Literal["equals"]
    value: SemanticValue


class SemanticSelector(
    RootModel[SemanticSelector1 | SemanticSelector2 | SemanticSelector3]
):
    root: SemanticSelector1 | SemanticSelector2 | SemanticSelector3


class SemanticRoute(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    annotators: list[SemanticAnnotator] = Field(..., max_length=16, min_length=0)
    destinations: list[SemanticDestination] = Field(..., max_length=16, min_length=1)
    endorsement_key: RecoveryDigest32
    implementation: RecoveryDigest32
    input_schema: RecoveryDigest32
    operation: OpaqueId
    operator_selectors: list[SemanticSelector] = Field(..., max_length=16, min_length=0)
    output_schema: RecoveryDigest32
    package: RecoveryDigest32
    prerequisite_key: RecoveryDigest32
    resolver_key: RecoveryDigest32
    reviewed_overrides: list[SemanticOverride] = Field(..., max_length=16, min_length=0)
    server: constr(min_length=1, max_length=128)
    tool: constr(min_length=1, max_length=128)
    transformation_key: RecoveryDigest32


class SemanticDeploymentV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    context_binding: RecoveryDigest32
    domain_version: Literal[1]
    exposure_binding: RecoveryDigest32
    generation: conint(ge=1, le=9007199254740991)
    native_binding: RecoveryDigest32
    packages: list[RecoveryDigest32] = Field(..., max_length=16, min_length=1)
    routes: list[SemanticRoute] = Field(..., max_length=16, min_length=1)
    scope: Scope
