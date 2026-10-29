# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class DelegationRecord(BaseModel):
    pass


class GraphRecord(BaseModel):
    pass


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


class PolicyGeneration(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)


class RecoveryDigest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title="Recovery digest octet")


class RecoveryDigest32(RootModel[list[RecoveryDigest32Item]]):
    root: list[RecoveryDigest32Item] = Field(
        ..., max_length=32, min_length=32, title="Recovery digest32"
    )


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class WorkDigest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class WorkId(
    RootModel[
        constr(
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
        )
    ]
):
    root: constr(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
    )


class WorkSlotId(
    RootModel[
        constr(pattern=r"^[A-Za-z0-9._:/-]{1,256}$", min_length=1, max_length=256)
    ]
):
    root: constr(pattern=r"^[A-Za-z0-9._:/-]{1,256}$", min_length=1, max_length=256)


class Proposal(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["delegate"]
    parent_id: WorkSlotId
    parent_allocation_hash: WorkDigest
    child: DelegationRecord


class Proposal2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["select"]
    offer: DelegationRecord
    request_id: OpaqueId
    capability_hash: WorkDigest
    expected_revision: SafeInteger


class Terms(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unpaid"]
    terms_reference: WorkId


class Terms29(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["funded"]
    funding_profile_id: WorkId
    terms_reference: WorkId


class Action(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["delegate"]
    subdivision: DelegationRecord


class Action5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["select"]
    selection: DelegationRecord


class Action6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["seal"]
    binding: DelegationRecord


class CatalogCursor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    catalog_generation: PolicyGeneration
    position: WorkDigest


class CatalogRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    owner: WorkId
    catalog_id: WorkId


class CommandRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    program_id: WorkId
    command_id: WorkId
    command_digest: WorkDigest


class DraftRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    draft_id: WorkId
    graph_sha256: WorkDigest


class FundingRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    rail: WorkId
    agreement_digest: WorkDigest
    reserve_ref: WorkId


class Handle(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    program_id: WorkId
    slot_id: WorkSlotId
    allocation_hash: WorkDigest
    receiver_kernel_id: WorkId
    request_id: OpaqueId


class PreparationRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    program_id: WorkId
    preparation_id: WorkId
    command_digest: WorkDigest


class ProfileRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    owner: WorkId
    catalog_entry: WorkId
    deployment_digest: RecoveryDigest32
    policy_generation: PolicyGeneration
    profile_digest: RecoveryDigest32


class Proposal1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["offer"]
    slot_id: WorkSlotId
    allocation_hash: WorkDigest
    profile_ref: ProfileRef
    receiver_kernel_id: WorkId
    server_id: WorkId
    tool_name: WorkId
    arguments: Any
    request_id: OpaqueId


class NewWorkItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    task_id: WorkId
    handle: Handle


class Proposal3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["extend"]
    expected_bundle_sha256: WorkDigest
    new_work: list[NewWorkItem] = Field(..., max_length=16)
    dependencies: list[GraphRecord] = Field(..., max_length=64)
    join_draft_refs: list[DraftRef] = Field(..., max_length=16)


class Proposal4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["join"]
    expected_bundle_sha256: WorkDigest
    join: GraphRecord
    parents: list[Handle] = Field(..., max_length=16)


class Action7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["extend"]
    expected_bundle_sha256: WorkDigest
    draft_ref: DraftRef


class Action9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["reconcile"]
    handle: Handle


class Action10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["cancel"]
    handle: Handle


class Query(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["work"]
    handle: Handle


class Query25(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["command"]
    command_ref: CommandRef


class Query26(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["preparation"]
    preparation_ref: PreparationRef


class Query27(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["catalog"]
    catalog_ref: CatalogRef
    cursor: CatalogCursor | None = None


class Query28(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["profile"]
    profile_ref: ProfileRef


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["query"]
    query: Query | Query25 | Query26 | Query27 | Query28


class Commitment(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    handle: Handle
    permit: DelegationRecord
    profile_ref: ProfileRef
    invocation_ref: WorkDigest
    graph_ref: WorkDigest
    funding: FundingRef | None = None


class Proposal5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["agreement"]
    commitment: Commitment
    terms: Terms | Terms29


class Preparation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.work.preparation.v1"] = Field(..., alias="schema")
    version: Literal[1]
    program_id: WorkId
    command_id: WorkId
    proposal: Proposal | Proposal1 | Proposal2 | Proposal3 | Proposal4 | Proposal5


class Body205(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["prepare"]
    preparation: Preparation


class Action8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["submit"]
    commitment: Commitment


class Command(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.work.command.v1"] = Field(..., alias="schema")
    version: Literal[1]
    program_id: WorkId
    command_id: WorkId
    action: Action | Action5 | Action6 | Action7 | Action8 | Action9 | Action10


class Body206(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["submit"]
    command: Command


class WorkRequestV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.work.request.v1"] = Field(..., alias="schema")
    version: Literal[1]
    body: Body205 | Body206 | Body
