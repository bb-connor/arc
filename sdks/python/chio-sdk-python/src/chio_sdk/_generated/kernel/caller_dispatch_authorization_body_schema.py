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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DispatchLaunch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    native_launch: None
    worker_profile: None


class ProviderAttempt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attempt_id: str
    operation_id: str
    transport_id: str
    transport_key_epoch: int


class StoreFence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lease_id: str
    owner_epoch: int
    store_uuid: str


class DispatchCommit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_version: int
    coordinator_lease_epoch: int
    coordinator_lease_id: str
    dispatch_launch: DispatchLaunch
    provider_attempt: ProviderAttempt
    store_fence: StoreFence


class Committed(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budget_hold_id: str
    dispatch_commit: DispatchCommit
    execution_nonce_id: str
    frozen_context_digest: str


class Executor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    executor_id: str
    key_epoch: int
    public_key: str


class Invocation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_digest: str
    capability_id: str
    operation_id: str
    parameters_digest: str
    request_binding_hash: str
    request_id: str
    server_id: str
    tool_name: str


class ChioCallerDispatchAuthorizationV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed: Committed
    executor: Executor
    expires_at_unix_ms: int
    invocation: Invocation
    kernel_public_key: str
    not_before_unix_ms: int
    schema_: Literal["chio.caller-dispatch-authorization.v1"] = Field(
        ..., alias="schema"
    )
