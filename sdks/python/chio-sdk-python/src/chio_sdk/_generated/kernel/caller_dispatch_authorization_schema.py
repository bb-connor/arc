# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from chio_sdk._manifest_wire import SecurityWireModel as BaseModel
from pydantic import BaseModel as DispatchLaunchBaseModel

from pydantic import ConfigDict, Field, RootModel, conint, constr


class CallerSignature(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )


class CallerIdentifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512) = Field(
        ...,
        description="The kernel additionally bounds UTF-8 bytes and rejects control characters and surrounding whitespace.",
    )


class CallerDigest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class CallerPositiveInteger(RootModel[conint(strict=True, ge=1, le=9007199254740991)]):
    root: conint(strict=True, ge=1, le=9007199254740991)


class NativeLaunch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    receipt_id: CallerDigest
    receipt_sha256: CallerDigest


class LaunchRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    record_id: CallerDigest
    record_sha256: CallerDigest


class WorkerProfile(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["container"]
    launch_attempt: conint(strict=True, ge=1, le=4294967295)
    launch_ref: LaunchRef


class CallerDispatchLaunch(DispatchLaunchBaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    native_launch: NativeLaunch | None = Field(...)
    worker_profile: WorkerProfile | None = Field(...)


class CallerPublicKey(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )


class CallerExecutor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    executor_id: CallerIdentifier
    public_key: CallerPublicKey
    key_epoch: CallerPositiveInteger


class Invocation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operation_id: CallerDigest
    request_id: CallerIdentifier
    request_binding_hash: CallerDigest
    capability_id: CallerIdentifier
    capability_digest: CallerDigest
    server_id: CallerIdentifier
    tool_name: CallerIdentifier
    parameters_digest: CallerDigest


class StoreFence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    store_uuid: CallerIdentifier
    lease_id: CallerIdentifier
    owner_epoch: CallerPositiveInteger


class ProviderAttempt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operation_id: CallerDigest
    attempt_id: CallerIdentifier
    transport_id: constr(
        pattern=r"^(caller-report:|native-caller-report:v1:)",
        min_length=15,
        max_length=512,
    )
    transport_key_epoch: CallerPositiveInteger


class DispatchCommit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_version: CallerPositiveInteger
    coordinator_lease_id: CallerIdentifier
    coordinator_lease_epoch: CallerPositiveInteger
    store_fence: StoreFence
    provider_attempt: ProviderAttempt
    dispatch_launch: CallerDispatchLaunch


class Committed(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    execution_nonce_id: CallerIdentifier
    budget_hold_id: CallerIdentifier
    frozen_context_digest: CallerDigest
    dispatch_commit: DispatchCommit


class Authorization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.caller-dispatch-authorization.v1"] = Field(
        ..., alias="schema"
    )
    kernel_public_key: CallerPublicKey
    executor: CallerExecutor
    invocation: Invocation
    committed: Committed
    not_before_unix_ms: CallerPositiveInteger
    expires_at_unix_ms: CallerPositiveInteger


class ChioSignedCallerDispatchAuthorization(BaseModel):
    """
    A committed kernel statement, not an executor claim. Canonical encoding is bounded to 32768 bytes. The executor must independently authenticate pins and durably claim the original operation before effect.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    authorization: Authorization
    signature: CallerSignature
