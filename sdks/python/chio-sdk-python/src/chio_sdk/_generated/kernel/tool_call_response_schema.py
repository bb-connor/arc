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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, conint, constr

from ..receipt import record_schema
from ..result import pending_approval_schema
from . import execution_nonce_schema


class Result(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["ok"]
    value: Any


class Result23(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["stream_complete"]
    total_chunks: conint(ge=0)


class Result24(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["cancelled"]
    reason: constr(min_length=1)
    chunks_received: conint(ge=0)


class Result25(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["incomplete"]
    reason: constr(min_length=1)
    chunks_received: conint(ge=0)


class Error(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_denied"]
    detail: constr(min_length=1)


class Error10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_expired"]


class Error11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_revoked"]


class Detail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guard: constr(min_length=1)
    reason: constr(min_length=1)


class Error12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["policy_denied"]
    detail: Detail


class Error13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["tool_server_error"]
    detail: constr(min_length=1)


class Error14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["internal_error"]
    detail: constr(min_length=1)


class Result26(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["err"]
    error: Error | Error10 | Error11 | Error12 | Error13 | Error14


class ChioKernelmessageToolCallResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["tool_call_response"]
    id: constr(min_length=1)
    result: (
        Result
        | Result23
        | Result24
        | Result25
        | Result26
        | pending_approval_schema.ChioToolcallresultPendingApproval
    )
    receipt: record_schema.ChioReceiptRecord
    execution_nonce: execution_nonce_schema.ChioSignedExecutionNonce | None = None
