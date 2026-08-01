# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..receipt import record_schema
from . import execution_nonce_schema


class Result(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["ok"]
    value: Any


class Result2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["stream_complete"]
    total_chunks: Annotated[int, Field(ge=0)]


class Result3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chunks_received: Annotated[int, Field(ge=0)]
    reason: Annotated[str, Field(min_length=1)]
    status: Literal["cancelled"]


class Result4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chunks_received: Annotated[int, Field(ge=0)]
    reason: Annotated[str, Field(min_length=1)]
    status: Literal["incomplete"]


class Error(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_denied"]
    detail: Annotated[str, Field(min_length=1)]


class Error9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_expired"]


class Error10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_revoked"]


class Detail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guard: Annotated[str, Field(min_length=1)]
    reason: Annotated[str, Field(min_length=1)]


class Error11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["policy_denied"]
    detail: Detail


class Error12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["tool_server_error"]
    detail: Annotated[str, Field(min_length=1)]


class Error13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["internal_error"]
    detail: Annotated[str, Field(min_length=1)]


class Result5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    error: Error | Error9 | Error10 | Error11 | Error12 | Error13
    status: Literal["err"]


class ChioKernelmessageToolCallResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    execution_nonce: execution_nonce_schema.ChioSignedExecutionNonce | None = None
    id: Annotated[str, Field(min_length=1)]
    receipt: record_schema.ChioReceiptRecord
    result: Result | Result2 | Result3 | Result4 | Result5
    type: Literal["tool_call_response"]
