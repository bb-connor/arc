# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 35f8e30cf30553986a159b074ee485804a85db29547a8102522cd7bfa3080d2e
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

class KernelToolCallResponseResultOk(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['ok']
    value: Any

class KernelToolCallResponseResultStreamComplete(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['stream_complete']
    total_chunks: conint(ge=0)

class KernelToolCallResponseResultCancelled(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['cancelled']
    reason: constr(min_length=1)
    chunks_received: conint(ge=0)

class KernelToolCallResponseResultIncomplete(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['incomplete']
    reason: constr(min_length=1)
    chunks_received: conint(ge=0)

class KernelToolCallResponseResultErrErrorVariant0(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['capability_denied']
    detail: constr(min_length=1)

class KernelToolCallResponseResultErrErrorVariant1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['capability_expired']

class KernelToolCallResponseResultErrErrorVariant2(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['capability_revoked']

class KernelToolCallResponseResultErrErrorVariant3Detail(BaseModel):
    model_config = ConfigDict(extra='forbid')
    guard: constr(min_length=1)
    reason: constr(min_length=1)

class KernelToolCallResponseResultErrErrorVariant3(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['policy_denied']
    detail: KernelToolCallResponseResultErrErrorVariant3Detail

class KernelToolCallResponseResultErrErrorVariant4(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['tool_server_error']
    detail: constr(min_length=1)

class KernelToolCallResponseResultErrErrorVariant5(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['internal_error']
    detail: constr(min_length=1)

class KernelToolCallResponseResultErr(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['err']
    error: KernelToolCallResponseResultErrErrorVariant0 | KernelToolCallResponseResultErrErrorVariant1 | KernelToolCallResponseResultErrErrorVariant2 | KernelToolCallResponseResultErrErrorVariant3 | KernelToolCallResponseResultErrErrorVariant4 | KernelToolCallResponseResultErrErrorVariant5

class ChioKernelMessageToolCallResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['tool_call_response']
    id: constr(min_length=1)
    result: KernelToolCallResponseResultOk | KernelToolCallResponseResultStreamComplete | KernelToolCallResponseResultCancelled | KernelToolCallResponseResultIncomplete | KernelToolCallResponseResultErr | pending_approval_schema.ChioToolCallResultPendingApproval
    receipt: record_schema.ChioReceiptRecord
    execution_nonce: execution_nonce_schema.ChioSignedExecutionNonce | None = None

# Public compatibility aliases reference the actual current model classes.
ChioKernelmessageToolCallResponse = ChioKernelMessageToolCallResponse
Detail = KernelToolCallResponseResultErrErrorVariant3Detail
Error = KernelToolCallResponseResultErrErrorVariant0
Error10 = KernelToolCallResponseResultErrErrorVariant2
Error11 = KernelToolCallResponseResultErrErrorVariant3
Error12 = KernelToolCallResponseResultErrErrorVariant4
Error13 = KernelToolCallResponseResultErrErrorVariant5
Error9 = KernelToolCallResponseResultErrErrorVariant1
KernelToolCallResponseChioKernelMessageToolCallResponse = ChioKernelMessageToolCallResponse
Result = KernelToolCallResponseResultOk
Result3 = KernelToolCallResponseResultStreamComplete
Result4 = KernelToolCallResponseResultCancelled
Result5 = KernelToolCallResponseResultIncomplete
Result6 = KernelToolCallResponseResultErr
