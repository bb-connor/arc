# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: d2b29cbbc9a0070d3666a33fd5a06bbda07a8e70f6d54bf33c15ca8b74893ff9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, ConfigDict, constr

class ResultErrErrorVariant0(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['capability_denied']
    detail: constr(min_length=1)

class ResultErrErrorVariant1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['capability_expired']

class ResultErrErrorVariant2(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['capability_revoked']

class ResultErrErrorVariant3Detail(BaseModel):
    model_config = ConfigDict(extra='forbid')
    guard: constr(min_length=1)
    reason: constr(min_length=1)

class ResultErrErrorVariant3(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['policy_denied']
    detail: ResultErrErrorVariant3Detail

class ResultErrErrorVariant4(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['tool_server_error']
    detail: constr(min_length=1)

class ResultErrErrorVariant5(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['internal_error']
    detail: constr(min_length=1)

class ChioToolCallResultErr(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['err']
    error: ResultErrErrorVariant0 | ResultErrErrorVariant1 | ResultErrErrorVariant2 | ResultErrErrorVariant3 | ResultErrErrorVariant4 | ResultErrErrorVariant5

# Public compatibility aliases reference the actual current model classes.
ChioToolcallresultErr = ChioToolCallResultErr
Detail = ResultErrErrorVariant3Detail
Error = ResultErrErrorVariant0
Error1 = ResultErrErrorVariant1
Error2 = ResultErrErrorVariant2
Error3 = ResultErrErrorVariant3
Error4 = ResultErrErrorVariant4
Error5 = ResultErrErrorVariant5
ResultErrChioToolCallResultErr = ChioToolCallResultErr
