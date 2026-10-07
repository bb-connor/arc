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
from typing import Literal
from pydantic import BaseModel, ConfigDict, constr

class ErrorPolicyDeniedDetail(BaseModel):
    model_config = ConfigDict(extra='forbid')
    guard: constr(min_length=1)
    reason: constr(min_length=1)

class ChioToolCallErrorPolicyDenied(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: Literal['policy_denied']
    detail: ErrorPolicyDeniedDetail

# Public compatibility aliases reference the actual current model classes.
ChioToolcallerrorPolicyDenied = ChioToolCallErrorPolicyDenied
Detail = ErrorPolicyDeniedDetail
ErrorPolicyDeniedChioToolCallErrorPolicyDenied = ChioToolCallErrorPolicyDenied
