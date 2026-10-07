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
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint

class SecurityCageProcessExitEvidenceV1ExitCode(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class SecurityCageProcessExitEvidenceV1ExitCode1(RootModel[None]):
    root: None

class SecurityCageProcessExitEvidenceV1Variant0(BaseModel):
    """
    Terminal process observation carrying exactly one normal exit code or terminating signal.
    """
    model_config = ConfigDict(extra='forbid')
    process_id: conint(ge=1, le=4294967295)
    exit_code: SecurityCageProcessExitEvidenceV1ExitCode | SecurityCageProcessExitEvidenceV1ExitCode1
    signal: conint(ge=1, le=64) | None = None
    exited_at_unix_ms: conint(ge=1, le=18446744073709551615)

class SecurityCageProcessExitEvidenceV1Signal(RootModel[conint(ge=1, le=64)]):
    root: conint(ge=1, le=64)

class SecurityCageProcessExitEvidenceV1Signal1(RootModel[None]):
    root: None

class SecurityCageProcessExitEvidenceV1Variant1(BaseModel):
    """
    Terminal process observation carrying exactly one normal exit code or terminating signal.
    """
    model_config = ConfigDict(extra='forbid')
    process_id: conint(ge=1, le=4294967295)
    exit_code: conint(ge=0, le=255) | None = None
    signal: SecurityCageProcessExitEvidenceV1Signal | SecurityCageProcessExitEvidenceV1Signal1
    exited_at_unix_ms: conint(ge=1, le=18446744073709551615)

class ChioCageProcessExitEvidenceV1(RootModel[SecurityCageProcessExitEvidenceV1Variant0 | SecurityCageProcessExitEvidenceV1Variant1]):
    root: SecurityCageProcessExitEvidenceV1Variant0 | SecurityCageProcessExitEvidenceV1Variant1 = Field(..., description='Terminal process observation carrying exactly one normal exit code or terminating signal.', title='Chio cage process-exit evidence v1')

# Public compatibility aliases reference the actual current model classes.
ChioCageProcessExitEvidenceV11 = SecurityCageProcessExitEvidenceV1Variant0
ChioCageProcessExitEvidenceV12 = SecurityCageProcessExitEvidenceV1Variant1
ExitCode = SecurityCageProcessExitEvidenceV1ExitCode
ExitCode1 = SecurityCageProcessExitEvidenceV1ExitCode1
SecurityCageProcessExitEvidenceV1ChioCageProcessExitEvidenceV1 = ChioCageProcessExitEvidenceV1
Signal = SecurityCageProcessExitEvidenceV1Signal
Signal1 = SecurityCageProcessExitEvidenceV1Signal1
