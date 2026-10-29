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

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint


class ExitCode(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class ExitCode1(RootModel[None]):
    root: None


class ChioCageProcessExitEvidenceV11(BaseModel):
    """
    Terminal process observation carrying exactly one normal exit code or terminating signal.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    process_id: conint(ge=1, le=4294967295)
    exit_code: ExitCode | ExitCode1
    signal: conint(ge=1, le=64) | None = None
    exited_at_unix_ms: conint(ge=1, le=18446744073709551615)


class Signal(RootModel[conint(ge=1, le=64)]):
    root: conint(ge=1, le=64)


class Signal1(RootModel[None]):
    root: None


class ChioCageProcessExitEvidenceV12(BaseModel):
    """
    Terminal process observation carrying exactly one normal exit code or terminating signal.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    process_id: conint(ge=1, le=4294967295)
    exit_code: conint(ge=0, le=255) | None = None
    signal: Signal | Signal1
    exited_at_unix_ms: conint(ge=1, le=18446744073709551615)


class ChioCageProcessExitEvidenceV1(
    RootModel[ChioCageProcessExitEvidenceV11 | ChioCageProcessExitEvidenceV12]
):
    root: ChioCageProcessExitEvidenceV11 | ChioCageProcessExitEvidenceV12 = Field(
        ...,
        description="Terminal process observation carrying exactly one normal exit code or terminating signal.",
        title="Chio cage process-exit evidence v1",
    )
