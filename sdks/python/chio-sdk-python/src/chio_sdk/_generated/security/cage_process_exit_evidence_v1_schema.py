# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel


class ExitCode(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class ExitCode1(RootModel[None]):
    root: Annotated[None, Field(ge=0, le=255)]


class Signal(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=64)]


class ChioCageProcessExitEvidenceV11(BaseModel):
    """
    Terminal process observation carrying exactly one normal exit code or terminating signal.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    exit_code: ExitCode | ExitCode1
    exited_at_unix_ms: Annotated[int, Field(ge=1, le=18446744073709551615)]
    process_id: Annotated[int, Field(ge=1, le=4294967295)]
    signal: Signal | None = None


class ExitCode2(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Signal2(RootModel[None]):
    root: Annotated[None, Field(ge=1, le=64)]


class ChioCageProcessExitEvidenceV12(BaseModel):
    """
    Terminal process observation carrying exactly one normal exit code or terminating signal.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    exit_code: ExitCode2 | None = None
    exited_at_unix_ms: Annotated[int, Field(ge=1, le=18446744073709551615)]
    process_id: Annotated[int, Field(ge=1, le=4294967295)]
    signal: Signal | Signal2


class ChioCageProcessExitEvidenceV1(
    RootModel[ChioCageProcessExitEvidenceV11 | ChioCageProcessExitEvidenceV12]
):
    root: Annotated[
        ChioCageProcessExitEvidenceV11 | ChioCageProcessExitEvidenceV12,
        Field(
            description="Terminal process observation carrying exactly one normal exit code or terminating signal.",
            title="Chio cage process-exit evidence v1",
        ),
    ]
