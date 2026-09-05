# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9695e2b405d3cd46de929a925e1a3b9b33ec4a67a0a5e93f625c433f820e1920
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import (
    cage_enforcement_failure_v1_schema,
    cage_fully_enforced_evidence_v1_schema,
    cage_process_exit_evidence_v1_schema,
)


class State(Enum):
    unsupported = "unsupported"
    rejected = "rejected"
    bootstrap_failed = "bootstrap_failed"
    fully_enforced = "fully_enforced"
    exited = "exited"


class State2(Enum):
    unsupported = "unsupported"
    rejected = "rejected"
    bootstrap_failed = "bootstrap_failed"
    fully_enforced = "fully_enforced"
    exited = "exited"
    unsupported_1 = "unsupported"
    rejected_1 = "rejected"
    bootstrap_failed_1 = "bootstrap_failed"


class ChioCageEnforcementRecordV11(BaseModel):
    """
    Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cage.enforcement-record.v1"] = Field(..., alias="schema")
    state: Literal["fully_enforced"]
    fully_enforced: (
        cage_fully_enforced_evidence_v1_schema.ChioCageFullyEnforcedEvidenceV1
    )
    failure: cage_enforcement_failure_v1_schema.ChioCageEnforcementFailureV1 | None = (
        None
    )
    exit: cage_process_exit_evidence_v1_schema.ChioCageProcessExitEvidenceV1 | None = (
        None
    )


class ChioCageEnforcementRecordV12(BaseModel):
    """
    Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cage.enforcement-record.v1"] = Field(..., alias="schema")
    state: Literal["exited"]
    fully_enforced: (
        cage_fully_enforced_evidence_v1_schema.ChioCageFullyEnforcedEvidenceV1
    )
    failure: cage_enforcement_failure_v1_schema.ChioCageEnforcementFailureV1 | None = (
        None
    )
    exit: cage_process_exit_evidence_v1_schema.ChioCageProcessExitEvidenceV1


class ChioCageEnforcementRecordV13(BaseModel):
    """
    Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cage.enforcement-record.v1"] = Field(..., alias="schema")
    state: State2
    fully_enforced: (
        cage_fully_enforced_evidence_v1_schema.ChioCageFullyEnforcedEvidenceV1 | None
    ) = None
    failure: cage_enforcement_failure_v1_schema.ChioCageEnforcementFailureV1
    exit: cage_process_exit_evidence_v1_schema.ChioCageProcessExitEvidenceV1 | None = (
        None
    )


class ChioCageEnforcementRecordV1(
    RootModel[
        ChioCageEnforcementRecordV11
        | ChioCageEnforcementRecordV12
        | ChioCageEnforcementRecordV13
    ]
):
    root: (
        ChioCageEnforcementRecordV11
        | ChioCageEnforcementRecordV12
        | ChioCageEnforcementRecordV13
    ) = Field(
        ...,
        description="Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.",
        title="Chio cage enforcement record v1",
    )
