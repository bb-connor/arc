# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 87aeeadf1295c6ed5c56ce7813afa5a254c07827c1029566566991a30ebeb7d7
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from . import (
    cage_enforcement_prepared_v1_schema,
    cage_exec_transition_observed_v1_schema,
)


class ChioCageFullyEnforcedEvidenceV1(BaseModel):
    """
    Composite evidence requiring a prepared confinement record, the matching observed target exec transition, and EOF on the private helper status channel.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    prepared: cage_enforcement_prepared_v1_schema.ChioCageEnforcementPreparedEvidenceV1
    exec_transition: (
        cage_exec_transition_observed_v1_schema.ChioCageExecTransitionObservationV1
    )
    status_eof_observed: Literal[True]
