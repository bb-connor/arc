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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from . import (
    semantic_action_schema,
    semantic_payload_schema,
    signed_scoped_endorsement_schema,
    signed_semantic_annotation_schema,
    signed_semantic_audience_schema,
    signed_semantic_prerequisite_schema,
    signed_semantic_transformation_schema,
)


class SemanticInvocationV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.semantic.invocation.v1"] = Field(..., alias="schema")
    action: semantic_action_schema.SemanticActionV1
    payload: semantic_payload_schema.SemanticPayloadV1
    audience: signed_semantic_audience_schema.SignedSemanticAudienceV1
    endorsements: list[signed_scoped_endorsement_schema.SignedScopedEndorsementV1] = (
        Field(..., max_length=8, min_length=0)
    )
    annotations: list[signed_semantic_annotation_schema.SignedSemanticAnnotationV1] = (
        Field(..., max_length=8, min_length=0)
    )
    transformation: (
        signed_semantic_transformation_schema.SignedSemanticTransformationV1 | None
    ) = None
    prerequisites: list[
        signed_semantic_prerequisite_schema.SignedSemanticPrerequisiteV1
    ] = Field(..., max_length=8, min_length=0)
