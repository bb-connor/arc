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

from pydantic import BaseModel, ConfigDict, Field

from . import response_state_transition_receipt_body_v1_schema


class ChioCorrelatedFindingReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    finding_hash: response_state_transition_receipt_body_v1_schema.Digest
    finding_id: response_state_transition_receipt_body_v1_schema.Identifier
    first_event_time_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    group_key_hash: response_state_transition_receipt_body_v1_schema.Digest
    header: response_state_transition_receipt_body_v1_schema.Header
    last_event_time_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    lineage_seed: response_state_transition_receipt_body_v1_schema.Identifier
    ordered_event_ids: Annotated[
        list[response_state_transition_receipt_body_v1_schema.Identifier],
        Field(max_length=64, min_length=1),
    ]
    ordered_evidence_digests: Annotated[
        list[response_state_transition_receipt_body_v1_schema.Digest],
        Field(max_length=64, min_length=1),
    ]
    ordered_source_receipt_ids: Annotated[
        list[response_state_transition_receipt_body_v1_schema.Identifier],
        Field(max_length=64, min_length=1),
    ]
    policy: response_state_transition_receipt_body_v1_schema.Policy
    rule_id: response_state_transition_receipt_body_v1_schema.Identifier
    rule_version_hash: response_state_transition_receipt_body_v1_schema.Digest
