# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from . import response_state_transition_receipt_body_v1_schema


class ChioCorrelatedFindingReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: response_state_transition_receipt_body_v1_schema.Header
    policy: response_state_transition_receipt_body_v1_schema.Policy
    finding_id: response_state_transition_receipt_body_v1_schema.Identifier
    finding_hash: response_state_transition_receipt_body_v1_schema.Digest
    rule_id: response_state_transition_receipt_body_v1_schema.Identifier
    rule_version_hash: response_state_transition_receipt_body_v1_schema.Digest
    group_key_hash: response_state_transition_receipt_body_v1_schema.Digest
    ordered_event_ids: list[
        response_state_transition_receipt_body_v1_schema.Identifier
    ] = Field(..., max_length=64, min_length=1)
    ordered_evidence_digests: list[
        response_state_transition_receipt_body_v1_schema.Digest
    ] = Field(..., max_length=64, min_length=1)
    ordered_source_receipt_ids: list[
        response_state_transition_receipt_body_v1_schema.Identifier
    ] = Field(..., max_length=64, min_length=1)
    first_event_time_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    last_event_time_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    lineage_seed: response_state_transition_receipt_body_v1_schema.Identifier
