# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 6a4145266d2febc07a862fffbc565f800ff133c6f0adb06aac524c0ff01e4f34
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from . import flow_denial_receipt_body_v1_schema


class TripwireKind(Enum):
    canary_capability = "canary_capability"
    honey_tool = "honey_tool"
    credential_artifact = "credential_artifact"
    file_marker = "file_marker"
    browser_cookie = "browser_cookie"
    internal_hostname = "internal_hostname"
    signed_watermark = "signed_watermark"


class Severity(Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ChioTripwireObservationReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: flow_denial_receipt_body_v1_schema.Header
    policy: flow_denial_receipt_body_v1_schema.Policy
    request_id: flow_denial_receipt_body_v1_schema.Identifier
    request_hash: flow_denial_receipt_body_v1_schema.Digest
    event_id: flow_denial_receipt_body_v1_schema.Identifier
    tripwire_kind: TripwireKind
    artifact_id_hash: flow_denial_receipt_body_v1_schema.Digest
    artifact_version_hash: flow_denial_receipt_body_v1_schema.Digest
    observation_hash: flow_denial_receipt_body_v1_schema.Digest
    severity: Severity
