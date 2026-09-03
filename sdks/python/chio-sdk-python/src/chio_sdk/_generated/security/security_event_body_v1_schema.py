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

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class EventKind(Enum):
    canary_invocation = "canary_invocation"
    credential_access = "credential_access"
    declassification_attempt = "declassification_attempt"
    detector_health = "detector_health"
    egress_attempt = "egress_attempt"
    flow_denial = "flow_denial"
    tool_invocation = "tool_invocation"
    tripwire_observation = "tripwire_observation"
    watermark_observation = "watermark_observation"


class Severity(Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class TrustClass(Enum):
    internal_detector = "internal_detector"
    verified_receipt = "verified_receipt"


class Identifier(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=256,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=256,
    )


class Time(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class Subject(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    subject_id: Identifier
    agent_id: Identifier
    session_id: Identifier
    capability_id: Identifier
    lineage_seed: Identifier


class ChioSecurityEventBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: Identifier
    event_time_unix_ms: Time
    ingest_time_unix_ms: Time
    tenant_id: Identifier
    subject: Subject
    source_receipt_id: Identifier
    event_kind: EventKind
    severity: Severity
    evidence_references: list[Identifier] = Field(..., max_length=64, min_length=1)
    producer_id: Identifier
    producer_key_id: Identifier
    trust_class: TrustClass
    policy_version: Identifier
