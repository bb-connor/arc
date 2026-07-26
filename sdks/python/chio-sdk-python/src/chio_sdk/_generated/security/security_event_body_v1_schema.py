# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel


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


class Identifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=256,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class Subject(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agent_id: Identifier
    capability_id: Identifier
    lineage_seed: Identifier
    session_id: Identifier
    subject_id: Identifier


class Time(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=9007199254740991)]


class ChioSecurityEventBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: Identifier
    event_kind: EventKind
    event_time_unix_ms: Time
    evidence_references: Annotated[list[Identifier], Field(max_length=64, min_length=1)]
    ingest_time_unix_ms: Time
    policy_version: Identifier
    producer_id: Identifier
    producer_key_id: Identifier
    severity: Severity
    source_receipt_id: Identifier
    subject: Subject
    tenant_id: Identifier
    trust_class: TrustClass
