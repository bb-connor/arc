# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: a2de5a34e01a3345c9d1cfd8af54ab7b51bd57eed8cf608d3b84ede910af0a3e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, conint, constr

from . import caller_dispatch_authorization_schema


class RealizedCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    units: conint(strict=True, ge=0, le=9007199254740991)
    currency: constr(min_length=1, max_length=64)


class Report(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.caller-delivery-report.v1"] = Field(..., alias="schema")
    authorization_digest: caller_dispatch_authorization_schema.CallerDigest
    executor: caller_dispatch_authorization_schema.CallerExecutor
    claim_id: caller_dispatch_authorization_schema.CallerIdentifier
    execution_started_at_unix_ms: (
        caller_dispatch_authorization_schema.CallerPositiveInteger
    )
    completed_at_unix_ms: caller_dispatch_authorization_schema.CallerPositiveInteger
    output: Any
    realized_cost: RealizedCost | None = Field(...)


class ChioSignedCallerDeliveryReport(BaseModel):
    """
    Executor-authenticated historical observation, never a new execution permit or provider attestation. Canonical encoding is bounded to 1048576 bytes. Raw output remains on the trusted executor-to-kernel path until finalization permits release.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    report: Report
    signature: caller_dispatch_authorization_schema.CallerSignature
