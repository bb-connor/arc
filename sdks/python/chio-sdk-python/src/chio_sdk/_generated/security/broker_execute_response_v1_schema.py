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

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import (
    broker_execute_request_v1_schema,
    broker_execution_evidence_v1_schema,
    broker_execution_receipt_envelope_v1_schema,
)


class BodyItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class ChioBrokerExecuteResponseV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: conint(ge=100, le=599)
    headers: list[broker_execute_request_v1_schema.Header] = Field(..., max_length=64)
    body: list[BodyItem] = Field(..., max_length=2097152)
    evidence: broker_execution_evidence_v1_schema.ChioBrokerExecutionEvidenceV1
    receiptReference: constr(
        pattern=r"^broker-receipt-sha256-[0-9a-f]{64}$", min_length=86, max_length=86
    )
    receipt: (
        broker_execution_receipt_envelope_v1_schema.ChioSignedBrokerExecutionReceiptV1
    )
