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

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import (
    broker_execute_request_v1_schema,
    broker_execution_evidence_v1_schema,
    broker_execution_receipt_envelope_v1_schema,
)


class BodyItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class ChioBrokerExecuteResponseV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Annotated[list[BodyItem], Field(max_length=2097152)]
    evidence: broker_execution_evidence_v1_schema.ChioBrokerExecutionEvidenceV1
    headers: Annotated[
        list[broker_execute_request_v1_schema.Header], Field(max_length=64)
    ]
    receipt: (
        broker_execution_receipt_envelope_v1_schema.ChioSignedBrokerExecutionReceiptV1
    )
    receiptReference: Annotated[
        str,
        Field(
            max_length=86, min_length=86, pattern="^broker-receipt-sha256-[0-9a-f]{64}$"
        ),
    ]
    status: Annotated[int, Field(ge=100, le=599)]
