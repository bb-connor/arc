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

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from . import broker_execution_failure_receipt_envelope_v1_schema


class ChioBrokerExecuteFailureV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    diagnosticCode: Annotated[
        str, Field(max_length=128, min_length=6, pattern="^chio\\.[a-z0-9._-]+$")
    ]
    receipt: (
        broker_execution_failure_receipt_envelope_v1_schema.ChioSignedBrokerExecutionFailureReceiptV1
    )
    receiptReference: Annotated[
        str,
        Field(
            max_length=94,
            min_length=94,
            pattern="^broker-failure-receipt-sha256-[0-9a-f]{64}$",
        ),
    ]
