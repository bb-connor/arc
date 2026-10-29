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

from pydantic import BaseModel, ConfigDict, constr

from . import broker_execution_failure_receipt_envelope_v1_schema


class ChioBrokerExecuteFailureV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    diagnosticCode: constr(
        pattern=r"^chio\.[a-z0-9._-]+$", min_length=6, max_length=128
    )
    receiptReference: constr(
        pattern=r"^broker-failure-receipt-sha256-[0-9a-f]{64}$",
        min_length=94,
        max_length=94,
    )
    receipt: (
        broker_execution_failure_receipt_envelope_v1_schema.ChioSignedBrokerExecutionFailureReceiptV1
    )
