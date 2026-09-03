# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 389bcf1b0204c491a4db719480c568ace486987ea9871d15adefdc3bb3a365cc
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
