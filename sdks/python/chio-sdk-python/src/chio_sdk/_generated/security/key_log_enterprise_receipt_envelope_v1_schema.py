# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9695e2b405d3cd46de929a925e1a3b9b33ec4a67a0a5e93f625c433f820e1920
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, constr

from . import key_log_enterprise_receipt_body_v1_schema


class OperatorAlgorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class ChioSignedKeyLogEnterpriseReceiptEnvelopeV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: key_log_enterprise_receipt_body_v1_schema.ChioKeyLogEnterpriseReceiptBodyV1
    operator_key_id: constr(pattern=r"^0x[0-9a-f]{64}$")
    operator_algorithm: OperatorAlgorithm
    operator_signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )
