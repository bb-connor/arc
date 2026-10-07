# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 35f8e30cf30553986a159b074ee485804a85db29547a8102522cd7bfa3080d2e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, ConfigDict, constr

class SecurityKeyLogWitnessSignatureV1Algorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class ChioKeyLogWitnessSignatureV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    witness_id: constr(pattern='^[A-Za-z0-9._:/-]+$', min_length=1, max_length=128)
    algorithm: SecurityKeyLogWitnessSignatureV1Algorithm
    signature: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

# Public compatibility aliases reference the actual current model classes.
Algorithm = SecurityKeyLogWitnessSignatureV1Algorithm
SecurityKeyLogWitnessSignatureV1ChioKeyLogWitnessSignatureV1 = ChioKeyLogWitnessSignatureV1
