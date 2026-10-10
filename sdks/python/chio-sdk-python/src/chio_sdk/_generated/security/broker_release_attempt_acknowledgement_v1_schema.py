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
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)

class ChioBrokerReleaseAttemptAcknowledgementV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.broker-release-attempt-acknowledgement.v1'] = Field(..., alias='schema')
    operationId: Identifier
    attemptId: Identifier
    releasedAtUnixSeconds: conint(ge=1)

# Public compatibility aliases reference the actual current model classes.
SecurityBrokerReleaseAttemptAcknowledgementV1ChioBrokerReleaseAttemptAcknowledgementV1 = ChioBrokerReleaseAttemptAcknowledgementV1
SecurityBrokerReleaseAttemptAcknowledgementV1Identifier = Identifier
