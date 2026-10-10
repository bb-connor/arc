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
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from . import broker_capability_body_v1_schema

class SecurityBrokerAdminMutationReceiptBodyV1Operation(Enum):
    provision = 'provision'
    rotate = 'rotate'
    disable = 'disable'
    delete = 'delete'

class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class ChioBrokerAdminMutationReceiptBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.broker-admin-mutation-receipt.v1'] = Field(..., alias='schema')
    operationId: Digest
    requestId: Identifier
    intentDigest: Digest
    authorizationDigest: Digest
    operation: SecurityBrokerAdminMutationReceiptBodyV1Operation
    tenantScope: Identifier
    credential: broker_capability_body_v1_schema.SecurityBrokerCapabilityBodyV1DefinitionsCredentialRef
    completedAtUnixSeconds: conint(ge=1)
    outcome: Literal['applied']

# Public compatibility aliases reference the actual current model classes.
Operation = SecurityBrokerAdminMutationReceiptBodyV1Operation
SecurityBrokerAdminMutationReceiptBodyV1ChioBrokerAdminMutationReceiptBodyV1 = ChioBrokerAdminMutationReceiptBodyV1
SecurityBrokerAdminMutationReceiptBodyV1Digest = Digest
SecurityBrokerAdminMutationReceiptBodyV1Identifier = Identifier
