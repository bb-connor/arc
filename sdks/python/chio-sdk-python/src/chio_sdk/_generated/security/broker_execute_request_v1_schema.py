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
from . import broker_capability_body_v1_schema, broker_capability_envelope_v1_schema, broker_request_proof_envelope_v1_schema

class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class DigestOrNull(RootModel[Digest | None]):
    root: Digest | None

class ValueItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class SecurityBrokerExecuteRequestV1DefinitionsHeader(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: constr(pattern='^[a-z0-9-]+$', min_length=1, max_length=128)
    value: list[ValueItem] = Field(..., max_length=8192)

class SecurityBrokerExecuteRequestV1DefinitionsOptions(BaseModel):
    model_config = ConfigDict(extra='forbid')
    timeoutMs: conint(ge=1, le=120000)
    streaming: bool
    responseLimitBytes: conint(ge=1, le=2097152)

class BodyItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class SecurityBrokerExecuteRequestV1DefinitionsRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    destination: broker_capability_body_v1_schema.SecurityBrokerCapabilityBodyV1DefinitionsDestination
    headers: list[SecurityBrokerExecuteRequestV1DefinitionsHeader] = Field(..., max_length=64)
    body: list[BodyItem] = Field(..., max_length=524288)
    approvedPreviewSha256: DigestOrNull
    options: SecurityBrokerExecuteRequestV1DefinitionsOptions

class ChioBrokerExecuteRequestV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.broker-execute.v1'] = Field(..., alias='schema')
    invocationId: Identifier
    capability: broker_capability_envelope_v1_schema.ChioSignedBrokerCapabilityV1
    proof: broker_request_proof_envelope_v1_schema.ChioSignedBrokerRequestProofV1
    request: SecurityBrokerExecuteRequestV1DefinitionsRequest

# Public compatibility aliases reference the actual current model classes.
Header = SecurityBrokerExecuteRequestV1DefinitionsHeader
Options = SecurityBrokerExecuteRequestV1DefinitionsOptions
Request = SecurityBrokerExecuteRequestV1DefinitionsRequest
SecurityBrokerExecuteRequestV1BodyItem = BodyItem
SecurityBrokerExecuteRequestV1ChioBrokerExecuteRequestV1 = ChioBrokerExecuteRequestV1
SecurityBrokerExecuteRequestV1Digest = Digest
SecurityBrokerExecuteRequestV1DigestOrNull = DigestOrNull
SecurityBrokerExecuteRequestV1Identifier = Identifier
SecurityBrokerExecuteRequestV1ValueItem = ValueItem
