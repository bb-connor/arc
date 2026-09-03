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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import (
    broker_capability_body_v1_schema,
    broker_capability_envelope_v1_schema,
    broker_request_proof_envelope_v1_schema,
)


class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class DigestOrNull(RootModel[Digest | None]):
    root: Digest | None


class ValueItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class Header(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: constr(pattern=r"^[a-z0-9-]+$", min_length=1, max_length=128)
    value: list[ValueItem] = Field(..., max_length=8192)


class Options(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    timeoutMs: conint(ge=1, le=120000)
    streaming: bool
    responseLimitBytes: conint(ge=1, le=2097152)


class BodyItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class Request(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    destination: broker_capability_body_v1_schema.Destination
    headers: list[Header] = Field(..., max_length=64)
    body: list[BodyItem] = Field(..., max_length=524288)
    approvedPreviewSha256: DigestOrNull
    options: Options


class ChioBrokerExecuteRequestV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-execute.v1"] = Field(..., alias="schema")
    invocationId: Identifier
    capability: broker_capability_envelope_v1_schema.ChioSignedBrokerCapabilityV1
    proof: broker_request_proof_envelope_v1_schema.ChioSignedBrokerRequestProofV1
    request: Request
