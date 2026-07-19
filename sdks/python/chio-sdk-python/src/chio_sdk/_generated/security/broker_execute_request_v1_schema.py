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

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import (
    broker_capability_body_v1_schema,
    broker_capability_envelope_v1_schema,
    broker_request_proof_envelope_v1_schema,
)


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class DigestOrNull(RootModel[Digest | None]):
    root: Digest | None


class ValueItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Header(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: Annotated[str, Field(max_length=128, min_length=1, pattern="^[a-z0-9-]+$")]
    value: Annotated[list[ValueItem], Field(max_length=8192)]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class Options(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    responseLimitBytes: Annotated[int, Field(ge=1, le=2097152)]
    streaming: bool
    timeoutMs: Annotated[int, Field(ge=1, le=120000)]


class BodyItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Request(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approvedPreviewSha256: DigestOrNull
    body: Annotated[list[BodyItem], Field(max_length=524288)]
    destination: broker_capability_body_v1_schema.Destination
    headers: Annotated[list[Header], Field(max_length=64)]
    options: Options


class ChioBrokerExecuteRequestV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability: broker_capability_envelope_v1_schema.ChioSignedBrokerCapabilityV1
    invocationId: Identifier
    proof: broker_request_proof_envelope_v1_schema.ChioSignedBrokerRequestProofV1
    request: Request
    schema_: Annotated[Literal["chio.broker-execute.v1"], Field(alias="schema")]
