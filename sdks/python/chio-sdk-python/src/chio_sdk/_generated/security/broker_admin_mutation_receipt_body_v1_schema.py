# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import broker_capability_body_v1_schema


class Operation(Enum):
    provision = "provision"
    rotate = "rotate"
    disable = "disable"
    delete = "delete"


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class ChioBrokerAdminMutationReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorizationDigest: Digest
    completedAtUnixSeconds: Annotated[int, Field(ge=1)]
    credential: broker_capability_body_v1_schema.CredentialRef
    intentDigest: Digest
    operation: Operation
    operationId: Digest
    outcome: Literal["applied"]
    requestId: Identifier
    schema_: Annotated[
        Literal["chio.broker-admin-mutation-receipt.v1"], Field(alias="schema")
    ]
    tenantScope: Identifier
