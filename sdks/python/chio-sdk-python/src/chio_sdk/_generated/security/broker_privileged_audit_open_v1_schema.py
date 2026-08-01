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

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import broker_execute_request_v1_schema


class Byte(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=512,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class NonzeroDigest(BaseModel):
    pass


class ChioBrokerPrivilegedAuditOpenRequestV1(BaseModel):
    """
    First-phase request on the isolated broker privileged audit transport.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    auditId: Identifier
    referenceCommitmentSalt: NonzeroDigest
    referenceCommitmentSha256: Digest
    referenceRequestBody: Annotated[list[Byte], Field(max_length=524288)]
    referenceRequestHead: Annotated[list[Byte], Field(max_length=1048576, min_length=1)]
    referenceSource: Identifier
    request: broker_execute_request_v1_schema.ChioBrokerExecuteRequestV1
    revocationAuthorityDomain: Identifier
    schema_: Annotated[
        Literal["chio.broker-privileged-audit-open.v1"], Field(alias="schema")
    ]
