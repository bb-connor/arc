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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import broker_execute_request_v1_schema


class AuditIdentifier(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=512,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=512,
    )


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class NonzeroDigest(BaseModel):
    pass


class Byte(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class ChioBrokerPrivilegedAuditOpenRequestV1(BaseModel):
    """
    First-phase request on the isolated broker privileged audit transport.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-privileged-audit-open.v1"] = Field(
        ..., alias="schema"
    )
    auditId: AuditIdentifier
    referenceSource: AuditIdentifier
    revocationAuthorityDomain: AuditIdentifier
    request: broker_execute_request_v1_schema.ChioBrokerExecuteRequestV1
    referenceCommitmentSalt: NonzeroDigest
    referenceCommitmentSha256: Digest
    referenceRequestHead: list[Byte] = Field(..., max_length=1048576, min_length=1)
    referenceRequestBody: list[Byte] = Field(..., max_length=524288)
