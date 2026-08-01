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

from . import broker_audit_runner_authorization_envelope_v1_schema


class GovernedAdminAuthorizationItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class ChioBrokerPrivilegedAuditCommitRequestV1(BaseModel):
    """
    Second and final request binding runner and governed administrator authorization to a broker challenge.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    governedAdminAuthorization: Annotated[
        list[GovernedAdminAuthorizationItem], Field(max_length=65536, min_length=1)
    ]
    runnerAuthorization: (
        broker_audit_runner_authorization_envelope_v1_schema.ChioSignedBrokerAuditRunnerAuthorizationV1
    )
    schema_: Annotated[
        Literal["chio.broker-privileged-audit-commit.v1"], Field(alias="schema")
    ]
    sessionCommitmentSha256: Digest
    sessionNonce: Digest
