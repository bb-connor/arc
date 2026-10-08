# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 98badc519c6787931e288dad66023f0515a7bda8b0be5b4370b5b906713f8c3e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class SecurityBindingText(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
    )


class ChioCapabilitySecurityBinding(BaseModel):
    """
    Decoded predicate of a bind_security_context caveat. The caveat predicate is the RFC 8785 canonical JSON text of this object, and the caveat carries no sig.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.capability-security-binding.v1"] = Field(..., alias="schema")
    tenantId: SecurityBindingText
    lineageId: SecurityBindingText
    sessionId: SecurityBindingText
    principalId: SecurityBindingText
    isolationEpochId: SecurityBindingText
    contextGeneration: conint(ge=1, le=18446744073709551615)
    workloadId: SecurityBindingText
    serverId: SecurityBindingText
    workloadSignerPublicKey: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    ) = Field(
        ..., description="Canonical lowercase PublicKey hex form, without a 0x prefix."
    )
