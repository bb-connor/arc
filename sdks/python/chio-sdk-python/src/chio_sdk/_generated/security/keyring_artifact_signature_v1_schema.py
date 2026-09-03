# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0407f7020bf1ed0a18c5cfabf00d6a6d8721d03a88b1c1763dcc7b25a264b2b0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Hash(RootModel[constr(pattern=r"^0x[0-9a-f]{64}$")]):
    root: constr(pattern=r"^0x[0-9a-f]{64}$")


class U64(RootModel[conint(ge=0, le=18446744073709551615)]):
    root: conint(ge=0, le=18446744073709551615)


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class Signature(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )


class ChioKeyringArtifactSignatureEvidenceV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.keyring.artifact-signature.v1"] = Field(..., alias="schema")
    artifact_hash: Hash
    key_id: Hash
    signing_epoch: U64
    algorithm: Algorithm
    artifact_signature: Signature
    fence_signature: Signature
