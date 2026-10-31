# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Pcrs(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field_0: str = Field(..., alias="0")


class AwsNitro(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    digest: str
    moduleId: str
    pcrs: Pcrs


class AzureMaa(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attestationType: str


class EnterpriseVerifier(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attestationType: str
    digest: str | None = None
    hardwareModel: str | None = None
    pcrs: Pcrs | None = None
    secureBoot: str | None = None


class Claims(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    awsNitro: AwsNitro | None = None
    azureMaa: AzureMaa | None = None
    enterpriseVerifier: EnterpriseVerifier | None = None


class WorkloadIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    credentialKind: str
    path: str
    scheme: str
    trustDomain: str
    uri: str


class ChioRuntimeAttestationEvidenceSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claims: Claims
    evidence_sha256: str
    expires_at: int
    issued_at: int
    runtime_identity: str | None = None
    schema_: str = Field(..., alias="schema")
    tier: str
    verifier: str
    workload_identity: WorkloadIdentity | None = None
