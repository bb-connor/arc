# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field


class Tier(Enum):
    """
    Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
    """

    none = "none"
    basic = "basic"
    attested = "attested"
    verified = "verified"


class CredentialKind(Enum):
    """
    Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
    """

    uri = "uri"
    x509_svid = "x509_svid"
    jwt_svid = "jwt_svid"


class Scheme(Enum):
    """
    Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
    """

    spiffe = "spiffe"


class WorkloadIdentity(BaseModel):
    """
    Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    credentialKind: Annotated[
        CredentialKind,
        Field(
            description="Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`."
        ),
    ]
    path: Annotated[
        str, Field(description="Canonical workload path within the trust domain.")
    ]
    scheme: Annotated[
        Scheme,
        Field(
            description="Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`."
        ),
    ]
    trustDomain: Annotated[
        str,
        Field(
            description="Stable trust domain resolved from the identifier.",
            min_length=1,
        ),
    ]
    uri: Annotated[
        str, Field(description="Canonical workload identifier URI.", min_length=1)
    ]


class ChioTrustControlRuntimeAttestationEvidence(BaseModel):
    """
    One normalized runtime attestation evidence statement carried alongside trust-control authority operations and governed capability issuance. The shape names the upstream attestation schema, the verifier or relying party that accepted the evidence, the normalized assurance tier Chio resolved, the evidence's issued-at and expires-at bounds, and a stable SHA-256 digest of the underlying attestation payload. Optional fields preserve a runtime or workload identifier and a normalized SPIFFE workload identity when the verifier exposed one. Mirrors the `RuntimeAttestationEvidence` struct in `crates/core/chio-core-types`. The struct does not carry `serde(rename_all)`, so wire field names are snake_case. Verifier adapters and trust-control issuance call sites in `crates/platform/chio-control-plane` populate this shape after running the per-vendor verifier bridges (Azure MAA, AWS Nitro, Google Confidential VM).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    claims: Annotated[
        Any | None,
        Field(
            description="Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims."
        ),
    ] = None
    evidence_sha256: Annotated[
        str,
        Field(
            description="Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.",
            min_length=1,
        ),
    ]
    expires_at: Annotated[
        int,
        Field(
            description="Unix timestamp (seconds) when this attestation expires. Trust-control fails closed when `now < issued_at` or `now >= expires_at`.",
            ge=0,
        ),
    ]
    issued_at: Annotated[
        int,
        Field(
            description="Unix timestamp (seconds) when this attestation was issued.",
            ge=0,
        ),
    ]
    runtime_identity: Annotated[
        str | None,
        Field(
            description="Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.",
            min_length=1,
        ),
    ] = None
    schema_: Annotated[
        str,
        Field(
            alias="schema",
            description="Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).",
            min_length=1,
        ),
    ]
    tier: Annotated[
        Tier,
        Field(
            description="Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`."
        ),
    ]
    verifier: Annotated[
        str,
        Field(
            description="Attestation verifier or relying party that accepted the evidence.",
            min_length=1,
        ),
    ]
    workload_identity: Annotated[
        WorkloadIdentity | None,
        Field(
            description="Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity."
        ),
    ] = None
