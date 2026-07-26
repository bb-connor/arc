# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceClass(Enum):
    """
    Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`, which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.
    """

    asserted = "asserted"
    observed = "observed"
    verified = "verified"


class Tier(Enum):
    """
    Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types`.
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
    Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
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


class Statement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claims: Annotated[
        Any | None,
        Field(
            description="Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`."
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
            description="Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.",
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
            description="Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types`."
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
            description="Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`."
        ),
    ] = None


class ChioProvenanceAttestationBundle(BaseModel):
    """
    One bundle of corroborating runtime attestation evidence statements that anchor a governed call-chain context to a verified runtime. Names the `chainId` it binds to (matching `provenance/context.schema.json`), the canonical evidence-class Chio resolved across the bundle, the unix-second `assembledAt` timestamp, and the ordered list of normalized statements. Each statement mirrors the `RuntimeAttestationEvidence` shape and is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json`; the family is inlined rather than `$ref`'d. Field names are camelCase to match `GovernedCallChainContext`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    assembledAt: Annotated[
        int,
        Field(
            description="Unix timestamp (seconds) at which the bundle was assembled. Used to bound bundle freshness and to establish ordering with respect to receipts emitted from the same kernel.",
            ge=0,
        ),
    ]
    chainId: Annotated[
        str,
        Field(
            description="Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.",
            min_length=1,
        ),
    ]
    evidenceClass: Annotated[
        EvidenceClass,
        Field(
            description="Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`, which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it."
        ),
    ]
    issuer: Annotated[
        str | None,
        Field(
            description="Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.",
            min_length=1,
        ),
    ] = None
    statements: Annotated[
        list[Statement],
        Field(
            description="Ordered list of normalized runtime attestation evidence statements. Each statement is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json` and mirrors `RuntimeAttestationEvidence` in `crates/core/chio-core-types`. The struct does not carry `serde(rename_all)`, so the per-statement scalar fields are snake_case; the embedded `workload_identity` carries `serde(rename_all = camelCase)` so its inner fields are camelCase. Optional fields (`runtime_identity`, `workload_identity`, `claims`) are omitted from the wire when their underlying `Option<...>` is `None`.",
            min_length=1,
        ),
    ]
