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
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator


class Algorithm(Enum):
    """
    Signing algorithm envelope hint. Verification dispatches off the signature hex prefix, not this field.
    """

    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"


class BoundaryClass(Enum):
    """
    Signed runtime boundary class. `cannot_see` is planning metadata only and is not valid on signed runtime receipts.
    """

    prevent = "prevent"
    detect_only = "detect_only"
    advisory_only = "advisory_only"


class ObservationOutcome(Enum):
    """
    Signed outcome for trace and advisory records. Omitted for mediated decisions.
    """

    observed = "observed"
    evaluated = "evaluated"
    dropped = "dropped"


class ReceiptKind(Enum):
    """
    Signed semantic class for this v1 receipt.
    """

    mediated_decision = "mediated_decision"
    trace_observation = "trace_observation"
    advisory_evaluation = "advisory_evaluation"


class RedactionMode(Enum):
    """
    Signed redaction mode applied to receipt details.
    """

    none = "none"
    summary = "summary"
    redacted = "redacted"


class ToolOrigin(Enum):
    """
    Signed classification of where the tool effect executed relative to Chio.
    """

    caller_executed = "caller_executed"
    host_executed_provider_reported = "host_executed_provider_reported"
    host_executed_unmediated = "host_executed_unmediated"


class TrustLevel(Enum):
    """
    Strength of kernel mediation that produced this receipt. Must cohere with receipt_kind: mediated_decision uses mediated, trace_observation uses verified, and advisory_evaluation uses advisory.
    """

    mediated = "mediated"
    verified = "verified"
    advisory = "advisory"


class ActorRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actor_id: Annotated[str, Field(min_length=1)]
    actor_kind: Annotated[str | None, Field(min_length=1)] = None


class BbsReceiptSignature(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: Literal["bbs"]
    ciphersuite: Literal["BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"]
    issuer_fingerprint: Annotated[str, Field(pattern="^[A-Za-z0-9._:-]{1,128}$")]
    issuer_public_key_hex: Annotated[str, Field(pattern="^[0-9a-f]{192}$")]
    message_count: Literal[14]
    projection_version: Literal["chio.bbs-projection.receipt.v1"]
    schema_: Annotated[Literal["chio.receipt.bbs_signature.v1"], Field(alias="schema")]
    signature_hex: Annotated[str, Field(pattern="^([0-9a-f]{2})+$")]


class Decision2(BaseModel):
    """
    The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["allow"]


class Decision3(BaseModel):
    """
    The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    guard: Annotated[
        str,
        Field(description="The guard or validation step that triggered the denial."),
    ]
    reason: Annotated[str, Field(description="Human-readable reason for the denial.")]
    verdict: Literal["deny"]


class Decision4(BaseModel):
    """
    The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    reason: Annotated[
        str, Field(description="Human-readable reason for the cancellation.")
    ]
    verdict: Literal["cancelled"]


class Decision5(BaseModel):
    """
    The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    reason: Annotated[
        str,
        Field(description="Human-readable reason for the incomplete terminal state."),
    ]
    verdict: Literal["incomplete"]


class Decision(RootModel[Decision2 | Decision3 | Decision4 | Decision5]):
    root: Annotated[
        Decision2 | Decision3 | Decision4 | Decision5,
        Field(
            description='The Kernel\'s verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).'
        ),
    ]


class GuardEvidence(BaseModel):
    """
    Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    details: Annotated[
        str | None, Field(description="Optional details about the guard's decision.")
    ] = None
    guard_name: Annotated[
        str,
        Field(
            description="Name of the guard (e.g. `ForbiddenPathGuard`).", min_length=1
        ),
    ]
    verdict: Annotated[
        bool, Field(description="Whether the guard passed (true) or denied (false).")
    ]


class ToolCallAction(BaseModel):
    """
    Describes the tool call that was evaluated. Mirrors `ToolCallAction`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    parameter_hash: Annotated[
        str,
        Field(
            description="SHA-256 hex hash of the canonical JSON of `parameters`.",
            pattern="^[0-9a-f]{64}$",
        ),
    ]
    parameters: Annotated[
        Any,
        Field(
            description="The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`)."
        ),
    ]


class ChioReceiptRecord(BaseModel):
    """
    A signed Chio receipt: proof that a tool call was evaluated by the Kernel. The receipt id is the authoritative content-addressed SHA-256 hash over the canonical ChioReceiptIdInput.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    action: ToolCallAction
    actor_chain: Annotated[
        list[ActorRef] | None,
        Field(
            description="Signed actor attribution chain. Omitted from the wire when empty."
        ),
    ] = None
    algorithm: Annotated[
        Algorithm | None,
        Field(
            description="Signing algorithm envelope hint. Verification dispatches off the signature hex prefix, not this field."
        ),
    ] = None
    bbs_projection_version: Annotated[
        Literal["chio.bbs-projection.receipt.v1"] | None,
        Field(
            description="Receipt-body BBS projection version bound into the receipt id when bbs_signature is present."
        ),
    ] = None
    bbs_signature: Annotated[
        BbsReceiptSignature | None,
        Field(
            description="Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody."
        ),
    ] = None
    boundary_class: Annotated[
        BoundaryClass,
        Field(
            description="Signed runtime boundary class. `cannot_see` is planning metadata only and is not valid on signed runtime receipts."
        ),
    ]
    capability_id: Annotated[
        str,
        Field(
            description="ID of the capability token that was exercised (or presented).",
            min_length=1,
        ),
    ]
    content_hash: Annotated[
        str,
        Field(
            description="SHA-256 hex hash of the evaluated content for this receipt.",
            pattern="^[0-9a-f]{64}$",
        ),
    ]
    decision: Decision | None = None
    evidence: Annotated[
        list[GuardEvidence] | None,
        Field(
            description='Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = "Vec::is_empty")]`).'
        ),
    ] = None
    id: Annotated[
        str,
        Field(
            description="Authoritative content-addressed receipt id.",
            min_length=1,
            pattern="^[0-9a-f]{64}$",
        ),
    ]
    kernel_key: Annotated[
        str,
        Field(
            description="Kernel public key (for verification without out-of-band lookup). Bare 64-char lowercase hex string for Ed25519, `p256:<130-char hex>` for uncompressed SEC1 P-256 (65 bytes; leading byte `0x04`), or `p384:<194-char hex>` for uncompressed SEC1 P-384 (97 bytes; leading byte `0x04`). Anything outside these length classes is rejected at decode time by `PublicKey::from_hex` in `crates/core/chio-core-types/src/crypto.rs`.",
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$",
        ),
    ]
    metadata: Annotated[
        Any | None,
        Field(
            description="Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`)."
        ),
    ] = None
    observation_outcome: Annotated[
        ObservationOutcome | None,
        Field(
            description="Signed outcome for trace and advisory records. Omitted for mediated decisions."
        ),
    ] = None
    policy_hash: Annotated[
        str,
        Field(
            description="SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.",
            min_length=1,
        ),
    ]
    receipt_kind: Annotated[
        ReceiptKind, Field(description="Signed semantic class for this v1 receipt.")
    ]
    redaction_mode: Annotated[
        RedactionMode,
        Field(description="Signed redaction mode applied to receipt details."),
    ]
    signature: Annotated[
        str,
        Field(
            description="Hex-encoded signature over canonical JSON of ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature? }. Bare 128-char lowercase hex for Ed25519 (`Signature::from_hex` in `crates/core/chio-core-types/src/crypto.rs` requires exactly 64 bytes for the bare path), or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.",
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$",
        ),
    ]
    tenant_id: Annotated[
        str | None,
        Field(
            description="Tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields.",
            min_length=1,
        ),
    ] = None
    timestamp: Annotated[
        int,
        Field(
            description="Unix timestamp (seconds) when the receipt was created.", ge=0
        ),
    ]
    tool_name: Annotated[
        str, Field(description="Tool that was invoked (or attempted).", min_length=1)
    ]
    tool_origin: Annotated[
        ToolOrigin,
        Field(
            description="Signed classification of where the tool effect executed relative to Chio."
        ),
    ]
    tool_server: Annotated[
        str, Field(description="Tool server that handled the invocation.", min_length=1)
    ]
    trust_level: Annotated[
        TrustLevel,
        Field(
            description="Strength of kernel mediation that produced this receipt. Must cohere with receipt_kind: mediated_decision uses mediated, trace_observation uses verified, and advisory_evaluation uses advisory."
        ),
    ]

    @model_validator(mode="after")
    def _validate_bbs_pairing(self) -> "ChioReceiptRecord":
        has_projection = self.bbs_projection_version is not None
        has_signature = self.bbs_signature is not None
        if has_projection != has_signature:
            raise ValueError(
                "bbs_projection_version and bbs_signature must be present together"
            )
        return self
