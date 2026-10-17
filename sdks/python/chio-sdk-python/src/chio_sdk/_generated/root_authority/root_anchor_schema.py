# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7bc9c9d39014b0d2234c7f929e827c2ab02e825f9cb23c608c135695ce3ed4d1
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class AnchorKind(Enum):
    """
    Closed set of anchor kinds (PROTOCOL 5.6.2). Unknown kinds reject at decode.
    """

    oauth_id_jag = "oauth_id_jag"
    entra_jwt = "entra_jwt"
    entra_agent_id = "entra_agent_id"
    oidc_jwt = "oidc_jwt"
    oauth_introspection = "oauth_introspection"
    chio_local_as = "chio_local_as"
    chio_operator_key = "chio_operator_key"
    operator_static_bearer = "operator_static_bearer"


class Digest(RootModel[constr(pattern=r"^sha256:[0-9a-f]{64}$")]):
    root: constr(pattern=r"^sha256:[0-9a-f]{64}$") = Field(
        ...,
        description="SHA-256 digest as `sha256:` followed by 64 lowercase hex characters.",
    )


class Salt(RootModel[constr(pattern=r"^b64u:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$")]):
    root: constr(pattern=r"^b64u:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$") = Field(
        ...,
        description="A 32-byte salt as `b64u:` followed by its canonical unpadded base64url encoding (43 characters).",
    )


class PublicKeyHex(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    ) = Field(
        ...,
        description="Self-describing public key encoding of PROTOCOL 4.4 (`PublicKey::to_hex`).",
    )


class SignatureHex(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    ) = Field(
        ...,
        description="Self-describing signature encoding over the signing wrapper (PROTOCOL 4.5).",
    )


class Commitment(BaseModel):
    """
    A salted commitment whose salt is held in the disclosure store under `salt_ref`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    commit: Digest
    salt_ref: constr(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$")


class HolderClass(Enum):
    """
    Who holds the root capability's subject key (PROTOCOL 5.6.6).
    """

    edge_session = "edge_session"
    caller = "caller"


class Kty(Enum):
    RSA = "RSA"
    EC = "EC"
    OKP = "OKP"


class Use(Enum):
    sig = "sig"


class Crv(Enum):
    P_256 = "P-256"
    P_384 = "P-384"
    P_521 = "P-521"
    Ed25519 = "Ed25519"


class JwsAlgorithm(Enum):
    """
    Asymmetric JWS algorithms. `none` and the HMAC algorithms are never admitted.
    """

    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    EdDSA = "EdDSA"


class ChioRootAnchor(BaseModel):
    """
    The `root_anchor` member of a root `chio.capability.v1` body (PROTOCOL 5.6.1). A delegated token copies it byte for byte from its root. The `$defs` here are shared by every root-authority schema.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: AnchorKind
    context_digest: Digest = Field(
        ...,
        description="SHA-256 over `chio.delegation-context.v1\\0 || canonical_json(context)`.",
    )
    root_policy_digest: Digest = Field(
        ...,
        description="SHA-256 over `chio.root-policy.v1\\0 || canonical_json(policy signing body)`.",
    )
    anchored_at: conint(ge=0) = Field(
        ...,
        description="Unix seconds. Equals `exchange.exchanged_at` of the delegation context.",
    )
    assertion_exp: conint(ge=0) = Field(
        ...,
        description="Unix seconds. Equals `anchor.token_exp` of the delegation context. A root's `expires_at` must not exceed it.",
    )


class Jwk(BaseModel):
    """
    A public JSON Web Key. Private key members are not admitted.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kid: constr(min_length=1)
    kty: Kty
    alg: JwsAlgorithm | None = None
    use: Use | None = None
    n: constr(pattern=r"^[A-Za-z0-9_-]+$") | None = None
    e: constr(pattern=r"^[A-Za-z0-9_-]+$") | None = None
    crv: Crv | None = None
    x: constr(pattern=r"^[A-Za-z0-9_-]+$") | None = None
    y: constr(pattern=r"^[A-Za-z0-9_-]+$") | None = None
