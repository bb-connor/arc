# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class AnchorKind(Enum):
    """
    Closed set of anchor kinds. `oauth_id_jag`, `entra_jwt`, `entra_agent_id`, `oidc_jwt` and `oauth_introspection` are provider-backed: they verify against an enterprise provider record. Unknown kinds reject at decode.
    """

    oauth_id_jag = "oauth_id_jag"
    entra_jwt = "entra_jwt"
    entra_agent_id = "entra_agent_id"
    oidc_jwt = "oidc_jwt"
    oauth_introspection = "oauth_introspection"
    chio_local_as = "chio_local_as"
    chio_operator_key = "chio_operator_key"
    operator_static_bearer = "operator_static_bearer"


class Identifier(
    RootModel[constr(pattern=r"^[^\u0000]+$", min_length=1, max_length=128)]
):
    root: constr(pattern=r"^[^\u0000]+$", min_length=1, max_length=128) = Field(
        ...,
        description="A bounded identifier. NUL characters are rejected because identifiers feed NUL-delimited hash inputs.",
    )


class Text(RootModel[constr(pattern=r"^[^\u0000]+$", min_length=1, max_length=1024)]):
    root: constr(pattern=r"^[^\u0000]+$", min_length=1, max_length=1024) = Field(
        ..., description="A bounded NUL-free string."
    )


class Uri(RootModel[constr(pattern=r"^[^\u0000\s]+$", min_length=1, max_length=2048)]):
    root: constr(pattern=r"^[^\u0000\s]+$", min_length=1, max_length=2048) = Field(
        ..., description="A bounded URI or URN, such as an issuer."
    )


class HttpsUrl(RootModel[constr(pattern=r"^https://[^\u0000\s]+$", max_length=2048)]):
    root: constr(pattern=r"^https://[^\u0000\s]+$", max_length=2048)


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


class SaltRef(
    RootModel[constr(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$", max_length=64)]
):
    root: constr(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$", max_length=64)


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
        description="Self-describing public key encoding (`PublicKey::to_hex`): bare Ed25519 hex, `p256:`, `p384:` or `hybrid:`.",
    )


class SignatureHex(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{128}|p256:([0-9a-f]{2}){8,72}|p384:([0-9a-f]{2}){8,104}|hybrid:([0-9a-f]{128}|p256:([0-9a-f]{2}){8,72}|p384:([0-9a-f]{2}){8,104}):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{128}|p256:([0-9a-f]{2}){8,72}|p384:([0-9a-f]{2}){8,104}|hybrid:([0-9a-f]{128}|p256:([0-9a-f]{2}){8,72}|p384:([0-9a-f]{2}){8,104}):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    ) = Field(
        ...,
        description="Self-describing signature encoding: bare Ed25519 hex, `p256:` or `p384:` DER hex, or the hybrid form.",
    )


class Commitment(BaseModel):
    """
    A salted commitment whose salt is held in the disclosure store under `salt_ref`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    commit: Digest
    salt_ref: SaltRef


class HolderClass(Enum):
    """
    Who holds the root capability's subject key: the edge session or a Chio-aware caller.
    """

    edge_session = "edge_session"
    caller = "caller"


class ClaimValue(RootModel[Text | list[Text] | Commitment]):
    root: Text | list[Text] | Commitment = Field(
        ...,
        description="A recorded claim: a plain string, a plain list of strings, or a committed value.",
    )


class RecordedClaims(BaseModel):
    """
    The closed set of identity-provider claims a root policy rule may record. A committed claim is `SHA-256("chio.delegation-context.claim.v1\0" || utf8(name) || 0x00 || salt || canonical_json(value))`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    client_id: ClaimValue | None = None
    scope: ClaimValue | None = None
    sub: ClaimValue | None = None
    aud: ClaimValue | None = None
    resource: ClaimValue | None = None
    azp: ClaimValue | None = None
    appid: ClaimValue | None = None
    oid: ClaimValue | None = None
    tid: ClaimValue | None = None


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


class X5cItem(RootModel[constr(pattern=r"^[A-Za-z0-9+/]+={0,2}$", max_length=16384)]):
    root: constr(pattern=r"^[A-Za-z0-9+/]+={0,2}$", max_length=16384)


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
    The `root_anchor` member of a root `chio.capability.v1` body. It names how the root was anchored, binds the delegation context and root policy by digest, and is copied byte for byte into every delegated token. The `$defs` here are shared by every root-authority schema.
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
    A public JSON Web Key with the RFC 7517 and RFC 7518 members identity providers publish, plus Entra's `issuer` and `cloud_instance_name`. Private key members are not admitted.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kid: Identifier
    kty: Kty
    alg: JwsAlgorithm | None = None
    use: Use | None = None
    n: constr(pattern=r"^[A-Za-z0-9_-]+$", max_length=1400) | None = None
    e: constr(pattern=r"^[A-Za-z0-9_-]+$", max_length=16) | None = None
    crv: Crv | None = None
    x: constr(pattern=r"^[A-Za-z0-9_-]+$", max_length=128) | None = None
    y: constr(pattern=r"^[A-Za-z0-9_-]+$", max_length=128) | None = None
    x5c: list[X5cItem] | None = Field(None, max_length=8)
    x5t: constr(pattern=r"^[A-Za-z0-9_-]+$", max_length=64) | None = None
    x5t_S256: constr(pattern=r"^[A-Za-z0-9_-]+$", max_length=64) | None = Field(
        None, alias="x5t#S256"
    )
    issuer: Uri | None = None
    cloud_instance_name: Identifier | None = None
