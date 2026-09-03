# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 389bcf1b0204c491a4db719480c568ace486987ea9871d15adefdc3bb3a365cc
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import (
    cage_init_plan_v2_schema,
    signed_tool_manifest_v2_schema,
    tool_manifest_v2_schema,
)


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class PublicKey(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )


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


class Identifier(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=256,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=256,
    )


class AbsoluteCanonicalPath(
    RootModel[
        constr(
            pattern=r"^/(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*\/$)[^\u0000-\u001F\u007F-\u009F]+$",
            min_length=2,
        )
    ]
):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: constr(
        pattern=r"^/(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*\/$)[^\u0000-\u001F\u007F-\u009F]+$",
        min_length=2,
    )


class EnvironmentVariable(
    RootModel[
        constr(
            pattern=r"^(?!(?:[lL][dD]_|[dD][yY][lL][dD]_|[bB][aA][sS][hH]_[fF][uU][nN][cC]_|[mM][aA][lL][lL][oO][cC]_))(?!(?:[bB][aA][sS][hH]_[eE][nN][vV]|[dD][oO][cC][kK][eE][rR]_[cC][oO][nN][fF][iI][gG]|[eE][nN][vV]|[gG][cC][oO][nN][vV]_[pP][aA][tT][hH]|[gG][eE][mM]_[hH][oO][mM][eE]|[gG][eE][mM]_[pP][aA][tT][hH]|[gG][iI][tT]_[aA][sS][kK][pP][aA][sS][sS]|[gG][lL][iI][bB][cC]_[tT][uU][nN][aA][bB][lL][eE][sS]|[gG][pP][gG]_[aA][gG][eE][nN][tT]_[iI][nN][fF][oO]|[iI][fF][sS]|[jJ][aA][vV][aA]_[tT][oO][oO][lL]_[oO][pP][tT][iI][oO][nN][sS]|[jJ][dD][kK]_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS]|[kK][rR][bB]5[cC][cC][nN][aA][mM][eE]|[lL][oO][cC][pP][aA][tT][hH]|[nN][eE][tT][rR][cC]|[nN][lL][sS][pP][aA][tT][hH]|[nN][oO][dD][eE]_[oO][pP][tT][iI][oO][nN][sS]|[nN][oO][dD][eE]_[pP][aA][tT][hH]|[nN][pP][mM]_[cC][oO][nN][fF][iI][gG]_[uU][sS][eE][rR][cC][oO][nN][fF][iI][gG]|[pP][eE][rR][lL]5[oO][pP][tT]|[pP][eE][rR][lL]5[lL][iI][bB]|[pP][yY][tT][hH][oO][nN][hH][oO][mM][eE]|[pP][yY][tT][hH][oO][nN][iI][nN][sS][pP][eE][cC][tT]|[pP][yY][tT][hH][oO][nN][pP][aA][tT][hH]|[pP][yY][tT][hH][oO][nN][sS][tT][aA][rR][tT][uU][pP]|[rR][uU][bB][yY][lL][iI][bB]|[rR][uU][bB][yY][oO][pP][tT]|[rR][uU][sS][tT][cC]_[wW][rR][aA][pP][pP][eE][rR]|[sS][sS][lL][kK][eE][yY][lL][oO][gG][fF][iI][lL][eE]|[sS][sS][lL]_[cC][eE][rR][tT]_[dD][iI][rR]|[sS][sS][lL]_[cC][eE][rR][tT]_[fF][iI][lL][eE]|[sS][sS][hH]_[aA][uU][tT][hH]_[sS][oO][cC][kK]|[sS][uU][dD][oO]_[aA][sS][kK][pP][aA][sS][sS]|[zZ][dD][oO][tT][dD][iI][rR]|_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS])$)(?!.*(?:[tT][oO][kK][eE][nN]|[sS][eE][cC][rR][eE][tT]|[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][dD]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[aA][pP][iI]_[kK][eE][yY]|[pP][rR][iI][vV][aA][tT][eE]_[kK][eE][yY]|[aA][cC][cC][eE][sS][sS]_[kK][eE][yY]|[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]))[A-Za-z_][A-Za-z0-9_]*$"
        )
    ]
):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: constr(
        pattern=r"^(?!(?:[lL][dD]_|[dD][yY][lL][dD]_|[bB][aA][sS][hH]_[fF][uU][nN][cC]_|[mM][aA][lL][lL][oO][cC]_))(?!(?:[bB][aA][sS][hH]_[eE][nN][vV]|[dD][oO][cC][kK][eE][rR]_[cC][oO][nN][fF][iI][gG]|[eE][nN][vV]|[gG][cC][oO][nN][vV]_[pP][aA][tT][hH]|[gG][eE][mM]_[hH][oO][mM][eE]|[gG][eE][mM]_[pP][aA][tT][hH]|[gG][iI][tT]_[aA][sS][kK][pP][aA][sS][sS]|[gG][lL][iI][bB][cC]_[tT][uU][nN][aA][bB][lL][eE][sS]|[gG][pP][gG]_[aA][gG][eE][nN][tT]_[iI][nN][fF][oO]|[iI][fF][sS]|[jJ][aA][vV][aA]_[tT][oO][oO][lL]_[oO][pP][tT][iI][oO][nN][sS]|[jJ][dD][kK]_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS]|[kK][rR][bB]5[cC][cC][nN][aA][mM][eE]|[lL][oO][cC][pP][aA][tT][hH]|[nN][eE][tT][rR][cC]|[nN][lL][sS][pP][aA][tT][hH]|[nN][oO][dD][eE]_[oO][pP][tT][iI][oO][nN][sS]|[nN][oO][dD][eE]_[pP][aA][tT][hH]|[nN][pP][mM]_[cC][oO][nN][fF][iI][gG]_[uU][sS][eE][rR][cC][oO][nN][fF][iI][gG]|[pP][eE][rR][lL]5[oO][pP][tT]|[pP][eE][rR][lL]5[lL][iI][bB]|[pP][yY][tT][hH][oO][nN][hH][oO][mM][eE]|[pP][yY][tT][hH][oO][nN][iI][nN][sS][pP][eE][cC][tT]|[pP][yY][tT][hH][oO][nN][pP][aA][tT][hH]|[pP][yY][tT][hH][oO][nN][sS][tT][aA][rR][tT][uU][pP]|[rR][uU][bB][yY][lL][iI][bB]|[rR][uU][bB][yY][oO][pP][tT]|[rR][uU][sS][tT][cC]_[wW][rR][aA][pP][pP][eE][rR]|[sS][sS][lL][kK][eE][yY][lL][oO][gG][fF][iI][lL][eE]|[sS][sS][lL]_[cC][eE][rR][tT]_[dD][iI][rR]|[sS][sS][lL]_[cC][eE][rR][tT]_[fF][iI][lL][eE]|[sS][sS][hH]_[aA][uU][tT][hH]_[sS][oO][cC][kK]|[sS][uU][dD][oO]_[aA][sS][kK][pP][aA][sS][sS]|[zZ][dD][oO][tT][dD][iI][rR]|_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS])$)(?!.*(?:[tT][oO][kK][eE][nN]|[sS][eE][cC][rR][eE][tT]|[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][dD]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[aA][pP][iI]_[kK][eE][yY]|[pP][rR][iI][vV][aA][tT][eE]_[kK][eE][yY]|[aA][cC][cC][eE][sS][sS]_[kK][eE][yY]|[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]))[A-Za-z_][A-Za-z0-9_]*$"
    )


class NativeSyscallProfile(Enum):
    native_minimal_v1 = "native_minimal_v1"
    native_standard_v1 = "native_standard_v1"
    brokered_native_v1 = "brokered_native_v1"


class TargetArgvItem(RootModel[constr(pattern=r"^[^\u0000]*$", max_length=16384)]):
    root: constr(pattern=r"^[^\u0000]*$", max_length=16384)


class Runtime(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cage_init_path: AbsoluteCanonicalPath
    cage_init_binding_digest: Digest
    target_path: AbsoluteCanonicalPath
    target_binding_digest: Digest
    working_directory: AbsoluteCanonicalPath
    runtime_files: list[AbsoluteCanonicalPath] = Field(..., max_length=48)
    target_argv: list[TargetArgvItem] = Field(..., max_length=256, min_length=1)
    execution_identity: cage_init_plan_v2_schema.ExecutionIdentity


class Limits(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_artifact_bytes: conint(ge=1, le=268435456)
    launch_timeout_ms: conint(ge=1, le=60000)
    nofile_soft: Literal[192]
    nofile_hard: Literal[192]


class ReceiptRuntime(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    database_path: AbsoluteCanonicalPath
    signer_seed_path: AbsoluteCanonicalPath
    trusted_signer_public_key: PublicKey
    capability_id: Identifier
    tenant_id: Identifier | None = None


class MigrationKey(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    deployment_id: Identifier
    scope_kind: Literal["tool_server"]
    scope_id: Identifier
    control: Literal["cage_enforcement"]


class NonzeroDigest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class NonzeroDigest32(RootModel[list[NonzeroDigest32Item]]):
    root: list[NonzeroDigest32Item] = Field(..., max_length=32, min_length=32)


class MinimumGeneration(Enum):
    int_0 = 0
    int_1 = 1
    int_2 = 2
    int_3 = 3


class MinimumHead(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    key: MigrationKey
    minimum_generation: MinimumGeneration
    transition_digest: NonzeroDigest32


class Stage(Enum):
    disabled = "disabled"
    shadow = "shadow"
    enforced = "enforced"
    legacy_removed = "legacy_removed"


class EnterpriseMigration(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state_database_path: AbsoluteCanonicalPath
    deployment_id: Identifier
    stage: Stage
    trusted_transition_signers: list[PublicKey] = Field(
        ..., max_length=16, min_length=1
    )
    minimum_head: MinimumHead


class BrokerPeerIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    pid: conint(ge=1, le=4294967295)
    uid: conint(ge=0, le=4294967295)
    gid: conint(ge=0, le=4294967295)


class BrokerBinding1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    inherited_fd: conint(ge=3, le=2147483647)
    socket_path: AbsoluteCanonicalPath | None = None
    authentication_digest: Digest
    expected_peer_identity: BrokerPeerIdentity


class BrokerBinding2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    inherited_fd: conint(ge=3, le=2147483647) | None = None
    socket_path: AbsoluteCanonicalPath
    authentication_digest: Digest
    expected_peer_identity: BrokerPeerIdentity


class BrokerBinding(RootModel[BrokerBinding1 | BrokerBinding2]):
    root: BrokerBinding1 | BrokerBinding2


class OperatorCeilings(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    read_paths: list[AbsoluteCanonicalPath]
    write_paths: list[AbsoluteCanonicalPath]
    network_destinations: list[tool_manifest_v2_schema.NetworkDestination]
    environment_variables: list[EnvironmentVariable]
    native_syscall_profiles: list[NativeSyscallProfile] = Field(..., min_length=1)
    forbidden_paths: list[AbsoluteCanonicalPath]


class PolicyBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.mcp.cage-launch-policy.v2"] = Field(..., alias="schema")
    signed_manifest: signed_tool_manifest_v2_schema.ChioSignedToolManifestV2
    registered_public_key: PublicKey
    operator_ceilings: OperatorCeilings
    runtime: Runtime
    limits: Limits
    receipt: ReceiptRuntime
    enterprise_migration: EnterpriseMigration
    broker: BrokerBinding | None = None


class ChioSignedMcpCageLaunchPolicyV2(BaseModel):
    """
    Canonical signed operator policy for a migration-enforced MCP stdio cage launch.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    body: PolicyBody
    signer_public_key: PublicKey
    signature: Signature
