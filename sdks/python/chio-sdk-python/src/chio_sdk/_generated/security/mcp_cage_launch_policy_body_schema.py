# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Key(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    control: str
    deployment_id: str
    scope_id: str
    scope_kind: str


class Head(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    key: Key
    transition_digest: list[int]


class EnterpriseMigration(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    deployment_id: str
    head: Head
    state_database_path: str
    trusted_transition_signers: list[str]


class Limits(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    launch_timeout_ms: int
    max_artifact_bytes: int
    nofile_hard: int
    nofile_soft: int


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


class NetworkDestination(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    host: constr(pattern=r"^[^A-Z*\s/]+$", min_length=1, max_length=253)
    port: conint(ge=1, le=65535)


class ReadPath(
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


class WritePath(
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


class OperatorCeilings(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    environment_variables: list[EnvironmentVariable]
    forbidden_paths: list[str]
    native_syscall_profiles: list[str]
    network_destinations: list[NetworkDestination]
    read_paths: list[ReadPath]
    write_paths: list[WritePath]


class Receipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: str
    database_path: str
    signer_seed_path: str
    tenant_id: str
    trusted_signer_public_key: str


class SupplementaryGid(RootModel[conint(ge=1, le=4294967294)]):
    root: conint(ge=1, le=4294967294)


class ExecutionIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    gid: int
    supplementary_gids: list[SupplementaryGid] = Field(..., max_length=64)
    uid: int


class RuntimeFile(
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


class Runtime(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cage_init_binding_digest: str
    cage_init_path: str
    execution_identity: ExecutionIdentity
    runtime_files: list[RuntimeFile] = Field(..., max_length=48)
    target_argv: list[str]
    target_binding_digest: str
    target_path: str
    working_directory: str


class RequiredPermissions(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    native_syscall_profile: str


class Annotations(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    destructive: bool
    idempotent: bool
    read_only: bool
    requires_approval: bool


class InputSchema(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: str


class Tool(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    annotations: Annotations
    description: str
    input_schema: InputSchema
    latency_hint: str
    name: str


class Manifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str
    public_key: str
    required_permissions: RequiredPermissions
    schema_: str = Field(..., alias="schema")
    server_id: str
    tools: list[Tool]
    version: str


class SignedManifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    manifest: Manifest
    signature: str
    signer_key: str


class ChioMcpCageLaunchPolicyV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    enterprise_migration: EnterpriseMigration
    limits: Limits
    operator_ceilings: OperatorCeilings
    receipt: Receipt
    registered_public_key: str
    runtime: Runtime
    schema_: Literal["chio.mcp.cage-launch-policy.v1"] = Field(..., alias="schema")
    signed_manifest: SignedManifest
