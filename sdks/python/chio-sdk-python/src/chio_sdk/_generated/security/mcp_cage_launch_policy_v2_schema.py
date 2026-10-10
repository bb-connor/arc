# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 35f8e30cf30553986a159b074ee485804a85db29547a8102522cd7bfa3080d2e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from . import cage_init_plan_v2_schema, signed_tool_manifest_v2_schema, tool_manifest_v2_schema

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class PublicKey(RootModel[constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')

class Signature(RootModel[constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

class Identifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

class AbsoluteCanonicalPath(RootModel):
    model_config = ConfigDict(regex_engine='python-re')
    root: constr(pattern='^/(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*\\/$)[^\\u0000-\\u001F\\u007F-\\u009F]+$', min_length=2)

class EnvironmentVariable(RootModel):
    model_config = ConfigDict(regex_engine='python-re')
    root: constr(pattern='^(?!(?:[lL][dD]_|[dD][yY][lL][dD]_|[bB][aA][sS][hH]_[fF][uU][nN][cC]_|[mM][aA][lL][lL][oO][cC]_))(?!(?:[bB][aA][sS][hH]_[eE][nN][vV]|[dD][oO][cC][kK][eE][rR]_[cC][oO][nN][fF][iI][gG]|[eE][nN][vV]|[gG][cC][oO][nN][vV]_[pP][aA][tT][hH]|[gG][eE][mM]_[hH][oO][mM][eE]|[gG][eE][mM]_[pP][aA][tT][hH]|[gG][iI][tT]_[aA][sS][kK][pP][aA][sS][sS]|[gG][lL][iI][bB][cC]_[tT][uU][nN][aA][bB][lL][eE][sS]|[gG][pP][gG]_[aA][gG][eE][nN][tT]_[iI][nN][fF][oO]|[iI][fF][sS]|[jJ][aA][vV][aA]_[tT][oO][oO][lL]_[oO][pP][tT][iI][oO][nN][sS]|[jJ][dD][kK]_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS]|[kK][rR][bB]5[cC][cC][nN][aA][mM][eE]|[lL][oO][cC][pP][aA][tT][hH]|[nN][eE][tT][rR][cC]|[nN][lL][sS][pP][aA][tT][hH]|[nN][oO][dD][eE]_[oO][pP][tT][iI][oO][nN][sS]|[nN][oO][dD][eE]_[pP][aA][tT][hH]|[nN][pP][mM]_[cC][oO][nN][fF][iI][gG]_[uU][sS][eE][rR][cC][oO][nN][fF][iI][gG]|[pP][eE][rR][lL]5[oO][pP][tT]|[pP][eE][rR][lL]5[lL][iI][bB]|[pP][yY][tT][hH][oO][nN][hH][oO][mM][eE]|[pP][yY][tT][hH][oO][nN][iI][nN][sS][pP][eE][cC][tT]|[pP][yY][tT][hH][oO][nN][pP][aA][tT][hH]|[pP][yY][tT][hH][oO][nN][sS][tT][aA][rR][tT][uU][pP]|[rR][uU][bB][yY][lL][iI][bB]|[rR][uU][bB][yY][oO][pP][tT]|[rR][uU][sS][tT][cC]_[wW][rR][aA][pP][pP][eE][rR]|[sS][sS][lL][kK][eE][yY][lL][oO][gG][fF][iI][lL][eE]|[sS][sS][lL]_[cC][eE][rR][tT]_[dD][iI][rR]|[sS][sS][lL]_[cC][eE][rR][tT]_[fF][iI][lL][eE]|[sS][sS][hH]_[aA][uU][tT][hH]_[sS][oO][cC][kK]|[sS][uU][dD][oO]_[aA][sS][kK][pP][aA][sS][sS]|[zZ][dD][oO][tT][dD][iI][rR]|_[jJ][aA][vV][aA]_[oO][pP][tT][iI][oO][nN][sS])$)(?!.*(?:[tT][oO][kK][eE][nN]|[sS][eE][cC][rR][eE][tT]|[pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][dD]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[aA][pP][iI]_[kK][eE][yY]|[pP][rR][iI][vV][aA][tT][eE]_[kK][eE][yY]|[aA][cC][cC][eE][sS][sS]_[kK][eE][yY]|[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]))[A-Za-z_][A-Za-z0-9_]*$')

class SecurityMcpCageLaunchPolicyV2DefinitionsOperatorCeilingsNativeSyscallProfilesItems(Enum):
    native_minimal_v1 = 'native_minimal_v1'
    native_standard_v1 = 'native_standard_v1'
    brokered_native_v1 = 'brokered_native_v1'

class TargetArgvItem(RootModel[constr(pattern='^[^\\u0000]*$', max_length=16384)]):
    root: constr(pattern='^[^\\u0000]*$', max_length=16384)

class SecurityMcpCageLaunchPolicyV2DefinitionsRuntime(BaseModel):
    model_config = ConfigDict(extra='forbid')
    cage_init_path: AbsoluteCanonicalPath
    cage_init_binding_digest: Digest
    target_path: AbsoluteCanonicalPath
    target_binding_digest: Digest
    working_directory: AbsoluteCanonicalPath
    runtime_files: list[AbsoluteCanonicalPath] = Field(..., max_length=48)
    target_argv: list[TargetArgvItem] = Field(..., max_length=256, min_length=1)
    execution_identity: cage_init_plan_v2_schema.SecurityCageInitPlanV2DefinitionsExecutionIdentity

class SecurityMcpCageLaunchPolicyV2DefinitionsLimits(BaseModel):
    model_config = ConfigDict(extra='forbid')
    max_artifact_bytes: conint(ge=1, le=268435456)
    launch_timeout_ms: conint(ge=1, le=60000)
    nofile_soft: Literal[192]
    nofile_hard: Literal[192]

class SecurityMcpCageLaunchPolicyV2DefinitionsReceiptRuntime(BaseModel):
    model_config = ConfigDict(extra='forbid')
    database_path: AbsoluteCanonicalPath
    signer_seed_path: AbsoluteCanonicalPath
    trusted_signer_public_key: PublicKey
    capability_id: Identifier
    tenant_id: Identifier | None = None

class SecurityMcpCageLaunchPolicyV2DefinitionsMigrationKey(BaseModel):
    model_config = ConfigDict(extra='forbid')
    deployment_id: Identifier
    scope_kind: Literal['tool_server']
    scope_id: Identifier
    control: Literal['cage_enforcement']

class NonzeroDigest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class NonzeroDigest32(RootModel[list[NonzeroDigest32Item]]):
    root: list[NonzeroDigest32Item] = Field(..., max_length=32, min_length=32)

class SecurityMcpCageLaunchPolicyV2DefinitionsMinimumHeadMinimumGeneration(Enum):
    int_0 = 0
    int_1 = 1
    int_2 = 2
    int_3 = 3

class SecurityMcpCageLaunchPolicyV2DefinitionsMinimumHead(BaseModel):
    model_config = ConfigDict(extra='forbid')
    key: SecurityMcpCageLaunchPolicyV2DefinitionsMigrationKey
    minimum_generation: SecurityMcpCageLaunchPolicyV2DefinitionsMinimumHeadMinimumGeneration
    transition_digest: NonzeroDigest32

class SecurityMcpCageLaunchPolicyV2DefinitionsEnterpriseMigrationStage(Enum):
    disabled = 'disabled'
    shadow = 'shadow'
    enforced = 'enforced'
    legacy_removed = 'legacy_removed'

class SecurityMcpCageLaunchPolicyV2DefinitionsEnterpriseMigration(BaseModel):
    model_config = ConfigDict(extra='forbid')
    state_database_path: AbsoluteCanonicalPath
    deployment_id: Identifier
    stage: SecurityMcpCageLaunchPolicyV2DefinitionsEnterpriseMigrationStage
    trusted_transition_signers: list[PublicKey] = Field(..., max_length=16, min_length=1)
    minimum_head: SecurityMcpCageLaunchPolicyV2DefinitionsMinimumHead

class SecurityMcpCageLaunchPolicyV2DefinitionsBrokerPeerIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid')
    pid: conint(ge=1, le=4294967295)
    uid: conint(ge=0, le=4294967295)
    gid: conint(ge=0, le=4294967295)

class SecurityMcpCageLaunchPolicyV2DefinitionsBrokerBinding(BaseModel):
    model_config = ConfigDict(extra='forbid')
    inherited_fd: conint(ge=3, le=2147483647)
    socket_path: AbsoluteCanonicalPath | None = None
    authentication_digest: Digest
    expected_peer_identity: SecurityMcpCageLaunchPolicyV2DefinitionsBrokerPeerIdentity

class SecurityMcpCageLaunchPolicyV2DefinitionsBrokerBinding1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    inherited_fd: conint(ge=3, le=2147483647) | None = None
    socket_path: AbsoluteCanonicalPath
    authentication_digest: Digest
    expected_peer_identity: SecurityMcpCageLaunchPolicyV2DefinitionsBrokerPeerIdentity

class BrokerBinding(RootModel[SecurityMcpCageLaunchPolicyV2DefinitionsBrokerBinding | SecurityMcpCageLaunchPolicyV2DefinitionsBrokerBinding1]):
    root: SecurityMcpCageLaunchPolicyV2DefinitionsBrokerBinding | SecurityMcpCageLaunchPolicyV2DefinitionsBrokerBinding1

class SecurityMcpCageLaunchPolicyV2DefinitionsOperatorCeilings(BaseModel):
    model_config = ConfigDict(extra='forbid')
    read_paths: list[AbsoluteCanonicalPath]
    write_paths: list[AbsoluteCanonicalPath]
    network_destinations: list[tool_manifest_v2_schema.SecurityToolManifestV2DefinitionsNetworkDestination]
    environment_variables: list[EnvironmentVariable]
    native_syscall_profiles: list[SecurityMcpCageLaunchPolicyV2DefinitionsOperatorCeilingsNativeSyscallProfilesItems] = Field(..., min_length=1)
    forbidden_paths: list[AbsoluteCanonicalPath]

class SecurityMcpCageLaunchPolicyV2DefinitionsPolicyBody(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.mcp.cage-launch-policy.v2'] = Field(..., alias='schema')
    signed_manifest: signed_tool_manifest_v2_schema.ChioSignedToolManifestV2
    registered_public_key: PublicKey
    operator_ceilings: SecurityMcpCageLaunchPolicyV2DefinitionsOperatorCeilings
    runtime: SecurityMcpCageLaunchPolicyV2DefinitionsRuntime
    limits: SecurityMcpCageLaunchPolicyV2DefinitionsLimits
    receipt: SecurityMcpCageLaunchPolicyV2DefinitionsReceiptRuntime
    enterprise_migration: SecurityMcpCageLaunchPolicyV2DefinitionsEnterpriseMigration
    broker: BrokerBinding | None = None

class ChioSignedMCPCageLaunchPolicyV2(BaseModel):
    """
    Canonical signed operator policy for a migration-enforced MCP stdio cage launch.
    """
    model_config = ConfigDict(extra='forbid')
    body: SecurityMcpCageLaunchPolicyV2DefinitionsPolicyBody
    signer_public_key: PublicKey
    signature: Signature

# Public compatibility aliases reference the actual current model classes.
BrokerBinding1 = SecurityMcpCageLaunchPolicyV2DefinitionsBrokerBinding
BrokerBinding2 = SecurityMcpCageLaunchPolicyV2DefinitionsBrokerBinding1
BrokerPeerIdentity = SecurityMcpCageLaunchPolicyV2DefinitionsBrokerPeerIdentity
ChioSignedMcpCageLaunchPolicyV2 = ChioSignedMCPCageLaunchPolicyV2
EnterpriseMigration = SecurityMcpCageLaunchPolicyV2DefinitionsEnterpriseMigration
Limits = SecurityMcpCageLaunchPolicyV2DefinitionsLimits
MigrationKey = SecurityMcpCageLaunchPolicyV2DefinitionsMigrationKey
MinimumGeneration = SecurityMcpCageLaunchPolicyV2DefinitionsMinimumHeadMinimumGeneration
MinimumHead = SecurityMcpCageLaunchPolicyV2DefinitionsMinimumHead
NativeSyscallProfile = SecurityMcpCageLaunchPolicyV2DefinitionsOperatorCeilingsNativeSyscallProfilesItems
OperatorCeilings = SecurityMcpCageLaunchPolicyV2DefinitionsOperatorCeilings
PolicyBody = SecurityMcpCageLaunchPolicyV2DefinitionsPolicyBody
ReceiptRuntime = SecurityMcpCageLaunchPolicyV2DefinitionsReceiptRuntime
Runtime = SecurityMcpCageLaunchPolicyV2DefinitionsRuntime
SecurityMcpCageLaunchPolicyV2AbsoluteCanonicalPath = AbsoluteCanonicalPath
SecurityMcpCageLaunchPolicyV2BrokerBinding = BrokerBinding
SecurityMcpCageLaunchPolicyV2ChioSignedMCPCageLaunchPolicyV2 = ChioSignedMCPCageLaunchPolicyV2
SecurityMcpCageLaunchPolicyV2Digest = Digest
SecurityMcpCageLaunchPolicyV2EnvironmentVariable = EnvironmentVariable
SecurityMcpCageLaunchPolicyV2Identifier = Identifier
SecurityMcpCageLaunchPolicyV2NonzeroDigest32 = NonzeroDigest32
SecurityMcpCageLaunchPolicyV2NonzeroDigest32Item = NonzeroDigest32Item
SecurityMcpCageLaunchPolicyV2PublicKey = PublicKey
SecurityMcpCageLaunchPolicyV2Signature = Signature
SecurityMcpCageLaunchPolicyV2TargetArgvItem = TargetArgvItem
Stage = SecurityMcpCageLaunchPolicyV2DefinitionsEnterpriseMigrationStage
