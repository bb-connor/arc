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
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class SupplementaryGid(RootModel[conint(ge=1, le=4294967294)]):
    root: conint(ge=1, le=4294967294)

class SecurityCageInitPlanV2DefinitionsExecutionIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid')
    uid: conint(ge=1, le=4294967294)
    gid: conint(ge=1, le=4294967294)
    supplementary_gids: list[SupplementaryGid] = Field(..., max_length=64)

class AbsoluteCanonicalPath(RootModel):
    model_config = ConfigDict(regex_engine='python-re')
    root: constr(pattern='^/(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*\\/$)[^\\u0000-\\u001F\\u007F-\\u009F]+$', min_length=2)

class TargetArgvItem(RootModel[constr(pattern='^[^\\u0000]*$', max_length=16384)]):
    root: constr(pattern='^[^\\u0000]*$', max_length=16384)

class TargetArgv(RootModel[list[TargetArgvItem]]):
    root: list[TargetArgvItem] = Field(..., max_length=256, min_length=1)

class SecurityCageInitPlanV2DefinitionsFileIdentityKind(Enum):
    regular_file = 'regular_file'
    directory = 'directory'
    unix_socket = 'unix_socket'

class SecurityCageInitPlanV2DefinitionsFileIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid')
    device: conint(ge=0, le=18446744073709551615)
    inode: conint(ge=0, le=18446744073709551615)
    mount_id: conint(ge=0, le=18446744073709551615)
    mode: conint(ge=0, le=4294967295)
    uid: conint(ge=0, le=4294967295)
    gid: conint(ge=0, le=4294967295)
    kind: SecurityCageInitPlanV2DefinitionsFileIdentityKind

class RegularFileIdentity(SecurityCageInitPlanV2DefinitionsFileIdentity):
    kind: Literal['regular_file']

class DirectoryIdentity(SecurityCageInitPlanV2DefinitionsFileIdentity):
    kind: Literal['directory']

class SocketIdentity(SecurityCageInitPlanV2DefinitionsFileIdentity):
    kind: Literal['unix_socket']

class SecurityCageInitPlanV2DefinitionsPathIdentityVariant1Kind(Enum):
    regular_file = 'regular_file'
    directory = 'directory'

class PathIdentity(SecurityCageInitPlanV2DefinitionsFileIdentity):
    kind: SecurityCageInitPlanV2DefinitionsPathIdentityVariant1Kind

class SecurityCageInitPlanV2DefinitionsBrokerPeerIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid')
    pid: conint(ge=1, le=4294967295)
    uid: conint(ge=0, le=4294967295)
    gid: conint(ge=0, le=4294967295)

class SecurityCageInitPlanV2DefinitionsPurposeCageInitHelper(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['cage_init_helper']

class SecurityCageInitPlanV2DefinitionsPurposeTargetExecutable(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['target_executable']

class SecurityCageInitPlanV2DefinitionsPurposeWorkingDirectory(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['working_directory']

class SecurityCageInitPlanV2DefinitionsPurposeTargetStdin(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['target_stdin']

class SecurityCageInitPlanV2DefinitionsPurposeTargetStdout(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['target_stdout']

class SecurityCageInitPlanV2DefinitionsPurposeTargetStderr(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['target_stderr']

class SecurityCageInitPlanV2DefinitionsPurposeIndexedResourceKind(Enum):
    runtime_file = 'runtime_file'
    read_grant = 'read_grant'
    write_grant = 'write_grant'

class SecurityCageInitPlanV2DefinitionsPurposeIndexedResource(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: SecurityCageInitPlanV2DefinitionsPurposeIndexedResourceKind
    index: conint(ge=0, le=63)

class SecurityCageInitPlanV2DefinitionsPurposeBrokerIpc(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['broker_ipc']

class SecurityCageInitPlanV2DefinitionsFdEntryBase(BaseModel):
    model_config = ConfigDict(extra='forbid')
    slot: int
    purpose: dict[str, Any]
    identity: SecurityCageInitPlanV2DefinitionsFileIdentity
    path: AbsoluteCanonicalPath | None = None
    binding_digest: Digest | None = None
    broker_peer_identity: SecurityCageInitPlanV2DefinitionsBrokerPeerIdentity | None = None
    close_on_exec: bool

class ArtifactEntry(SecurityCageInitPlanV2DefinitionsFdEntryBase):
    path: AbsoluteCanonicalPath | None = None
    binding_digest: Digest | None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True

class StdioEntry(SecurityCageInitPlanV2DefinitionsFdEntryBase):
    identity: SocketIdentity | None = None
    path: None = None
    binding_digest: None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True

class SecurityCageInitPlanV2DefinitionsFdEntry(ArtifactEntry):
    slot: Literal[5] = 5
    purpose: SecurityCageInitPlanV2DefinitionsPurposeCageInitHelper | None = None
    identity: RegularFileIdentity | None = None

class SecurityCageInitPlanV2DefinitionsFdEntry1(ArtifactEntry):
    slot: Literal[255] = 255
    purpose: SecurityCageInitPlanV2DefinitionsPurposeTargetExecutable | None = None
    identity: RegularFileIdentity | None = None

class SecurityCageInitPlanV2DefinitionsFdEntry2(ArtifactEntry):
    slot: Literal[6] = 6
    purpose: SecurityCageInitPlanV2DefinitionsPurposeWorkingDirectory | None = None
    identity: DirectoryIdentity | None = None

class SecurityCageInitPlanV2DefinitionsFdEntry3(StdioEntry):
    slot: Literal[7] = 7
    purpose: SecurityCageInitPlanV2DefinitionsPurposeTargetStdin | None = None

class SecurityCageInitPlanV2DefinitionsFdEntry4(StdioEntry):
    slot: Literal[9] = 9
    purpose: SecurityCageInitPlanV2DefinitionsPurposeTargetStdout | None = None

class SecurityCageInitPlanV2DefinitionsFdEntry5(StdioEntry):
    slot: Literal[10] = 10
    purpose: SecurityCageInitPlanV2DefinitionsPurposeTargetStderr | None = None

class Purpose(SecurityCageInitPlanV2DefinitionsPurposeIndexedResource):
    kind: Literal['runtime_file'] = 'runtime_file'

class SecurityCageInitPlanV2DefinitionsFdEntry6(ArtifactEntry):
    slot: conint(ge=16, le=63) | None = None
    purpose: Purpose | None = None
    identity: RegularFileIdentity | None = None

class Purpose1(SecurityCageInitPlanV2DefinitionsPurposeIndexedResource):
    kind: Literal['read_grant'] = 'read_grant'

class SecurityCageInitPlanV2DefinitionsFdEntry7(SecurityCageInitPlanV2DefinitionsFdEntryBase):
    slot: conint(ge=64, le=127) | None = None
    purpose: Purpose1 | None = None
    identity: PathIdentity | None = None
    path: AbsoluteCanonicalPath | None = None
    binding_digest: None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True

class Purpose2(SecurityCageInitPlanV2DefinitionsPurposeIndexedResource):
    kind: Literal['write_grant'] = 'write_grant'

class SecurityCageInitPlanV2DefinitionsFdEntry8(SecurityCageInitPlanV2DefinitionsFdEntryBase):
    slot: conint(ge=128, le=191) | None = None
    purpose: Purpose2 | None = None
    identity: RegularFileIdentity | None = None
    path: AbsoluteCanonicalPath | None = None
    binding_digest: None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True

class SecurityCageInitPlanV2DefinitionsFdEntry9(SecurityCageInitPlanV2DefinitionsFdEntryBase):
    slot: Literal[8] = 8
    purpose: SecurityCageInitPlanV2DefinitionsPurposeBrokerIpc | None = None
    identity: SocketIdentity | None = None
    path: None = None
    binding_digest: Digest | None = None
    broker_peer_identity: SecurityCageInitPlanV2DefinitionsBrokerPeerIdentity | None = None
    close_on_exec: Literal[False] = False

class FdEntry(RootModel[SecurityCageInitPlanV2DefinitionsFdEntry | SecurityCageInitPlanV2DefinitionsFdEntry1 | SecurityCageInitPlanV2DefinitionsFdEntry2 | SecurityCageInitPlanV2DefinitionsFdEntry3 | SecurityCageInitPlanV2DefinitionsFdEntry4 | SecurityCageInitPlanV2DefinitionsFdEntry5 | SecurityCageInitPlanV2DefinitionsFdEntry6 | SecurityCageInitPlanV2DefinitionsFdEntry7 | SecurityCageInitPlanV2DefinitionsFdEntry8 | SecurityCageInitPlanV2DefinitionsFdEntry9]):
    root: SecurityCageInitPlanV2DefinitionsFdEntry | SecurityCageInitPlanV2DefinitionsFdEntry1 | SecurityCageInitPlanV2DefinitionsFdEntry2 | SecurityCageInitPlanV2DefinitionsFdEntry3 | SecurityCageInitPlanV2DefinitionsFdEntry4 | SecurityCageInitPlanV2DefinitionsFdEntry5 | SecurityCageInitPlanV2DefinitionsFdEntry6 | SecurityCageInitPlanV2DefinitionsFdEntry7 | SecurityCageInitPlanV2DefinitionsFdEntry8 | SecurityCageInitPlanV2DefinitionsFdEntry9

class FdTable1(BaseModel):
    pass

class FdTable(RootModel[list[FdEntry] | FdTable1]):
    root: list[FdEntry] | FdTable1 = Field(..., max_length=191, min_length=6)

class SecurityCageInitPlanV2DefinitionsForbiddenResource(BaseModel):
    model_config = ConfigDict(extra='forbid')
    path: AbsoluteCanonicalPath
    identity: PathIdentity

class SecurityCageInitPlanV2DefinitionsFilesystemGrantAccess(Enum):
    read = 'read'
    read_directory = 'read_directory'
    write_exact_file = 'write_exact_file'
    execute_read = 'execute_read'

class SecurityCageInitPlanV2DefinitionsFilesystemGrant(BaseModel):
    model_config = ConfigDict(extra='forbid')
    fd_slot: conint(ge=5, le=191)
    access: SecurityCageInitPlanV2DefinitionsFilesystemGrantAccess
    identity: PathIdentity

class SecurityCageInitPlanV2DefinitionsLandlockPlan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    default_filesystem_deny: Literal[True]
    network_mode: Literal['blocked']
    forbidden_resources: list[SecurityCageInitPlanV2DefinitionsForbiddenResource]
    grants: list[SecurityCageInitPlanV2DefinitionsFilesystemGrant]

class SecurityCageInitPlanV2DefinitionsSyscallArgumentConstraint(BaseModel):
    model_config = ConfigDict(extra='forbid')
    argument_index: conint(ge=0, le=5)
    comparison: Literal['equal']
    value: conint(ge=0, le=18446744073709551615)

class SecurityCageInitPlanV2DefinitionsSeccompPlanProfile(Enum):
    native_minimal_v1 = 'native_minimal_v1'
    native_standard_v1 = 'native_standard_v1'
    brokered_native_v1 = 'brokered_native_v1'

class AllowedSyscall(RootModel[constr(pattern='^[a-z][a-z0-9_]*$')]):
    root: constr(pattern='^[a-z][a-z0-9_]*$')

class SecurityCageInitPlanV2DefinitionsSeccompPlan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    architecture: Literal['x86_64']
    profile: SecurityCageInitPlanV2DefinitionsSeccompPlanProfile
    default_action: Literal['kill_process']
    allowed_syscalls: list[AllowedSyscall] = Field(..., min_length=1)
    argument_constraints: dict[str, list[SecurityCageInitPlanV2DefinitionsSyscallArgumentConstraint]]

class SecurityCageInitPlanV2DefinitionsResourceLimits(BaseModel):
    model_config = ConfigDict(extra='forbid')
    nofile_soft: Literal[192]
    nofile_hard: Literal[192]

class Environment(RootModel[dict[str, constr(pattern='^[^\\u0000-\\u001F\\u007F-\\u009F]*$', max_length=16384)]]):
    root: dict[str, constr(pattern='^[^\\u0000-\\u001F\\u007F-\\u009F]*$', max_length=16384)]

class ChioCageInitPlanV2(BaseModel):
    """
    Canonical, unsigned, launch-bound cage-init plan body consumed from a sealed descriptor after the parent binds target stdin, stdout, and stderr. The pre-launch CompiledCage inspection view is not an instance of this wire schema. Launch-envelope transport bindings and the aggregate 65536-byte UTF-8 environment limit are enforced by the cage runtime outside this structural schema.
    """
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.init-plan.v2'] = Field(..., alias='schema')
    compiler_version: Literal['chio-cage-compiler.v2']
    manifest_digest: Digest
    profile_digest: Digest
    plan_fd_slot: Literal[3]
    status_fd_slot: Literal[4]
    helper_fd_slot: Literal[5]
    target_fd_slot: Literal[255]
    working_directory_fd_slot: Literal[6]
    target_argv: TargetArgv
    fd_table: FdTable
    landlock: SecurityCageInitPlanV2DefinitionsLandlockPlan
    seccomp: SecurityCageInitPlanV2DefinitionsSeccompPlan
    resource_limits: SecurityCageInitPlanV2DefinitionsResourceLimits
    execution_identity: SecurityCageInitPlanV2DefinitionsExecutionIdentity
    environment: Environment
    broker_authentication_digest: Digest | None = None

# Public compatibility aliases reference the actual current model classes.
Access = SecurityCageInitPlanV2DefinitionsFilesystemGrantAccess
BrokerPeerIdentity = SecurityCageInitPlanV2DefinitionsBrokerPeerIdentity
ExecutionIdentity = SecurityCageInitPlanV2DefinitionsExecutionIdentity
FdEntry1 = SecurityCageInitPlanV2DefinitionsFdEntry
FdEntry10 = SecurityCageInitPlanV2DefinitionsFdEntry9
FdEntry2 = SecurityCageInitPlanV2DefinitionsFdEntry1
FdEntry3 = SecurityCageInitPlanV2DefinitionsFdEntry2
FdEntry4 = SecurityCageInitPlanV2DefinitionsFdEntry3
FdEntry5 = SecurityCageInitPlanV2DefinitionsFdEntry4
FdEntry6 = SecurityCageInitPlanV2DefinitionsFdEntry5
FdEntry7 = SecurityCageInitPlanV2DefinitionsFdEntry6
FdEntry8 = SecurityCageInitPlanV2DefinitionsFdEntry7
FdEntry9 = SecurityCageInitPlanV2DefinitionsFdEntry8
FdEntryBase = SecurityCageInitPlanV2DefinitionsFdEntryBase
FileIdentity = SecurityCageInitPlanV2DefinitionsFileIdentity
FilesystemGrant = SecurityCageInitPlanV2DefinitionsFilesystemGrant
ForbiddenResource = SecurityCageInitPlanV2DefinitionsForbiddenResource
Kind = SecurityCageInitPlanV2DefinitionsFileIdentityKind
Kind5 = SecurityCageInitPlanV2DefinitionsPathIdentityVariant1Kind
Kind6 = SecurityCageInitPlanV2DefinitionsPurposeIndexedResourceKind
Kind8 = SecurityCageInitPlanV2DefinitionsPathIdentityVariant1Kind
Kind9 = SecurityCageInitPlanV2DefinitionsPurposeIndexedResourceKind
LandlockPlan = SecurityCageInitPlanV2DefinitionsLandlockPlan
Profile = SecurityCageInitPlanV2DefinitionsSeccompPlanProfile
PurposeBrokerIpc = SecurityCageInitPlanV2DefinitionsPurposeBrokerIpc
PurposeCageInitHelper = SecurityCageInitPlanV2DefinitionsPurposeCageInitHelper
PurposeIndexedResource = SecurityCageInitPlanV2DefinitionsPurposeIndexedResource
PurposeTargetExecutable = SecurityCageInitPlanV2DefinitionsPurposeTargetExecutable
PurposeTargetStderr = SecurityCageInitPlanV2DefinitionsPurposeTargetStderr
PurposeTargetStdin = SecurityCageInitPlanV2DefinitionsPurposeTargetStdin
PurposeTargetStdout = SecurityCageInitPlanV2DefinitionsPurposeTargetStdout
PurposeWorkingDirectory = SecurityCageInitPlanV2DefinitionsPurposeWorkingDirectory
ResourceLimits = SecurityCageInitPlanV2DefinitionsResourceLimits
SeccompPlan = SecurityCageInitPlanV2DefinitionsSeccompPlan
SecurityCageInitPlanV2AbsoluteCanonicalPath = AbsoluteCanonicalPath
SecurityCageInitPlanV2AllowedSyscall = AllowedSyscall
SecurityCageInitPlanV2ArtifactEntry = ArtifactEntry
SecurityCageInitPlanV2ChioCageInitPlanV2 = ChioCageInitPlanV2
SecurityCageInitPlanV2Digest = Digest
SecurityCageInitPlanV2DirectoryIdentity = DirectoryIdentity
SecurityCageInitPlanV2Environment = Environment
SecurityCageInitPlanV2FdEntry = FdEntry
SecurityCageInitPlanV2FdTable = FdTable
SecurityCageInitPlanV2FdTable1 = FdTable1
SecurityCageInitPlanV2PathIdentity = PathIdentity
SecurityCageInitPlanV2Purpose = Purpose
SecurityCageInitPlanV2Purpose1 = Purpose1
SecurityCageInitPlanV2Purpose2 = Purpose2
SecurityCageInitPlanV2RegularFileIdentity = RegularFileIdentity
SecurityCageInitPlanV2SocketIdentity = SocketIdentity
SecurityCageInitPlanV2StdioEntry = StdioEntry
SecurityCageInitPlanV2SupplementaryGid = SupplementaryGid
SecurityCageInitPlanV2TargetArgv = TargetArgv
SecurityCageInitPlanV2TargetArgvItem = TargetArgvItem
SyscallArgumentConstraint = SecurityCageInitPlanV2DefinitionsSyscallArgumentConstraint
