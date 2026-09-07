# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class SupplementaryGid(RootModel[conint(ge=1, le=4294967294)]):
    root: conint(ge=1, le=4294967294)


class ExecutionIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    uid: conint(ge=1, le=4294967294)
    gid: conint(ge=1, le=4294967294)
    supplementary_gids: list[SupplementaryGid] = Field(..., max_length=64)


class AbsoluteCanonicalPath(RootModel):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: constr(
        pattern=r"^/(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*\/$)[^\u0000-\u001F\u007F-\u009F]+$",
        min_length=2,
    )


class TargetArgvItem(RootModel[constr(pattern=r"^[^\u0000]*$", max_length=16384)]):
    root: constr(pattern=r"^[^\u0000]*$", max_length=16384)


class TargetArgv(RootModel[list[TargetArgvItem]]):
    root: list[TargetArgvItem] = Field(..., max_length=256, min_length=1)


class Kind(Enum):
    regular_file = "regular_file"
    directory = "directory"
    unix_socket = "unix_socket"


class FileIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    device: conint(ge=0, le=18446744073709551615)
    inode: conint(ge=0, le=18446744073709551615)
    mount_id: conint(ge=0, le=18446744073709551615)
    mode: conint(ge=0, le=4294967295)
    uid: conint(ge=0, le=4294967295)
    gid: conint(ge=0, le=4294967295)
    kind: Kind


class RegularFileIdentity(FileIdentity):
    kind: Literal["regular_file"]


class DirectoryIdentity(FileIdentity):
    kind: Literal["directory"]


class SocketIdentity(FileIdentity):
    kind: Literal["unix_socket"]


class Kind5(Enum):
    regular_file = "regular_file"
    directory = "directory"


class PathIdentity(FileIdentity):
    kind: Kind5


class BrokerPeerIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    pid: conint(ge=1, le=4294967295)
    uid: conint(ge=0, le=4294967295)
    gid: conint(ge=0, le=4294967295)


class PurposeCageInitHelper(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["cage_init_helper"]


class PurposeTargetExecutable(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["target_executable"]


class PurposeWorkingDirectory(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["working_directory"]


class PurposeTargetStdin(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["target_stdin"]


class PurposeTargetStdout(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["target_stdout"]


class PurposeTargetStderr(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["target_stderr"]


class Kind6(Enum):
    runtime_file = "runtime_file"
    read_grant = "read_grant"
    write_grant = "write_grant"


class PurposeIndexedResource(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind6
    index: conint(ge=0, le=63)


class PurposeBrokerIpc(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["broker_ipc"]


class FdEntryBase(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    slot: int
    purpose: dict[str, Any]
    identity: FileIdentity
    path: AbsoluteCanonicalPath | None = None
    binding_digest: Digest | None = None
    broker_peer_identity: BrokerPeerIdentity | None = None
    close_on_exec: bool


class ArtifactEntry(FdEntryBase):
    path: AbsoluteCanonicalPath | None = None
    binding_digest: Digest | None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True


class StdioEntry(FdEntryBase):
    identity: SocketIdentity | None = None
    path: None = None
    binding_digest: None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True


class FdEntry1(ArtifactEntry):
    slot: Literal[5] = 5
    purpose: PurposeCageInitHelper | None = None
    identity: RegularFileIdentity | None = None


class FdEntry2(ArtifactEntry):
    slot: Literal[255] = 255
    purpose: PurposeTargetExecutable | None = None
    identity: RegularFileIdentity | None = None


class FdEntry3(ArtifactEntry):
    slot: Literal[6] = 6
    purpose: PurposeWorkingDirectory | None = None
    identity: DirectoryIdentity | None = None


class FdEntry4(StdioEntry):
    slot: Literal[7] = 7
    purpose: PurposeTargetStdin | None = None


class FdEntry5(StdioEntry):
    slot: Literal[9] = 9
    purpose: PurposeTargetStdout | None = None


class FdEntry6(StdioEntry):
    slot: Literal[10] = 10
    purpose: PurposeTargetStderr | None = None


class Purpose(PurposeIndexedResource):
    kind: Literal["runtime_file"] = "runtime_file"


class FdEntry7(ArtifactEntry):
    slot: conint(ge=16, le=63) | None = None
    purpose: Purpose | None = None
    identity: RegularFileIdentity | None = None


class Purpose1(PurposeIndexedResource):
    kind: Literal["read_grant"] = "read_grant"


class FdEntry8(FdEntryBase):
    slot: conint(ge=64, le=127) | None = None
    purpose: Purpose1 | None = None
    identity: PathIdentity | None = None
    path: AbsoluteCanonicalPath | None = None
    binding_digest: None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True


class Purpose2(PurposeIndexedResource):
    kind: Literal["write_grant"] = "write_grant"


class FdEntry9(FdEntryBase):
    slot: conint(ge=128, le=191) | None = None
    purpose: Purpose2 | None = None
    identity: RegularFileIdentity | None = None
    path: AbsoluteCanonicalPath | None = None
    binding_digest: None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True


class FdEntry10(FdEntryBase):
    slot: Literal[8] = 8
    purpose: PurposeBrokerIpc | None = None
    identity: SocketIdentity | None = None
    path: None = None
    binding_digest: Digest | None = None
    broker_peer_identity: BrokerPeerIdentity | None = None
    close_on_exec: Literal[False] = False


class FdEntry(
    RootModel[
        FdEntry1
        | FdEntry2
        | FdEntry3
        | FdEntry4
        | FdEntry5
        | FdEntry6
        | FdEntry7
        | FdEntry8
        | FdEntry9
        | FdEntry10
    ]
):
    root: (
        FdEntry1
        | FdEntry2
        | FdEntry3
        | FdEntry4
        | FdEntry5
        | FdEntry6
        | FdEntry7
        | FdEntry8
        | FdEntry9
        | FdEntry10
    )


class FdTable1(BaseModel):
    pass


class FdTable(RootModel[list[FdEntry] | FdTable1]):
    root: list[FdEntry] | FdTable1 = Field(..., max_length=191, min_length=6)


class ForbiddenResource(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    path: AbsoluteCanonicalPath
    identity: PathIdentity


class Access(Enum):
    read = "read"
    read_directory = "read_directory"
    write_exact_file = "write_exact_file"
    execute_read = "execute_read"


class FilesystemGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    fd_slot: conint(ge=5, le=191)
    access: Access
    identity: PathIdentity


class LandlockPlan(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    default_filesystem_deny: Literal[True]
    network_mode: Literal["blocked"]
    forbidden_resources: list[ForbiddenResource]
    grants: list[FilesystemGrant]


class SyscallArgumentConstraint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    argument_index: conint(ge=0, le=5)
    comparison: Literal["equal"]
    value: conint(ge=0, le=18446744073709551615)


class Profile(Enum):
    native_minimal_v1 = "native_minimal_v1"
    native_standard_v1 = "native_standard_v1"
    brokered_native_v1 = "brokered_native_v1"


class AllowedSyscall(RootModel[constr(pattern=r"^[a-z][a-z0-9_]*$")]):
    root: constr(pattern=r"^[a-z][a-z0-9_]*$")


class SeccompPlan(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    architecture: Literal["x86_64"]
    profile: Profile
    default_action: Literal["kill_process"]
    allowed_syscalls: list[AllowedSyscall] = Field(..., min_length=1)
    argument_constraints: dict[str, list[SyscallArgumentConstraint]]


class ResourceLimits(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nofile_soft: Literal[192]
    nofile_hard: Literal[192]


class Environment(
    RootModel[
        dict[str, constr(pattern=r"^[^\u0000-\u001F\u007F-\u009F]*$", max_length=16384)]
    ]
):
    root: dict[
        str, constr(pattern=r"^[^\u0000-\u001F\u007F-\u009F]*$", max_length=16384)
    ]


class ChioCageInitPlanV2(BaseModel):
    """
    Canonical, unsigned, launch-bound cage-init plan body consumed from a sealed descriptor after the parent binds target stdin, stdout, and stderr. The pre-launch CompiledCage inspection view is not an instance of this wire schema. Launch-envelope transport bindings and the aggregate 65536-byte UTF-8 environment limit are enforced by the cage runtime outside this structural schema.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cage.init-plan.v2"] = Field(..., alias="schema")
    compiler_version: Literal["chio-cage-compiler.v2"]
    manifest_digest: Digest
    profile_digest: Digest
    plan_fd_slot: Literal[3]
    status_fd_slot: Literal[4]
    helper_fd_slot: Literal[5]
    target_fd_slot: Literal[255]
    working_directory_fd_slot: Literal[6]
    target_argv: TargetArgv
    fd_table: FdTable
    landlock: LandlockPlan
    seccomp: SeccompPlan
    resource_limits: ResourceLimits
    execution_identity: ExecutionIdentity
    environment: Environment
    broker_authentication_digest: Digest | None = None
