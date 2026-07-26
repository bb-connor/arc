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
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class AbsoluteCanonicalPath(RootModel[str]):
    model_config = ConfigDict(
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            min_length=2,
            pattern="^/(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*\\/$)[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        ),
    ]


class BrokerPeerIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    gid: Annotated[int, Field(ge=0, le=4294967295)]
    pid: Annotated[int, Field(ge=1, le=4294967295)]
    uid: Annotated[int, Field(ge=0, le=4294967295)]


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Environment(RootModel[dict[str, str]]):
    root: Annotated[
        dict[str, str],
        Field(max_length=16384, pattern="^[^\\u0000-\\u001F\\u007F-\\u009F]*$"),
    ]


class SupplementaryGid(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=4294967294)]


class ExecutionIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    gid: Annotated[int, Field(ge=1, le=4294967294)]
    supplementary_gids: Annotated[list[SupplementaryGid], Field(max_length=64)]
    uid: Annotated[int, Field(ge=1, le=4294967294)]


class FdTable1(BaseModel):
    pass


class Kind(Enum):
    regular_file = "regular_file"
    directory = "directory"
    unix_socket = "unix_socket"


class FileIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    device: Annotated[int, Field(ge=0, le=18446744073709551615)]
    gid: Annotated[int, Field(ge=0, le=4294967295)]
    inode: Annotated[int, Field(ge=0, le=18446744073709551615)]
    kind: Kind
    mode: Annotated[int, Field(ge=0, le=4294967295)]
    mount_id: Annotated[int, Field(ge=0, le=18446744073709551615)]
    uid: Annotated[int, Field(ge=0, le=4294967295)]


class Access(Enum):
    read = "read"
    read_directory = "read_directory"
    write_exact_file = "write_exact_file"
    execute_read = "execute_read"


class Kind5(Enum):
    regular_file = "regular_file"
    directory = "directory"


class PathIdentity(FileIdentity):
    kind: Kind5


class PurposeBrokerIpc(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["broker_ipc"]


class PurposeCageInitHelper(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["cage_init_helper"]


class Kind6(Enum):
    runtime_file = "runtime_file"
    read_grant = "read_grant"
    write_grant = "write_grant"


class PurposeIndexedResource(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    index: Annotated[int, Field(ge=0, le=63)]
    kind: Kind6


class PurposeTargetExecutable(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["target_executable"]


class PurposeTargetStderr(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["target_stderr"]


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


class PurposeWorkingDirectory(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["working_directory"]


class RegularFileIdentity(FileIdentity):
    kind: Literal["regular_file"]


class ResourceLimits(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nofile_hard: Literal[192]
    nofile_soft: Literal[192]


class AllowedSyscall(RootModel[str]):
    root: Annotated[str, Field(pattern="^[a-z][a-z0-9_]*$")]


class Profile(Enum):
    native_minimal_v1 = "native_minimal_v1"
    native_standard_v1 = "native_standard_v1"
    brokered_native_v1 = "brokered_native_v1"


class SocketIdentity(FileIdentity):
    kind: Literal["unix_socket"]


class SyscallArgumentConstraint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    argument_index: Annotated[int, Field(ge=0, le=5)]
    comparison: Literal["equal"]
    value: Annotated[int, Field(ge=0, le=18446744073709551615)]


class TargetArgvItem(RootModel[str]):
    root: Annotated[str, Field(max_length=16384, pattern="^[^\\u0000]*$")]


class TargetArgv(RootModel[list[TargetArgvItem]]):
    root: Annotated[list[TargetArgvItem], Field(max_length=256, min_length=1)]


class DirectoryIdentity(FileIdentity):
    kind: Literal["directory"]


class Purpose(PurposeIndexedResource):
    kind: Literal["runtime_file"] = "runtime_file"


class Purpose1(PurposeIndexedResource):
    kind: Literal["read_grant"] = "read_grant"


class Purpose2(PurposeIndexedResource):
    kind: Literal["write_grant"] = "write_grant"


class FdEntryBase(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    binding_digest: Digest | None = None
    broker_peer_identity: BrokerPeerIdentity | None = None
    close_on_exec: bool
    identity: FileIdentity
    path: AbsoluteCanonicalPath | None = None
    purpose: dict[str, Any]
    slot: int


class FilesystemGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    access: Access
    fd_slot: Annotated[int, Field(ge=5, le=191)]
    identity: PathIdentity


class ForbiddenResource(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    identity: PathIdentity
    path: AbsoluteCanonicalPath


class LandlockPlan(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    default_filesystem_deny: Literal[True]
    forbidden_resources: list[ForbiddenResource]
    grants: list[FilesystemGrant]
    network_mode: Literal["blocked"]


class SeccompPlan(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowed_syscalls: Annotated[list[AllowedSyscall], Field(min_length=1)]
    architecture: Literal["x86_64"]
    argument_constraints: dict[str, list[SyscallArgumentConstraint]]
    default_action: Literal["kill_process"]
    profile: Profile


class StdioEntry(FdEntryBase):
    binding_digest: None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True
    identity: SocketIdentity | None = None
    path: None = None


class ArtifactEntry(FdEntryBase):
    binding_digest: Digest | None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True
    path: AbsoluteCanonicalPath | None = None


class FdEntry1(ArtifactEntry):
    identity: RegularFileIdentity | None = None
    purpose: PurposeCageInitHelper | None = None
    slot: Literal[5] = 5


class FdEntry2(ArtifactEntry):
    identity: RegularFileIdentity | None = None
    purpose: PurposeTargetExecutable | None = None
    slot: Literal[255] = 255


class FdEntry3(ArtifactEntry):
    identity: DirectoryIdentity | None = None
    purpose: PurposeWorkingDirectory | None = None
    slot: Literal[6] = 6


class FdEntry4(StdioEntry):
    purpose: PurposeTargetStdin | None = None
    slot: Literal[7] = 7


class FdEntry5(StdioEntry):
    purpose: PurposeTargetStdout | None = None
    slot: Literal[9] = 9


class FdEntry6(StdioEntry):
    purpose: PurposeTargetStderr | None = None
    slot: Literal[10] = 10


class FdEntry7(ArtifactEntry):
    identity: RegularFileIdentity | None = None
    purpose: Purpose | None = None
    slot: Annotated[int | None, Field(ge=16, le=63)] = None


class FdEntry8(FdEntryBase):
    binding_digest: None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True
    identity: PathIdentity | None = None
    path: AbsoluteCanonicalPath | None = None
    purpose: Purpose1 | None = None
    slot: Annotated[int | None, Field(ge=64, le=127)] = None


class FdEntry9(FdEntryBase):
    binding_digest: None = None
    broker_peer_identity: None = None
    close_on_exec: Literal[True] = True
    identity: RegularFileIdentity | None = None
    path: AbsoluteCanonicalPath | None = None
    purpose: Purpose2 | None = None
    slot: Annotated[int | None, Field(ge=128, le=191)] = None


class FdEntry10(FdEntryBase):
    binding_digest: Digest | None = None
    broker_peer_identity: BrokerPeerIdentity | None = None
    close_on_exec: Literal[False] = False
    identity: SocketIdentity | None = None
    path: None = None
    purpose: PurposeBrokerIpc | None = None
    slot: Literal[8] = 8


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


class FdTable(RootModel[list[FdEntry] | FdTable1]):
    root: Annotated[list[FdEntry] | FdTable1, Field(max_length=191, min_length=6)]


class ChioCageInitPlanV2(BaseModel):
    """
    Canonical, unsigned, launch-bound cage-init plan body consumed from a sealed descriptor after the parent binds target stdin, stdout, and stderr. The pre-launch CompiledCage inspection view is not an instance of this wire schema. Launch-envelope transport bindings and the aggregate 65536-byte UTF-8 environment limit are enforced by the cage runtime outside this structural schema.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    broker_authentication_digest: Digest | None = None
    compiler_version: Literal["chio-cage-compiler.v2"]
    environment: Environment
    execution_identity: ExecutionIdentity
    fd_table: FdTable
    helper_fd_slot: Literal[5]
    landlock: LandlockPlan
    manifest_digest: Digest
    plan_fd_slot: Literal[3]
    profile_digest: Digest
    resource_limits: ResourceLimits
    schema_: Annotated[Literal["chio.cage.init-plan.v2"], Field(alias="schema")]
    seccomp: SeccompPlan
    status_fd_slot: Literal[4]
    target_argv: TargetArgv
    target_fd_slot: Literal[255]
    working_directory_fd_slot: Literal[6]
