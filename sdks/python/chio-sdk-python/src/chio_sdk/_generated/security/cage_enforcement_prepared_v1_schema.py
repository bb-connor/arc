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

from . import cage_init_plan_v2_schema


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


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


class ChioCageEnforcementPreparedEvidenceV1(BaseModel):
    """
    Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cage.enforcement-prepared.v1"] = Field(..., alias="schema")
    process_id: conint(ge=1, le=4294967295)
    manifest_digest: Digest
    profile_digest: Digest
    plan_digest: Digest
    fd_table_digest: Digest
    helper_binding_digest: Digest
    target_binding_digest: Digest
    target_identity: RegularFileIdentity
    applied_execution_identity: cage_init_plan_v2_schema.ExecutionIdentity
    nono_version: Literal["0.53.0"]
    nono_patch_version: Literal["chio.2"]
    landlock_abi: conint(ge=4, le=4294967295)
    landlock_filesystem_status: Literal["fully_enforced"]
    landlock_network_status: Literal["fully_enforced"]
    seccompiler_version: Literal["0.5.0"]
    seccomp_status: Literal["fully_enforced"]
    seccomp_architecture: Literal["x86_64"]
    seccomp_filter_digest: Digest
    trace_session_digest: Digest
    prepared_at_unix_ms: conint(ge=1, le=18446744073709551615)
