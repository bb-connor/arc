# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


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


class RegularFileIdentity(FileIdentity):
    kind: Literal["regular_file"]


class ChioCageExecTransitionObservationV1(BaseModel):
    """
    Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    observed_at_unix_ms: Annotated[int, Field(ge=1, le=18446744073709551615)]
    process_id: Annotated[int, Field(ge=1, le=4294967295)]
    schema_: Annotated[
        Literal["chio.cage.exec-transition-observed.v1"], Field(alias="schema")
    ]
    target_binding_digest: Digest
    target_identity: RegularFileIdentity
    trace_session_digest: Digest
