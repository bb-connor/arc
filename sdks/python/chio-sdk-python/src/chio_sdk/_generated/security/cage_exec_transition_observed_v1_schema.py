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

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class SecurityCageExecTransitionObservedV1DefinitionsFileIdentityKind(Enum):
    regular_file = 'regular_file'
    directory = 'directory'
    unix_socket = 'unix_socket'

class SecurityCageExecTransitionObservedV1DefinitionsFileIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid')
    device: conint(ge=0, le=18446744073709551615)
    inode: conint(ge=0, le=18446744073709551615)
    mount_id: conint(ge=0, le=18446744073709551615)
    mode: conint(ge=0, le=4294967295)
    uid: conint(ge=0, le=4294967295)
    gid: conint(ge=0, le=4294967295)
    kind: SecurityCageExecTransitionObservedV1DefinitionsFileIdentityKind

class RegularFileIdentity(SecurityCageExecTransitionObservedV1DefinitionsFileIdentity):
    kind: Literal['regular_file']

class ChioCageExecTransitionObservationV1(BaseModel):
    """
    Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
    """
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.cage.exec-transition-observed.v1'] = Field(..., alias='schema')
    process_id: conint(ge=1, le=4294967295)
    trace_session_digest: Digest
    target_binding_digest: Digest
    target_identity: RegularFileIdentity
    observed_at_unix_ms: conint(ge=1, le=18446744073709551615)

# Public compatibility aliases reference the actual current model classes.
FileIdentity = SecurityCageExecTransitionObservedV1DefinitionsFileIdentity
Kind = SecurityCageExecTransitionObservedV1DefinitionsFileIdentityKind
SecurityCageExecTransitionObservedV1ChioCageExecTransitionObservationV1 = ChioCageExecTransitionObservationV1
SecurityCageExecTransitionObservedV1Digest = Digest
SecurityCageExecTransitionObservedV1RegularFileIdentity = RegularFileIdentity
