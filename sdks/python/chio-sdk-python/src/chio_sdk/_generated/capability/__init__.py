# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
<<<<<<< HEAD
# Schema sha256: e22b26006c4ad64cb91683eb774882242236c16e94fa59e56793f01203f2304c
=======
# Schema sha256: 78f3823cf6fa1cdb5631939980d1e7f2ac23856bfa1d85734671809e66bef0e7
>>>>>>> 41493c3a3 (fix(spec): make schema field optional in v1 token schema)
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations

from .capabilities_schema import ChioCapabilityNegotiationV1, MaxCapabilitySchema
from .grant_schema import ChioCapabilityGrant, Constraint, MonetaryAmount, Operation, PromptGrant, ResourceGrant, ToolGrant
from .revocation_schema import ChioCapabilityRevocationEntry
from .token_schema import Algorithm, Attenuation, ChioCapabilitytoken, ChioScope, Constraint, DelegationLink, MonetaryAmount, Operation, PromptGrant, ResourceGrant, ToolGrant
from .token_v1_schema import Algorithm, Attenuation, ChioCapabilitytokenV1, ChioScope, Constraint, DelegationLink, MonetaryAmount, Operation, PromptGrant, ResourceGrant, ToolGrant
from .token_v2_schema import Algorithm, AttenuationProof, AttenuationWitness, Caveat, ChioCapabilitytokenV2, GrantKind, GrantSubsetRelation, Kind, ScopeAttenuation

__all__ = [
    "Algorithm",
    "Attenuation",
    "AttenuationProof",
    "AttenuationWitness",
    "Caveat",
    "ChioCapabilityGrant",
    "ChioCapabilityNegotiationV1",
    "ChioCapabilityRevocationEntry",
    "ChioCapabilitytoken",
    "ChioCapabilitytokenV1",
    "ChioCapabilitytokenV2",
    "ChioScope",
    "Constraint",
    "DelegationLink",
    "GrantKind",
    "GrantSubsetRelation",
    "Kind",
    "MaxCapabilitySchema",
    "MonetaryAmount",
    "Operation",
    "PromptGrant",
    "ResourceGrant",
    "ScopeAttenuation",
    "ToolGrant",
]
