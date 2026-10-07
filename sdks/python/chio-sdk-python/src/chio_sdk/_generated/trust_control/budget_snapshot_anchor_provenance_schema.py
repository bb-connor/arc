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
from typing import Literal
from pydantic import AnyUrl, BaseModel, ConfigDict, Field, RootModel, conint, constr

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class TrustControlBudgetSnapshotAnchorProvenanceDefinitionsCommitment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.budget-snapshot-anchor-commitment.v1'] = Field(..., alias='schema')
    commitSequence: conint(ge=1)
    previousChainDigest: Digest
    chainDigest: Digest
    anchorSetDigest: Digest
    leaderUrl: AnyUrl
    electionTerm: conint(ge=1)
    committedAt: conint(ge=0)
    signerPublicKey: constr(min_length=1)

class TrustControlBudgetSnapshotAnchorProvenanceDefinitionsSignedCommitment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    body: TrustControlBudgetSnapshotAnchorProvenanceDefinitionsCommitment
    signature: constr(min_length=1)

class BudgetSnapshotAnchorProvenance(BaseModel):
    """
    Leader-signed inclusion chain authenticating the exact immutable migration-anchor set carried by a trust-control cluster budget snapshot.
    """
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.budget-snapshot-anchor-provenance.v1'] = Field(..., alias='schema')
    chain: list[TrustControlBudgetSnapshotAnchorProvenanceDefinitionsSignedCommitment] = Field(..., min_length=1)
    clusterAuthenticator: constr(pattern='^[0-9a-f]{64}$')

# Public compatibility aliases reference the actual current model classes.
Commitment = TrustControlBudgetSnapshotAnchorProvenanceDefinitionsCommitment
SignedCommitment = TrustControlBudgetSnapshotAnchorProvenanceDefinitionsSignedCommitment
TrustControlBudgetSnapshotAnchorProvenanceBudgetSnapshotAnchorProvenance = BudgetSnapshotAnchorProvenance
TrustControlBudgetSnapshotAnchorProvenanceDigest = Digest
