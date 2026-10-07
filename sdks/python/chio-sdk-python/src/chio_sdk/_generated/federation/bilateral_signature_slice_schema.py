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
from pydantic import BaseModel, ConfigDict, Field, conint, constr

class FederationBilateralSignatureSliceSubjectItemsDigest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    sha256: constr(pattern='^[0-9a-f]{64}$')

class FederationBilateralSignatureSliceSubjectItems(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: constr(pattern='^chio-receipt:.+')
    digest: FederationBilateralSignatureSliceSubjectItemsDigest

class FederationBilateralSignatureSlicePredicateCoSign(Enum):
    bilateral_required = 'bilateral_required'
    bilateral_if_cross_org = 'bilateral_if_cross_org'

class FederationBilateralSignatureSlicePredicateCrossOrgVisibility(Enum):
    private = 'private'
    treaty_only = 'treaty_only'
    federated = 'federated'
    public = 'public'

class FederationBilateralSignatureSliceDefinitionsHashRecord(BaseModel):
    model_config = ConfigDict(extra='forbid')
    alg: Literal['sha256']
    value: constr(pattern='^[0-9a-f]{64}$')

class FederationBilateralSignatureSliceDefinitionsKernelIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kernel_id: constr(min_length=1)
    passport_key_fingerprint: constr(pattern='^[0-9a-f]{64}$')
    alg: Literal['ed25519']

class FederationBilateralSignatureSliceDefinitionsCapabilityLeaseRef(BaseModel):
    model_config = ConfigDict(extra='forbid')
    lease_id: constr(min_length=1)
    issuer: constr(min_length=1)
    expires_at_unix_ms: conint(ge=0)
    scope_digest: FederationBilateralSignatureSliceDefinitionsHashRecord | None = None

class FederationBilateralSignatureSliceDefinitionsPolicyVerdictVerdict(Enum):
    allow = 'allow'
    deny = 'deny'

class FederationBilateralSignatureSliceDefinitionsPolicyVerdict(BaseModel):
    model_config = ConfigDict(extra='forbid')
    verdict: FederationBilateralSignatureSliceDefinitionsPolicyVerdictVerdict
    policy_id: constr(min_length=1)
    policy_version: constr(min_length=1)
    rationale_code: constr(min_length=1) | None = None

class FederationBilateralSignatureSliceDefinitionsPolicyEvaluationSummaryJointDisposition(Enum):
    allow = 'allow'
    deny = 'deny'

class FederationBilateralSignatureSliceDefinitionsPolicyEvaluationSummary(BaseModel):
    model_config = ConfigDict(extra='forbid')
    server_a_verdict: FederationBilateralSignatureSliceDefinitionsPolicyVerdict
    server_b_verdict: FederationBilateralSignatureSliceDefinitionsPolicyVerdict
    joint_disposition: FederationBilateralSignatureSliceDefinitionsPolicyEvaluationSummaryJointDisposition | None = None

class FederationBilateralSignatureSliceDefinitionsGovernanceReceiptRef(BaseModel):
    model_config = ConfigDict(extra='forbid')
    receipt_id: constr(min_length=1)
    kernel_id: constr(min_length=1)
    digest: FederationBilateralSignatureSliceDefinitionsHashRecord

class FederationBilateralSignatureSlicePredicate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.bilateral-signature-slice.v1'] = Field(..., alias='schema')
    invocation_id: constr(min_length=1)
    tool_server_a: FederationBilateralSignatureSliceDefinitionsKernelIdentity
    tool_server_b: FederationBilateralSignatureSliceDefinitionsKernelIdentity
    tool_name: constr(min_length=1)
    co_sign: FederationBilateralSignatureSlicePredicateCoSign
    consistency_model: Literal['crdt-commutative']
    cross_org_visibility: FederationBilateralSignatureSlicePredicateCrossOrgVisibility
    timestamp_unix_ms: conint(ge=0)
    receipt_canonical_json: constr(min_length=2)
    capability_lease_ref: FederationBilateralSignatureSliceDefinitionsCapabilityLeaseRef | None = None
    policy_evaluation_summary: FederationBilateralSignatureSliceDefinitionsPolicyEvaluationSummary | None = None
    governance_receipt_ref: FederationBilateralSignatureSliceDefinitionsGovernanceReceiptRef | None = None
    consistency_anchor: constr(min_length=1) | None = None

class ChioBilateralDSSESignatureSliceStatement(BaseModel):
    """
    Bounded in-toto Statement payload for Chio bilateral DSSE signature slices. This is not the strict treaty-bound bilateral invocation predicate.
    """
    model_config = ConfigDict(extra='forbid')
    field_type: Literal['https://in-toto.io/Statement/v1'] = Field(..., alias='_type')
    subject: list[FederationBilateralSignatureSliceSubjectItems] = Field(..., max_length=1, min_length=1)
    predicateType: Literal['chio.bilateral-signature-slice.v1']
    predicate: FederationBilateralSignatureSlicePredicate

# Public compatibility aliases reference the actual current model classes.
CapabilityLeaseRef = FederationBilateralSignatureSliceDefinitionsCapabilityLeaseRef
ChioBilateralDsseSignatureSliceStatement = ChioBilateralDSSESignatureSliceStatement
CoSign = FederationBilateralSignatureSlicePredicateCoSign
CrossOrgVisibility = FederationBilateralSignatureSlicePredicateCrossOrgVisibility
Digest = FederationBilateralSignatureSliceSubjectItemsDigest
FederationBilateralSignatureSliceChioBilateralDSSESignatureSliceStatement = ChioBilateralDSSESignatureSliceStatement
GovernanceReceiptRef = FederationBilateralSignatureSliceDefinitionsGovernanceReceiptRef
HashRecord = FederationBilateralSignatureSliceDefinitionsHashRecord
JointDisposition = FederationBilateralSignatureSliceDefinitionsPolicyEvaluationSummaryJointDisposition
KernelIdentity = FederationBilateralSignatureSliceDefinitionsKernelIdentity
PolicyEvaluationSummary = FederationBilateralSignatureSliceDefinitionsPolicyEvaluationSummary
PolicyVerdict = FederationBilateralSignatureSliceDefinitionsPolicyVerdict
Predicate = FederationBilateralSignatureSlicePredicate
SubjectItem = FederationBilateralSignatureSliceSubjectItems
Verdict = FederationBilateralSignatureSliceDefinitionsPolicyVerdictVerdict
