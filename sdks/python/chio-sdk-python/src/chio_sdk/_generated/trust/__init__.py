# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations

from .agent_passport_presentation_response_schema import ActivityRatio, AverageUtilization, BoundaryPressure, BudgetReductionRate, CancellationRate, Challenge, ChioAgentPassportPresentationResponseSignedBody, CompletionRate, CompositeScore, Credential, CredentialSubject, DelegationHygiene, DenyRatio, Evidence, FitScore, HistoryDepth, IncidentCorrelation, IncompletionRate, LeastPrivilege, Metrics, Passport, Policy, PolicyRef, Proof, Query, Reliability, ResourceStewardship, ScopeReductionRate, Score, Score2, Score3, Specialization, TtlReductionRate
from .financial_agent_passport_presentation_challenge_body_schema import ChioFinancialAgentPassportPresentationChallengeV1SignedBody, Selector
from .financial_agent_passport_presentation_response_schema import ActivityRatio, AverageUtilization, Body, Body161, BoundaryPressure, BudgetReductionRate, CancellationRate, Challenge, ChioFinancialAgentPassportPresentationResponseSignedBody, CompletionRate, CompositeScore, Credential, Credential1, CredentialSubject, DelegationHygiene, DenyRatio, Evidence, FitScore, HistoryDepth, IncidentCorrelation, IncompletionRate, Leaf, LeastPrivilege, MembershipProof, Metrics, Presentation, Proof, Proof5, Query, Reliability, ResourceStewardship, ScopeReductionRate, Score, Score8, Score9, Selector, SourceManifest, Specialization, TtlReductionRate
from .financial_agent_passport_source_manifest_body_schema import ChioFinancialAgentPassportSourceManifestV1SignedBody
from .fincred_premium_history_body_schema import Artifact, AuditPathItem, Body, ChioFincredPremiumHistoryV1SignedBody, Claims, CommittedLeaf, CredentialSubject, Evidence, IndexProof, Leaf, LowerBoundary, QueryKey, QuotedAmount, SourceCompletenessAttestation, SourceDisclosure, UpperBoundary, Window
from .fincred_settlement_reliability_body_schema import Artifact, AuditPathItem, Body, ChioFincredSettlementReliabilityV1SignedBody, Claims, CommittedLeaf, CredentialSubject, Evidence, IndexProof, IndexProof2, IndexProof3, Leaf, Leaf3, Leaf4, LeafProof, LeafProof1, LowerBoundary, LowerBoundary2, QueryKey, QueryKey2, QueryKey3, Role, SourceArtifactDigest, SourceCompletenessAttestation, SourceDisclosure, SourceEvidenceClass, SourceFamily, UpperBoundary, UpperBoundary2, Window, Window5
from .fincred_source_checkpoint_body_schema import ChioFincredSourceCheckpointV1SignedBody, LowerBoundary, UpperBoundary, Window
from .fincred_source_completeness_attestation_body_schema import AuditPathItem, ChioFincredSourceCompletenessAttestationV1SignedBody, CommittedLeaf, IndexProof, Leaf, LowerBoundary, QueryKey, UpperBoundary, Window
from .fincred_source_member_body_schema import ChioFincredSourceMemberV1SignedBody, QueryKey
from .key_binding_certificate_schema import ChioKeyBindingCertificateSignedBody
from .passkey_capability_schema import ChioPasskeyCapabilitySignedBody
from .passport_verifier_policy_schema import ChioPassportVerifierPolicySignedBody, Policy
from .portable_agent_passport_schema import ChioPortableAgentPassportSignedBody
from .portable_negative_event_schema import ChioPortableNegativeEventSignedBody, EvidenceRef
from .portable_reputation_summary_schema import ActivityRatio, AverageUtilization, BoundaryPressure, BudgetReductionRate, CancellationRate, ChioPortableReputationSummarySignedBody, CompletionRate, CompositeScore, DelegationHygiene, DenyRatio, FitScore, HistoryDepth, IncidentCorrelation, IncompletionRate, LeastPrivilege, Reliability, ResourceStewardship, ScopeReductionRate, Score, Scorecard, Specialization, TtlReductionRate, Window
from .public_discovery_transparency_schema import ChioPublicDiscoveryTransparencySignedBody, Entry, ImportGuardrails
from .public_issuer_discovery_schema import ChioPublicIssuerDiscoverySignedBody, ImportGuardrails, PassportStatusDistribution
from .public_verifier_discovery_schema import ChioPublicVerifierDiscoverySignedBody, ImportGuardrails
from .reputation_credential_schema import ActivityRatio, AttributeSources, AverageUtilization, BoundaryPressure, BudgetReductionRate, CancellationRate, ChioReputationCredentialSignedBody, CompletionRate, CompositeScore, CredentialSubject, DelegationHygiene, DenyRatio, EnterpriseIdentityProvenance, Evidence, FitScore, HistoryDepth, IncidentCorrelation, IncompletionRate, LeastPrivilege, Metrics, Query, Reliability, ResourceStewardship, ScopeReductionRate, Score, Score20, Score21, Specialization, TtlReductionRate
from .trust_passport_revocation_root_body_schema import ChioTrustPassportRevocationRootV1SignedBody
from .trust_reputation_import_report_body_schema import ChioTrustReputationImportReportV1SignedBody
from .trust_root_body_schema import ChioTrustRootV1SignedBody, Root
from .trust_scorecard_snapshot_body_schema import ChioTrustScorecardSnapshotV1SignedBody, ComponentScore, FreshnessWindow

__all__ = [
    "ActivityRatio",
    "Artifact",
    "AttributeSources",
    "AuditPathItem",
    "AverageUtilization",
    "Body",
    "Body161",
    "BoundaryPressure",
    "BudgetReductionRate",
    "CancellationRate",
    "Challenge",
    "ChioAgentPassportPresentationResponseSignedBody",
    "ChioFinancialAgentPassportPresentationChallengeV1SignedBody",
    "ChioFinancialAgentPassportPresentationResponseSignedBody",
    "ChioFinancialAgentPassportSourceManifestV1SignedBody",
    "ChioFincredPremiumHistoryV1SignedBody",
    "ChioFincredSettlementReliabilityV1SignedBody",
    "ChioFincredSourceCheckpointV1SignedBody",
    "ChioFincredSourceCompletenessAttestationV1SignedBody",
    "ChioFincredSourceMemberV1SignedBody",
    "ChioKeyBindingCertificateSignedBody",
    "ChioPasskeyCapabilitySignedBody",
    "ChioPassportVerifierPolicySignedBody",
    "ChioPortableAgentPassportSignedBody",
    "ChioPortableNegativeEventSignedBody",
    "ChioPortableReputationSummarySignedBody",
    "ChioPublicDiscoveryTransparencySignedBody",
    "ChioPublicIssuerDiscoverySignedBody",
    "ChioPublicVerifierDiscoverySignedBody",
    "ChioReputationCredentialSignedBody",
    "ChioTrustPassportRevocationRootV1SignedBody",
    "ChioTrustReputationImportReportV1SignedBody",
    "ChioTrustRootV1SignedBody",
    "ChioTrustScorecardSnapshotV1SignedBody",
    "Claims",
    "CommittedLeaf",
    "CompletionRate",
    "ComponentScore",
    "CompositeScore",
    "Credential",
    "Credential1",
    "CredentialSubject",
    "DelegationHygiene",
    "DenyRatio",
    "EnterpriseIdentityProvenance",
    "Entry",
    "Evidence",
    "EvidenceRef",
    "FitScore",
    "FreshnessWindow",
    "HistoryDepth",
    "ImportGuardrails",
    "IncidentCorrelation",
    "IncompletionRate",
    "IndexProof",
    "IndexProof2",
    "IndexProof3",
    "Leaf",
    "Leaf3",
    "Leaf4",
    "LeafProof",
    "LeafProof1",
    "LeastPrivilege",
    "LowerBoundary",
    "LowerBoundary2",
    "MembershipProof",
    "Metrics",
    "Passport",
    "PassportStatusDistribution",
    "Policy",
    "PolicyRef",
    "Presentation",
    "Proof",
    "Proof5",
    "Query",
    "QueryKey",
    "QueryKey2",
    "QueryKey3",
    "QuotedAmount",
    "Reliability",
    "ResourceStewardship",
    "Role",
    "Root",
    "ScopeReductionRate",
    "Score",
    "Score2",
    "Score20",
    "Score21",
    "Score3",
    "Score8",
    "Score9",
    "Scorecard",
    "Selector",
    "SourceArtifactDigest",
    "SourceCompletenessAttestation",
    "SourceDisclosure",
    "SourceEvidenceClass",
    "SourceFamily",
    "SourceManifest",
    "Specialization",
    "TtlReductionRate",
    "UpperBoundary",
    "UpperBoundary2",
    "Window",
    "Window5",
]
