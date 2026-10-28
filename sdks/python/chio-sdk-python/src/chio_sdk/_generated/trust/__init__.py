# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations

from .agent_passport_presentation_response_schema import ActivityRatio, AverageUtilization, BoundaryPressure, BudgetReductionRate, CancellationRate, Challenge, ChioAgentPassportPresentationResponseSignedBody, CompletionRate, CompositeScore, Credential, CredentialSubject, DelegationHygiene, DenyRatio, Evidence, FitScore, HistoryDepth, IncidentCorrelation, IncompletionRate, LeastPrivilege, Metrics, Passport, Policy, PolicyRef, Proof, Query, Reliability, ResourceStewardship, ScopeReductionRate, Score, Score2, Score3, Specialization, TtlReductionRate
from .financial_agent_passport_presentation_response_schema import ActivityRatio, AverageUtilization, Body, Body146, BoundaryPressure, BudgetReductionRate, CancellationRate, Challenge, ChioFinancialAgentPassportPresentationResponseSignedBody, CompletionRate, CompositeScore, Credential, Credential1, CredentialSubject, DelegationHygiene, DenyRatio, Evidence, FitScore, HistoryDepth, IncidentCorrelation, IncompletionRate, Leaf, LeastPrivilege, MembershipProof, Metrics, Presentation, Proof, Proof2, Query, Reliability, ResourceStewardship, ScopeReductionRate, Score, Score8, Score9, Selector, SourceManifest, Specialization, TtlReductionRate
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

__all__ = [
    "ActivityRatio",
    "AttributeSources",
    "AverageUtilization",
    "Body",
    "Body146",
    "BoundaryPressure",
    "BudgetReductionRate",
    "CancellationRate",
    "Challenge",
    "ChioAgentPassportPresentationResponseSignedBody",
    "ChioFinancialAgentPassportPresentationResponseSignedBody",
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
    "CompletionRate",
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
    "HistoryDepth",
    "ImportGuardrails",
    "IncidentCorrelation",
    "IncompletionRate",
    "Leaf",
    "LeastPrivilege",
    "MembershipProof",
    "Metrics",
    "Passport",
    "PassportStatusDistribution",
    "Policy",
    "PolicyRef",
    "Presentation",
    "Proof",
    "Proof2",
    "Query",
    "Reliability",
    "ResourceStewardship",
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
    "SourceManifest",
    "Specialization",
    "TtlReductionRate",
    "Window",
]
