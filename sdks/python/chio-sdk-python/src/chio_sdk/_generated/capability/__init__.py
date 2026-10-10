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

from .aggregate_budget_root_schema import AggregateRootPublicKey
from .aggregate_budget_root_schema import AggregateRootSignature
from .aggregate_budget_root_schema import CapabilityAggregateBudgetRootDefinitionsAggregateRootSigningAlgorithm as AggregateRootSigningAlgorithm
from .token_schema import CapabilityTokenAlgorithm as Algorithm
from .token_schema import CapabilityTokenDefinitionsDelegationLinkAttenuationsItems as Attenuation
from .token_schema import CapabilityTokenDefinitionsAttenuationProof as AttenuationProof
from .token_schema import CapabilityTokenDefinitionsAttenuationWitness as AttenuationWitness
from .cumulative_approval_root_schema import CapabilityCumulativeApprovalRootBody as Body
from .aggregate_budget_root_schema import AggregateRootPublicKey as CapabilityAggregateBudgetRootAggregateRootPublicKey
from .aggregate_budget_root_schema import AggregateRootSignature as CapabilityAggregateBudgetRootAggregateRootSignature
from .aggregate_budget_root_schema import CapabilityAggregateBudgetRootBody
from .aggregate_budget_root_schema import ChioAggregateBudgetRootBinding as CapabilityAggregateBudgetRootChioAggregateBudgetRootBinding
from .aggregate_budget_root_schema import CapabilityAggregateBudgetRootDefinitionsAggregateRootSigningAlgorithm
from .aggregate_invocation_budget_schema import ChioAggregateInvocationBudget as CapabilityAggregateInvocationBudgetChioAggregateInvocationBudget
from .aggregate_invocation_budget_schema import CapabilityAggregateInvocationBudgetVariant0
from .aggregate_invocation_budget_schema import CapabilityAggregateInvocationBudgetVariant1
from .capabilities_schema import ChioCapabilityNegotiationV1 as CapabilityCapabilitiesChioCapabilityNegotiationV1
from .cumulative_approval_root_schema import CapabilityCumulativeApprovalRootBody
from .cumulative_approval_root_schema import ChioCumulativeApprovalRootBinding as CapabilityCumulativeApprovalRootChioCumulativeApprovalRootBinding
from .cumulative_approval_root_schema import CumulativeRootPublicKey as CapabilityCumulativeApprovalRootCumulativeRootPublicKey
from .cumulative_approval_root_schema import CumulativeRootSignature as CapabilityCumulativeApprovalRootCumulativeRootSignature
from .cumulative_approval_root_schema import CapabilityCumulativeApprovalRootDefinitionsCumulativeRootMonetaryAmount
from .cumulative_approval_root_schema import CapabilityCumulativeApprovalRootDefinitionsCumulativeRootSigningAlgorithm
from .governed_approval_token_schema import CapabilityGovernedApprovalTokenAlgorithm
from .governed_approval_token_schema import ChioGovernedApprovalToken as CapabilityGovernedApprovalTokenChioGovernedApprovalToken
from .governed_approval_token_schema import CapabilityGovernedApprovalTokenDecision
from .governed_approval_token_schema import GovernedApprovalPublicKey as CapabilityGovernedApprovalTokenGovernedApprovalPublicKey
from .governed_approval_token_schema import GovernedApprovalSignature as CapabilityGovernedApprovalTokenGovernedApprovalSignature
from .grant_schema import ChioCapabilityGrant as CapabilityGrantChioCapabilityGrant
from .grant_schema import CapabilityGrantDefinitionsConstraint
from .grant_schema import CapabilityGrantDefinitionsMonetaryAmount
from .grant_schema import CapabilityGrantDefinitionsOperation
from .grant_schema import CapabilityGrantDefinitionsPromptGrant
from .grant_schema import CapabilityGrantDefinitionsResourceGrant
from .grant_schema import CapabilityGrantDefinitionsToolGrant
from .revocation_schema import ChioCapabilityRevocationEntry as CapabilityRevocationChioCapabilityRevocationEntry
from .supplemental_authorization_schema import ChioOpaqueSupplementalAuthorization as CapabilitySupplementalAuthorizationChioOpaqueSupplementalAuthorization
from .threshold_approval_proposal_schema import CapabilityThresholdApprovalProposalAlgorithm
from .threshold_approval_proposal_schema import ChioThresholdApprovalProposal as CapabilityThresholdApprovalProposalChioThresholdApprovalProposal
from .threshold_approval_proposal_schema import ThresholdProposalPublicKey as CapabilityThresholdApprovalProposalThresholdProposalPublicKey
from .threshold_approval_proposal_schema import ThresholdProposalSignature as CapabilityThresholdApprovalProposalThresholdProposalSignature
from .token_schema import CapabilityTokenAlgorithm
from .token_schema import ChioCapabilityToken as CapabilityTokenChioCapabilityToken
from .token_schema import Constraint as CapabilityTokenConstraint
from .token_schema import CapabilityTokenDefinitionsAttenuationProof
from .token_schema import CapabilityTokenDefinitionsAttenuationWitness
from .token_schema import CapabilityTokenDefinitionsCaveat
from .token_schema import CapabilityTokenDefinitionsCaveatKind
from .token_schema import CapabilityTokenDefinitionsChioScope
from .token_schema import CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraint
from .token_schema import CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraintValue
from .token_schema import CapabilityTokenDefinitionsCumulativeApprovalDirectConstraint
from .token_schema import CapabilityTokenDefinitionsCumulativeApprovalDirectConstraintValue
from .token_schema import CapabilityTokenDefinitionsDelegationLink
from .token_schema import CapabilityTokenDefinitionsDelegationLinkAttenuationsItems
from .token_schema import CapabilityTokenDefinitionsGenericConstraint
from .token_schema import CapabilityTokenDefinitionsGrantSubsetRelation
from .token_schema import CapabilityTokenDefinitionsGrantSubsetRelationGrantKind
from .token_schema import CapabilityTokenDefinitionsLegacyApprovalConstraint
from .token_schema import CapabilityTokenDefinitionsLegacyApprovalConstraintValue
from .token_schema import CapabilityTokenDefinitionsMonetaryAmount
from .token_schema import CapabilityTokenDefinitionsOperation
from .token_schema import CapabilityTokenDefinitionsPromptGrant
from .token_schema import CapabilityTokenDefinitionsResourceGrant
from .token_schema import CapabilityTokenDefinitionsToolGrant
from .token_schema import CapabilityTokenScopeAttenuationsItems
from .token_schema import Subset as CapabilityTokenSubset
from .verified_approval_set_schema import ChioVerifiedApprovalSetBody as CapabilityVerifiedApprovalSetChioVerifiedApprovalSetBody
from .verified_approval_set_schema import TokenDigest as CapabilityVerifiedApprovalSetTokenDigest
from .token_schema import CapabilityTokenDefinitionsCaveat as Caveat
from .aggregate_budget_root_schema import ChioAggregateBudgetRootBinding
from .aggregate_invocation_budget_schema import ChioAggregateInvocationBudget
from .aggregate_invocation_budget_schema import CapabilityAggregateInvocationBudgetVariant0 as ChioAggregateInvocationBudget1
from .aggregate_invocation_budget_schema import CapabilityAggregateInvocationBudgetVariant1 as ChioAggregateInvocationBudget2
from .grant_schema import ChioCapabilityGrant
from .capabilities_schema import ChioCapabilityNegotiationV1
from .revocation_schema import ChioCapabilityRevocationEntry
from .token_schema import ChioCapabilityToken as ChioCapabilitytoken
from .cumulative_approval_root_schema import ChioCumulativeApprovalRootBinding
from .governed_approval_token_schema import ChioGovernedApprovalToken
from .supplemental_authorization_schema import ChioOpaqueSupplementalAuthorization
from .token_schema import CapabilityTokenDefinitionsChioScope as ChioScope
from .threshold_approval_proposal_schema import ChioThresholdApprovalProposal
from .verified_approval_set_schema import ChioVerifiedApprovalSetBody
from .token_schema import Constraint
from .token_schema import CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraint as CumulativeApprovalDelegableConstraint
from .token_schema import CapabilityTokenDefinitionsCumulativeApprovalDirectConstraint as CumulativeApprovalDirectConstraint
from .cumulative_approval_root_schema import CapabilityCumulativeApprovalRootDefinitionsCumulativeRootMonetaryAmount as CumulativeRootMonetaryAmount
from .cumulative_approval_root_schema import CumulativeRootPublicKey
from .cumulative_approval_root_schema import CumulativeRootSignature
from .cumulative_approval_root_schema import CapabilityCumulativeApprovalRootDefinitionsCumulativeRootSigningAlgorithm as CumulativeRootSigningAlgorithm
from .governed_approval_token_schema import CapabilityGovernedApprovalTokenDecision as Decision
from .token_schema import CapabilityTokenDefinitionsDelegationLink as DelegationLink
from .token_schema import CapabilityTokenDefinitionsGenericConstraint as GenericConstraint
from .governed_approval_token_schema import GovernedApprovalPublicKey
from .governed_approval_token_schema import GovernedApprovalSignature
from .token_schema import CapabilityTokenDefinitionsGrantSubsetRelationGrantKind as GrantKind
from .token_schema import CapabilityTokenDefinitionsGrantSubsetRelation as GrantSubsetRelation
from .token_schema import CapabilityTokenDefinitionsCaveatKind as Kind
from .token_schema import CapabilityTokenDefinitionsLegacyApprovalConstraint as LegacyApprovalConstraint
from .token_schema import CapabilityTokenDefinitionsMonetaryAmount as MonetaryAmount
from .token_schema import CapabilityTokenDefinitionsOperation as Operation
from .token_schema import CapabilityTokenDefinitionsPromptGrant as PromptGrant
from .token_schema import CapabilityTokenDefinitionsResourceGrant as ResourceGrant
from .token_schema import CapabilityTokenScopeAttenuationsItems as ScopeAttenuation
from .token_schema import Subset
from .threshold_approval_proposal_schema import ThresholdProposalPublicKey
from .threshold_approval_proposal_schema import ThresholdProposalSignature
from .verified_approval_set_schema import TokenDigest
from .token_schema import CapabilityTokenDefinitionsToolGrant as ToolGrant
from .token_schema import CapabilityTokenDefinitionsLegacyApprovalConstraintValue as Value
from .token_schema import CapabilityTokenDefinitionsCumulativeApprovalDirectConstraintValue as Value1
from .token_schema import CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraintValue as Value2

__all__ = [
    "AggregateRootPublicKey",
    "AggregateRootSignature",
    "AggregateRootSigningAlgorithm",
    "Algorithm",
    "Attenuation",
    "AttenuationProof",
    "AttenuationWitness",
    "Body",
    "CapabilityAggregateBudgetRootAggregateRootPublicKey",
    "CapabilityAggregateBudgetRootAggregateRootSignature",
    "CapabilityAggregateBudgetRootBody",
    "CapabilityAggregateBudgetRootChioAggregateBudgetRootBinding",
    "CapabilityAggregateBudgetRootDefinitionsAggregateRootSigningAlgorithm",
    "CapabilityAggregateInvocationBudgetChioAggregateInvocationBudget",
    "CapabilityAggregateInvocationBudgetVariant0",
    "CapabilityAggregateInvocationBudgetVariant1",
    "CapabilityCapabilitiesChioCapabilityNegotiationV1",
    "CapabilityCumulativeApprovalRootBody",
    "CapabilityCumulativeApprovalRootChioCumulativeApprovalRootBinding",
    "CapabilityCumulativeApprovalRootCumulativeRootPublicKey",
    "CapabilityCumulativeApprovalRootCumulativeRootSignature",
    "CapabilityCumulativeApprovalRootDefinitionsCumulativeRootMonetaryAmount",
    "CapabilityCumulativeApprovalRootDefinitionsCumulativeRootSigningAlgorithm",
    "CapabilityGovernedApprovalTokenAlgorithm",
    "CapabilityGovernedApprovalTokenChioGovernedApprovalToken",
    "CapabilityGovernedApprovalTokenDecision",
    "CapabilityGovernedApprovalTokenGovernedApprovalPublicKey",
    "CapabilityGovernedApprovalTokenGovernedApprovalSignature",
    "CapabilityGrantChioCapabilityGrant",
    "CapabilityGrantDefinitionsConstraint",
    "CapabilityGrantDefinitionsMonetaryAmount",
    "CapabilityGrantDefinitionsOperation",
    "CapabilityGrantDefinitionsPromptGrant",
    "CapabilityGrantDefinitionsResourceGrant",
    "CapabilityGrantDefinitionsToolGrant",
    "CapabilityRevocationChioCapabilityRevocationEntry",
    "CapabilitySupplementalAuthorizationChioOpaqueSupplementalAuthorization",
    "CapabilityThresholdApprovalProposalAlgorithm",
    "CapabilityThresholdApprovalProposalChioThresholdApprovalProposal",
    "CapabilityThresholdApprovalProposalThresholdProposalPublicKey",
    "CapabilityThresholdApprovalProposalThresholdProposalSignature",
    "CapabilityTokenAlgorithm",
    "CapabilityTokenChioCapabilityToken",
    "CapabilityTokenConstraint",
    "CapabilityTokenDefinitionsAttenuationProof",
    "CapabilityTokenDefinitionsAttenuationWitness",
    "CapabilityTokenDefinitionsCaveat",
    "CapabilityTokenDefinitionsCaveatKind",
    "CapabilityTokenDefinitionsChioScope",
    "CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraint",
    "CapabilityTokenDefinitionsCumulativeApprovalDelegableConstraintValue",
    "CapabilityTokenDefinitionsCumulativeApprovalDirectConstraint",
    "CapabilityTokenDefinitionsCumulativeApprovalDirectConstraintValue",
    "CapabilityTokenDefinitionsDelegationLink",
    "CapabilityTokenDefinitionsDelegationLinkAttenuationsItems",
    "CapabilityTokenDefinitionsGenericConstraint",
    "CapabilityTokenDefinitionsGrantSubsetRelation",
    "CapabilityTokenDefinitionsGrantSubsetRelationGrantKind",
    "CapabilityTokenDefinitionsLegacyApprovalConstraint",
    "CapabilityTokenDefinitionsLegacyApprovalConstraintValue",
    "CapabilityTokenDefinitionsMonetaryAmount",
    "CapabilityTokenDefinitionsOperation",
    "CapabilityTokenDefinitionsPromptGrant",
    "CapabilityTokenDefinitionsResourceGrant",
    "CapabilityTokenDefinitionsToolGrant",
    "CapabilityTokenScopeAttenuationsItems",
    "CapabilityTokenSubset",
    "CapabilityVerifiedApprovalSetChioVerifiedApprovalSetBody",
    "CapabilityVerifiedApprovalSetTokenDigest",
    "Caveat",
    "ChioAggregateBudgetRootBinding",
    "ChioAggregateInvocationBudget",
    "ChioAggregateInvocationBudget1",
    "ChioAggregateInvocationBudget2",
    "ChioCapabilityGrant",
    "ChioCapabilityNegotiationV1",
    "ChioCapabilityRevocationEntry",
    "ChioCapabilitytoken",
    "ChioCumulativeApprovalRootBinding",
    "ChioGovernedApprovalToken",
    "ChioOpaqueSupplementalAuthorization",
    "ChioScope",
    "ChioThresholdApprovalProposal",
    "ChioVerifiedApprovalSetBody",
    "Constraint",
    "CumulativeApprovalDelegableConstraint",
    "CumulativeApprovalDirectConstraint",
    "CumulativeRootMonetaryAmount",
    "CumulativeRootPublicKey",
    "CumulativeRootSignature",
    "CumulativeRootSigningAlgorithm",
    "Decision",
    "DelegationLink",
    "GenericConstraint",
    "GovernedApprovalPublicKey",
    "GovernedApprovalSignature",
    "GrantKind",
    "GrantSubsetRelation",
    "Kind",
    "LegacyApprovalConstraint",
    "MonetaryAmount",
    "Operation",
    "PromptGrant",
    "ResourceGrant",
    "ScopeAttenuation",
    "Subset",
    "ThresholdProposalPublicKey",
    "ThresholdProposalSignature",
    "TokenDigest",
    "ToolGrant",
    "Value",
    "Value1",
    "Value2",
]
