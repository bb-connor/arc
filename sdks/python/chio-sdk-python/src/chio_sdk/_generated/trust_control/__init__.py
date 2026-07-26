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

from .admission_capture_metadata_schema import Authority, ChioAuthoritativeAdmissionCaptureReceiptProjection, Digest, GuaranteeLevel, Identifier, InvocationQuotaTransition, MonetaryState
from .admission_request_binding_schema import ChioAdmissionOperationRequestBindingProjection, ChioAdmissionOperationRequestBindingProjection1, ChioAdmissionOperationRequestBindingProjection2, Digest, Identifier, OptionalDigest, OptionalIdentifier
from .attestation_schema import ChioTrustControlRuntimeAttestationEvidence, CredentialKind, Scheme, Tier, WorkloadIdentity
from .budget_invocation_admission_evidence_schema import ChioBudgetInvocationAdmissionEvidence, Digest, Identifier, InvocationQuota, PartitionEscrowEvidence, Profile, PublicKey, QuotaKey, RevocationSet, SafeInteger, SupplementalBinding
from .heartbeat_schema import ChioTrustControlLeaseHeartbeat
from .lease_schema import ChioTrustControlAuthorityLease
from .partition_escrow_admission_evidence_schema import AggregateCapabilityTrust, AggregateFamilyTrust, BrokerCapabilityTrust, ChioPartitionEscrowAdmissionEvidence, Digest, DurableStore, GrantCapabilityTrust, Identifier, PositiveSafeInteger, PositiveUint32, PublicKey, QuotaEvidence, Resolver, SafeInteger, SourceTrust, Uint32
from .partition_escrow_allocation_set_schema import Allocation, Body, ChioSignedPartitionEscrowAllocationSet
from .partition_escrow_quota_commitment_schema import ChioSignedPartitionEscrowQuotaCommitment, PartitionEscrowDigest, PartitionEscrowEd25519PublicKey, PartitionEscrowEd25519Signature, PartitionEscrowHybridPublicKey, PartitionEscrowHybridSignature, PartitionEscrowIdentifier, PartitionEscrowP256PublicKey, PartitionEscrowP256Signature, PartitionEscrowP384PublicKey, PartitionEscrowP384Signature, PartitionEscrowPositiveSafeInteger, PartitionEscrowPositiveUint32, PartitionEscrowPublicKey, PartitionEscrowQuota, PartitionEscrowSafeInteger, PartitionEscrowSignature, PartitionEscrowSignatureAlgorithm, PartitionEscrowUint32, Profile, QuotaCommitmentBody
from .partition_escrow_receipt_metadata_schema import ChioPartitionEscrowFinancialReceiptMetadata, Digest, Identifier, PositiveSafeInteger, PositiveUint32, Summary
from .terminate_schema import ChioTrustControlLeaseTermination, Reason

__all__ = [
    "AggregateCapabilityTrust",
    "AggregateFamilyTrust",
    "Allocation",
    "Authority",
    "Body",
    "BrokerCapabilityTrust",
    "ChioAdmissionOperationRequestBindingProjection",
    "ChioAdmissionOperationRequestBindingProjection1",
    "ChioAdmissionOperationRequestBindingProjection2",
    "ChioAuthoritativeAdmissionCaptureReceiptProjection",
    "ChioBudgetInvocationAdmissionEvidence",
    "ChioPartitionEscrowAdmissionEvidence",
    "ChioPartitionEscrowFinancialReceiptMetadata",
    "ChioSignedPartitionEscrowAllocationSet",
    "ChioSignedPartitionEscrowQuotaCommitment",
    "ChioTrustControlAuthorityLease",
    "ChioTrustControlLeaseHeartbeat",
    "ChioTrustControlLeaseTermination",
    "ChioTrustControlRuntimeAttestationEvidence",
    "CredentialKind",
    "Digest",
    "DurableStore",
    "GrantCapabilityTrust",
    "GuaranteeLevel",
    "Identifier",
    "InvocationQuota",
    "InvocationQuotaTransition",
    "MonetaryState",
    "OptionalDigest",
    "OptionalIdentifier",
    "PartitionEscrowDigest",
    "PartitionEscrowEd25519PublicKey",
    "PartitionEscrowEd25519Signature",
    "PartitionEscrowEvidence",
    "PartitionEscrowHybridPublicKey",
    "PartitionEscrowHybridSignature",
    "PartitionEscrowIdentifier",
    "PartitionEscrowP256PublicKey",
    "PartitionEscrowP256Signature",
    "PartitionEscrowP384PublicKey",
    "PartitionEscrowP384Signature",
    "PartitionEscrowPositiveSafeInteger",
    "PartitionEscrowPositiveUint32",
    "PartitionEscrowPublicKey",
    "PartitionEscrowQuota",
    "PartitionEscrowSafeInteger",
    "PartitionEscrowSignature",
    "PartitionEscrowSignatureAlgorithm",
    "PartitionEscrowUint32",
    "PositiveSafeInteger",
    "PositiveUint32",
    "Profile",
    "PublicKey",
    "QuotaCommitmentBody",
    "QuotaEvidence",
    "QuotaKey",
    "Reason",
    "Resolver",
    "RevocationSet",
    "SafeInteger",
    "Scheme",
    "SourceTrust",
    "Summary",
    "SupplementalBinding",
    "Tier",
    "Uint32",
    "WorkloadIdentity",
]
