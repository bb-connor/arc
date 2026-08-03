use alloc::string::String;
use core::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PartitionEscrowValidationError {
    InvalidSchema,
    InvalidIdentifier(&'static str),
    InvalidQuotaProfile(String),
    InvalidQuotaShape,
    InvalidDigest(&'static str),
    InvalidTimeWindow,
    NotYetValid,
    Expired,
    InvalidAllocationCount,
    AllocationOrder,
    DuplicatePartitionId,
    DuplicateAuthorityId,
    AllocationSumOverflow,
    AllocationSumExceeded { allocated: u64, maximum: u32 },
    QuotaMismatch,
    AuthorityDomainMismatch,
    AllocationRootMismatch,
    AllocationEpochMismatch,
    SignerMismatch,
    SignatureAlgorithmMismatch,
    SignatureInvalid,
    MissingLocalAllocation,
    MultipleLocalAllocations,
    AllocationSetDigestMismatch,
    AllocationPlanDigestMismatch,
    QuotaAuthorityDigestMismatch,
    UnderlyingSourceDigestMismatch,
    SourceTrustBindingMismatch,
    QuotaAuthorityExpiryMismatch,
    AllocationPredatesQuotaAuthority,
    AllocationOutlivesQuotaAuthority,
    NonCanonicalEnvelope,
    InvalidEnvelopeEncoding,
    InvalidEnvelope(String),
    Canonicalization(String),
    Signing(String),
}

impl fmt::Display for PartitionEscrowValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchema => formatter.write_str("partition escrow schema is invalid"),
            Self::InvalidIdentifier(field) => {
                write!(formatter, "partition escrow {field} is invalid")
            }
            Self::InvalidQuotaProfile(profile) => {
                write!(
                    formatter,
                    "partition escrow quota profile `{profile}` is unsupported"
                )
            }
            Self::InvalidQuotaShape => {
                formatter.write_str("partition escrow quota key shape is invalid")
            }
            Self::InvalidDigest(field) => {
                write!(
                    formatter,
                    "partition escrow {field} is not lowercase SHA-256 hex"
                )
            }
            Self::InvalidTimeWindow => {
                formatter.write_str("partition escrow allocation time window is invalid")
            }
            Self::NotYetValid => {
                formatter.write_str("partition escrow allocation is not yet valid")
            }
            Self::Expired => formatter.write_str("partition escrow allocation is expired"),
            Self::InvalidAllocationCount => formatter.write_str(
                "partition escrow allocation count is empty or exceeds the bounded maximum",
            ),
            Self::AllocationOrder => formatter.write_str(
                "partition escrow allocations are not strictly sorted by partition and authority",
            ),
            Self::DuplicatePartitionId => {
                formatter.write_str("partition escrow allocation has a duplicate partition id")
            }
            Self::DuplicateAuthorityId => {
                formatter.write_str("partition escrow allocation has a duplicate authority id")
            }
            Self::AllocationSumOverflow => {
                formatter.write_str("partition escrow allocation sum overflowed")
            }
            Self::AllocationSumExceeded { allocated, maximum } => write!(
                formatter,
                "partition escrow allocated {allocated} invocations above signed maximum {maximum}"
            ),
            Self::QuotaMismatch => {
                formatter.write_str("partition escrow allocation changed the verified quota")
            }
            Self::AuthorityDomainMismatch => {
                formatter.write_str("partition escrow authority domain is not pinned")
            }
            Self::AllocationRootMismatch => {
                formatter.write_str("partition escrow allocation root is not pinned")
            }
            Self::AllocationEpochMismatch => {
                formatter.write_str("partition escrow allocation epoch is not pinned")
            }
            Self::SignerMismatch => {
                formatter.write_str("partition escrow allocator is not the certificate signer")
            }
            Self::SignatureAlgorithmMismatch => formatter
                .write_str("partition escrow signature algorithm does not match its key material"),
            Self::SignatureInvalid => {
                formatter.write_str("partition escrow allocation signature is invalid")
            }
            Self::MissingLocalAllocation => {
                formatter.write_str("partition escrow allocation omits the local authority")
            }
            Self::MultipleLocalAllocations => formatter
                .write_str("partition escrow allocation contains multiple local authority entries"),
            Self::AllocationSetDigestMismatch => formatter
                .write_str("partition escrow allocation set does not match its configured pin"),
            Self::AllocationPlanDigestMismatch => formatter
                .write_str("partition escrow allocation plan does not match its source commitment"),
            Self::QuotaAuthorityDigestMismatch => formatter
                .write_str("partition escrow allocation changed the commitment certificate digest"),
            Self::UnderlyingSourceDigestMismatch => formatter.write_str(
                "partition escrow commitment changed the underlying source artifact digest",
            ),
            Self::SourceTrustBindingMismatch => formatter
                .write_str("partition escrow commitment changed the source trust binding digest"),
            Self::QuotaAuthorityExpiryMismatch => formatter
                .write_str("partition escrow allocation changed the authenticated source expiry"),
            Self::AllocationPredatesQuotaAuthority => formatter.write_str(
                "partition escrow allocation starts before its certificate source window",
            ),
            Self::AllocationOutlivesQuotaAuthority => formatter
                .write_str("partition escrow allocation outlives its certificate source window"),
            Self::NonCanonicalEnvelope => {
                formatter.write_str("partition escrow allocation envelope is not canonical JSON")
            }
            Self::InvalidEnvelopeEncoding => {
                formatter.write_str("partition escrow allocation envelope is not valid UTF-8")
            }
            Self::InvalidEnvelope(error) => {
                write!(
                    formatter,
                    "partition escrow allocation envelope is invalid: {error}"
                )
            }
            Self::Canonicalization(error) => {
                write!(
                    formatter,
                    "partition escrow canonicalization failed: {error}"
                )
            }
            Self::Signing(error) => write!(formatter, "partition escrow signing failed: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PartitionEscrowValidationError {}
