use chio_security_types::recovery::{
    ContractError, ProviderAccountId, ProviderId, ProviderResourceId,
    RecoveryProfileRequirementsV1, SafeInteger, VersionV1,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EffectContractSchema {
    #[serde(rename = "chio.semantic.effect-contract.v1")]
    V1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionIdentity {
    OriginalNativeOperation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportRetryPolicy {
    NoAutomaticRetries,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeduplicationPolicy {
    NotAssumed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupFinality {
    Unavailable,
    ExactOperationAuthoritativeFinal,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialSettlementPolicy {
    PreserveSpentIdentity,
}

/// Single-submission effect contract. Provider-deduplicated resubmission requires a
/// separately qualified version; metadata cannot enable generic retry middleware.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectContractV1 {
    schema: EffectContractSchema,
    version: VersionV1,
    provider_id: ProviderId,
    account_id: ProviderAccountId,
    resource_id: ProviderResourceId,
    effect_cardinality: SafeInteger,
    submission_identity: SubmissionIdentity,
    transport_retry: TransportRetryPolicy,
    deduplication: DeduplicationPolicy,
    lookup_finality: LookupFinality,
    partial_settlement: PartialSettlementPolicy,
    recovery_profile: RecoveryProfileRequirementsV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectContractInput {
    pub schema: EffectContractSchema,
    pub version: VersionV1,
    pub provider_id: ProviderId,
    pub account_id: ProviderAccountId,
    pub resource_id: ProviderResourceId,
    pub effect_cardinality: SafeInteger,
    pub submission_identity: SubmissionIdentity,
    pub transport_retry: TransportRetryPolicy,
    pub deduplication: DeduplicationPolicy,
    pub lookup_finality: LookupFinality,
    pub partial_settlement: PartialSettlementPolicy,
    pub recovery_profile: RecoveryProfileRequirementsV1,
}
impl EffectContractV1 {
    pub fn new(input: EffectContractInput) -> Result<Self, ContractError> {
        let EffectContractInput {
            schema,
            version,
            provider_id,
            account_id,
            resource_id,
            effect_cardinality,
            submission_identity,
            transport_retry,
            deduplication,
            lookup_finality,
            partial_settlement,
            recovery_profile,
        } = input;
        if !(1..=16).contains(&effect_cardinality.get()) {
            return Err(ContractError::LimitExceeded);
        }
        Ok(Self {
            schema,
            version,
            provider_id,
            account_id,
            resource_id,
            effect_cardinality,
            submission_identity,
            transport_retry,
            deduplication,
            lookup_finality,
            partial_settlement,
            recovery_profile,
        })
    }
    pub const fn effect_cardinality(&self) -> SafeInteger {
        self.effect_cardinality
    }
    pub const fn lookup_finality(&self) -> LookupFinality {
        self.lookup_finality
    }
    pub fn recovery_profile(&self) -> &RecoveryProfileRequirementsV1 {
        &self.recovery_profile
    }
}
impl<'de> Deserialize<'de> for EffectContractV1 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(EffectContractInput::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
