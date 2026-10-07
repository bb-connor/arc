//! Compare independently observed harness evidence, never fixture-supplied effect
//! claims, with the mandatory recovery assertions. This is not a runtime verifier.
use chio_security_types::recovery::{
    KnowledgeDigest, NativeAdmissionDigest, ProcessRequestDigest, RecoveryAssertionsV1, SafeInteger,
};

/// The native harness must obtain these values from endpoint effects, authority
/// records, knowledge state and original native/process identity respectively.
#[derive(Debug)]
pub struct ObservedRecoveryEvidence {
    pub effect_count: SafeInteger,
    pub consumed_authority: SafeInteger,
    pub remaining_budget: SafeInteger,
    pub knowledge_digest: KnowledgeDigest,
    pub native_admission_digest: NativeAdmissionDigest,
    pub process_request_digest: ProcessRequestDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAssertionFailure {
    EffectCount,
    ConsumedAuthority,
    RemainingBudget,
    RetainedKnowledge,
    OriginalNativeOperation,
    ImmutableProcessRequest,
}
impl core::fmt::Display for RecoveryAssertionFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::EffectCount => "recovery_assertion.effect_count",
            Self::ConsumedAuthority => "recovery_assertion.consumed_authority",
            Self::RemainingBudget => "recovery_assertion.remaining_budget",
            Self::RetainedKnowledge => "recovery_assertion.retained_knowledge",
            Self::OriginalNativeOperation => "recovery_assertion.original_native_operation",
            Self::ImmutableProcessRequest => "recovery_assertion.immutable_process_request",
        })
    }
}
impl core::error::Error for RecoveryAssertionFailure {}

pub fn assert_recovery_evidence(
    expected: &RecoveryAssertionsV1,
    actual: &ObservedRecoveryEvidence,
) -> Result<(), RecoveryAssertionFailure> {
    if actual.effect_count != expected.effect_count {
        return Err(RecoveryAssertionFailure::EffectCount);
    }
    if actual.consumed_authority != expected.consumed_authority {
        return Err(RecoveryAssertionFailure::ConsumedAuthority);
    }
    if actual.remaining_budget != expected.remaining_budget {
        return Err(RecoveryAssertionFailure::RemainingBudget);
    }
    if actual.knowledge_digest != expected.knowledge_digest {
        return Err(RecoveryAssertionFailure::RetainedKnowledge);
    }
    if actual.native_admission_digest != expected.native_admission_digest {
        return Err(RecoveryAssertionFailure::OriginalNativeOperation);
    }
    if actual.process_request_digest != expected.process_request_digest {
        return Err(RecoveryAssertionFailure::ImmutableProcessRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::recovery::decode_contract;
    use chio_security_types::recovery::RecoveryTrajectoryV1;

    #[test]
    fn trajectory_effect_assertions_reject_each_independent_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let wire = include_str!("../../../../spec/vectors/recovery/v1/trajectory.json").trim_end();
        let trajectory: RecoveryTrajectoryV1 = decode_contract(wire.as_bytes())?;
        let expected = &trajectory.frames.as_slice()[0].expected;
        let snapshot = || ObservedRecoveryEvidence {
            effect_count: expected.effect_count,
            consumed_authority: expected.consumed_authority,
            remaining_budget: expected.remaining_budget,
            knowledge_digest: expected.knowledge_digest,
            native_admission_digest: expected.native_admission_digest,
            process_request_digest: expected.process_request_digest,
        };
        assert_recovery_evidence(expected, &snapshot())?;
        for fault in [
            RecoveryAssertionFailure::EffectCount,
            RecoveryAssertionFailure::ConsumedAuthority,
            RecoveryAssertionFailure::RemainingBudget,
            RecoveryAssertionFailure::RetainedKnowledge,
            RecoveryAssertionFailure::OriginalNativeOperation,
            RecoveryAssertionFailure::ImmutableProcessRequest,
        ] {
            let mut actual = snapshot();
            match fault {
                RecoveryAssertionFailure::EffectCount => actual.effect_count = SafeInteger::ZERO,
                RecoveryAssertionFailure::ConsumedAuthority => {
                    actual.consumed_authority = SafeInteger::ZERO
                }
                RecoveryAssertionFailure::RemainingBudget => {
                    actual.remaining_budget = SafeInteger::ZERO
                }
                RecoveryAssertionFailure::RetainedKnowledge => {
                    actual.knowledge_digest = KnowledgeDigest::from_bytes([0; 32])
                }
                RecoveryAssertionFailure::OriginalNativeOperation => {
                    actual.native_admission_digest = NativeAdmissionDigest::from_bytes([0; 32])
                }
                RecoveryAssertionFailure::ImmutableProcessRequest => {
                    actual.process_request_digest = ProcessRequestDigest::from_bytes([0; 32])
                }
            }
            assert_eq!(assert_recovery_evidence(expected, &actual), Err(fault));
        }
        Ok(())
    }
}
