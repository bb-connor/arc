use chio_decision_model::{
    Envelope, EnvelopeError, FallbackReason, ProjectionOutcome, MAX_ENVELOPE_ACTIONS,
};
use chio_fixed::Q16_16;
use proptest::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Deny,
    PendingApproval,
    Allow,
}

const VERDICTS: [Verdict; 3] = [Verdict::Deny, Verdict::PendingApproval, Verdict::Allow];
const FALLBACK_REASONS: [FallbackReason; 5] = [
    FallbackReason::EmptyProposal,
    FallbackReason::ProposalInfeasible,
    FallbackReason::ScorerError,
    FallbackReason::WorkExhausted,
    FallbackReason::PolicyUnavailable,
];

fn q(bits: i32) -> Q16_16 {
    Q16_16::from_bits(bits)
}

#[test]
fn new_refuses_empty_and_oversized_sets() {
    assert_eq!(Envelope::<u8>::new(&[]).err(), Some(EnvelopeError::Empty));
    let largest = [0u16; MAX_ENVELOPE_ACTIONS];
    assert!(Envelope::new(&largest).is_ok());
    let oversized = [0u16; MAX_ENVELOPE_ACTIONS + 1];
    assert_eq!(
        Envelope::new(&oversized).err(),
        Some(EnvelopeError::TooLarge)
    );
}

#[test]
fn fallback_is_the_first_feasible_action() -> Result<(), EnvelopeError> {
    let envelope = Envelope::new(&VERDICTS)?;
    assert_eq!(envelope.fallback(), Verdict::Deny);
    assert!(VERDICTS.iter().all(|v| envelope.admits(*v)));
    let narrow = Envelope::new(&[Verdict::Deny, Verdict::PendingApproval])?;
    assert!(!narrow.admits(Verdict::Allow));
    Ok(())
}

#[test]
fn admitted_proposal_is_identity() -> Result<(), EnvelopeError> {
    let envelope = Envelope::new(&VERDICTS)?;
    let projected = envelope.project(Ok(Some(Verdict::Allow)));
    assert_eq!(projected.action(), Verdict::Allow);
    assert_eq!(projected.outcome(), ProjectionOutcome::Identity);
    assert!(!projected.fallback_used());
    Ok(())
}

#[test]
fn infeasible_proposal_falls_back() -> Result<(), EnvelopeError> {
    let envelope = Envelope::new(&[Verdict::Deny, Verdict::PendingApproval])?;
    let projected = envelope.project(Ok(Some(Verdict::Allow)));
    assert_eq!(projected.action(), Verdict::Deny);
    assert_eq!(
        projected.outcome(),
        ProjectionOutcome::Fallback(FallbackReason::ProposalInfeasible)
    );
    assert!(projected.fallback_used());
    Ok(())
}

#[test]
fn empty_proposal_falls_back() -> Result<(), EnvelopeError> {
    let envelope = Envelope::new(&VERDICTS)?;
    let projected = envelope.project(Ok(None));
    assert_eq!(projected.action(), Verdict::Deny);
    assert_eq!(
        projected.outcome(),
        ProjectionOutcome::Fallback(FallbackReason::EmptyProposal)
    );
    Ok(())
}

#[test]
fn proposer_error_falls_back_with_its_reason() -> Result<(), EnvelopeError> {
    let envelope = Envelope::new(&VERDICTS)?;
    for reason in FALLBACK_REASONS {
        let projected = envelope.project(Err(reason));
        assert_eq!(projected.action(), Verdict::Deny);
        assert_eq!(projected.outcome(), ProjectionOutcome::Fallback(reason));
        assert!(projected.fallback_used());
    }
    Ok(())
}

#[test]
fn select_rejects_length_mismatch() -> Result<(), EnvelopeError> {
    let envelope = Envelope::new(&VERDICTS)?;
    for scores in [&[][..], &[q(1), q(2)][..], &[q(1), q(2), q(3), q(4)][..]] {
        let projected = envelope.select(scores);
        assert_eq!(projected.action(), Verdict::Deny);
        assert_eq!(
            projected.outcome(),
            ProjectionOutcome::Fallback(FallbackReason::ScorerError)
        );
    }
    Ok(())
}

#[test]
fn select_takes_the_maximum_and_the_first_on_ties() -> Result<(), EnvelopeError> {
    let envelope = Envelope::new(&VERDICTS)?;
    let picked = envelope.select(&[q(-5), q(9), q(3)]);
    assert_eq!(picked.action(), Verdict::PendingApproval);
    assert_eq!(picked.outcome(), ProjectionOutcome::Identity);

    let tie = envelope.select(&[q(1), q(7), q(7)]);
    assert_eq!(tie.action(), Verdict::PendingApproval);

    let all_equal = envelope.select(&[Q16_16::MIN, Q16_16::MIN, Q16_16::MIN]);
    assert_eq!(all_equal.action(), Verdict::Deny);
    assert_eq!(all_equal.outcome(), ProjectionOutcome::Identity);

    let last = envelope.select(&[Q16_16::MIN, q(0), Q16_16::MAX]);
    assert_eq!(last.action(), Verdict::Allow);
    Ok(())
}

proptest! {
    #[test]
    fn projection_is_total_and_admitted(
        feasible in proptest::collection::vec(any::<u8>(), 1..16),
        proposal in proptest::option::of(any::<u8>()),
        failed in proptest::option::of(0usize..FALLBACK_REASONS.len()),
    ) {
        let envelope = Envelope::new(&feasible).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        let input = match failed {
            Some(index) => Err(FALLBACK_REASONS[index]),
            None => Ok(proposal),
        };
        let projected = envelope.project(input);
        prop_assert!(envelope.admits(projected.action()));
        match (input, projected.outcome()) {
            (Ok(Some(a)), ProjectionOutcome::Identity) => {
                prop_assert!(feasible.contains(&a));
                prop_assert_eq!(projected.action(), a);
            }
            (_, ProjectionOutcome::Fallback(reason)) => {
                prop_assert_eq!(projected.action(), feasible[0]);
                let expected = match input {
                    Err(r) => r,
                    Ok(None) => FallbackReason::EmptyProposal,
                    Ok(Some(_)) => FallbackReason::ProposalInfeasible,
                };
                prop_assert_eq!(reason, expected);
                if let Ok(Some(a)) = input {
                    prop_assert!(!feasible.contains(&a));
                }
            }
            (_, outcome) => prop_assert!(false, "unexpected outcome {:?}", outcome),
        }
    }

    #[test]
    fn projection_is_idempotent_on_its_result(
        feasible in proptest::collection::vec(any::<u8>(), 1..16),
        proposal in proptest::option::of(any::<u8>()),
    ) {
        let envelope = Envelope::new(&feasible).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        let first = envelope.project(Ok(proposal));
        let second = envelope.project(Ok(Some(first.action())));
        prop_assert_eq!(second.action(), first.action());
        prop_assert_eq!(second.outcome(), ProjectionOutcome::Identity);
    }

    #[test]
    fn select_is_the_first_argmax(
        pairs in proptest::collection::vec((any::<u8>(), any::<i32>()), 1..16),
    ) {
        let (feasible, bits): (Vec<u8>, Vec<i32>) = pairs.iter().copied().unzip();
        let scores: Vec<Q16_16> = bits.iter().copied().map(Q16_16::from_bits).collect();
        let envelope = Envelope::new(&feasible).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        let best = bits.iter().copied().max().unwrap_or(i32::MIN);
        let first = bits.iter().position(|b| *b == best).unwrap_or(0);
        let picked = envelope.select(&scores);
        prop_assert_eq!(picked.action(), feasible[first]);
        prop_assert_eq!(picked.outcome(), ProjectionOutcome::Identity);
    }
}
