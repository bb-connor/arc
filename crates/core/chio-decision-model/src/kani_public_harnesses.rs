#![allow(clippy::indexing_slicing)]

use chio_fixed::Q16_16;

use crate::{Envelope, FallbackReason, ProjectionOutcome};

fn any_reason() -> FallbackReason {
    match kani::any::<u8>() % 5 {
        0 => FallbackReason::EmptyProposal,
        1 => FallbackReason::ProposalInfeasible,
        2 => FallbackReason::ScorerError,
        3 => FallbackReason::WorkExhausted,
        _ => FallbackReason::PolicyUnavailable,
    }
}

fn any_proposal() -> Result<Option<u8>, FallbackReason> {
    if kani::any() {
        Err(any_reason())
    } else if kani::any() {
        Ok(Some(kani::any()))
    } else {
        Ok(None)
    }
}

#[kani::proof]
fn verify_projection_total_and_admitted() {
    let feasible: [u8; 4] = kani::any();
    let Ok(envelope) = Envelope::new(&feasible) else {
        panic!("a four-element feasible set is accepted");
    };
    let proposal = any_proposal();
    let projected = envelope.project(proposal);
    assert!(feasible.contains(&projected.action()));
    match projected.outcome() {
        ProjectionOutcome::Identity => {
            assert_eq!(proposal, Ok(Some(projected.action())));
        }
        ProjectionOutcome::Fallback(_) => assert_eq!(projected.action(), feasible[0]),
        ProjectionOutcome::Clipped => panic!("project never clips"),
    }
}

#[kani::proof]
fn verify_projection_idempotent_on_admitted() {
    let feasible: [u8; 4] = kani::any();
    let Ok(envelope) = Envelope::new(&feasible) else {
        panic!("a four-element feasible set is accepted");
    };
    let first = envelope.project(any_proposal());
    let second = envelope.project(Ok(Some(first.action())));
    assert_eq!(second.action(), first.action());
    assert_eq!(second.outcome(), ProjectionOutcome::Identity);
}

#[kani::proof]
fn verify_select_in_envelope() {
    let feasible: [u8; 4] = kani::any();
    let bits: [i32; 4] = kani::any();
    let scores = bits.map(Q16_16::from_bits);
    let Ok(envelope) = Envelope::new(&feasible) else {
        panic!("a four-element feasible set is accepted");
    };
    let picked = envelope.select(&scores);
    assert_eq!(picked.outcome(), ProjectionOutcome::Identity);
    let index: usize = kani::any();
    kani::assume(index < 4);
    assert!(feasible.contains(&picked.action()));
    let winner = (0..4)
        .find(|i| (0..4).all(|j| bits[*i] >= bits[j]))
        .unwrap_or(0);
    assert_eq!(picked.action(), feasible[winner]);
    assert!(bits[index] <= bits[winner]);
}
