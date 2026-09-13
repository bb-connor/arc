//! Local preparation is not durable credential ownership or dispatch authority.

use super::*;
use crate::kernel::credential_reservation::PreparedDispatchCredentials;
use std::sync::{atomic::AtomicU8, Arc};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[path = "prepared_dispatch_credentials/fixture.rs"]
mod fixture;
use fixture::Fixture;

#[test]
fn oversized_dpop_identity_denies_before_other_credential_probes_or_mutations() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture
        .request
        .dpop_proof
        .as_mut()
        .ok_or("dpop proof")?
        .body
        .nonce = "private-proof-nonce".repeat(300);
    fixture.nonce.mode.store(2, Ordering::SeqCst);
    let result = fixture.prepare();
    assert!(result
        .as_ref()
        .is_err_and(|error| error.to_string().contains("4096-byte limit")));
    fixture.assert_no_writes()?;
    Ok(())
}

#[test]
fn retired_dpop_source_denies_preparation_before_other_credentials_mutate() -> TestResult {
    use crate::dpop::replay_source::DpopReplaySourceBinding;
    let fixture = Fixture::new()?;
    let source = fixture.kernel.dpop_replay_source()?;
    let snapshot = source.preview_unsealed(&DpopReplaySourceBinding {
        dpop_authority_id: crate::admission_operation::AdmissionIdentifier::try_new(
            "authority",
            "dpop",
        )?,
        destination_authority_id: crate::admission_operation::AdmissionIdentifier::try_new(
            "destination",
            "admission",
        )?,
    })?;
    source.seal_exact(&snapshot)?;
    assert!(fixture.prepare().is_err());
    fixture.assert_no_writes()?;
    source.verify_exact(&snapshot)?;
    Ok(())
}

#[test]
fn dpop_retirement_between_preparation_and_consumption_rejects_the_stale_plan() -> TestResult {
    use crate::dpop::replay_source::DpopReplaySourceBinding;
    let fixture = Fixture::new()?;
    let prepared = fixture.prepare()?;
    let source = fixture.kernel.dpop_replay_source()?;
    let snapshot = source.preview_unsealed(&DpopReplaySourceBinding {
        dpop_authority_id: crate::admission_operation::AdmissionIdentifier::try_new(
            "authority",
            "dpop",
        )?,
        destination_authority_id: crate::admission_operation::AdmissionIdentifier::try_new(
            "destination",
            "admission",
        )?,
    })?;
    source.seal_exact(&snapshot)?;
    assert!(prepared.reserve().is_err());
    fixture.assert_no_writes()?;
    source.verify_exact(&snapshot)?;
    Ok(())
}

#[test]
fn prepared_credentials_and_dropped_plans_do_not_mutate_replay_stores() -> TestResult {
    let fixture = Fixture::new()?;
    let plan = fixture.prepare()?;
    fixture.assert_no_writes()?;
    drop(plan);
    fixture.assert_no_writes()?;
    let reservation = fixture.prepare()?.reserve()?;
    assert!(fixture.nonce_consumed()?);
    assert_eq!(fixture.dpop_occupancy()?, 1);
    assert_eq!(fixture.writes(), (1, 0, 1, 0, 0));
    reservation.rollback_before_dispatch()?;
    assert!(!fixture.nonce_consumed()?);
    assert_eq!(fixture.dpop_occupancy()?, 0);
    assert_eq!(fixture.writes(), (1, 1, 1, 0, 1));
    Ok(())
}

#[test]
fn competing_prepared_credentials_cannot_release_the_winning_reservation() -> TestResult {
    let fixture = Fixture::new()?;
    let first = fixture.prepare()?;
    let second = fixture.prepare()?;
    fixture.assert_no_writes()?;
    let mut owner = first.reserve()?;
    let refused = second.reserve();
    assert!(refused
        .as_ref()
        .is_err_and(|error| error.to_string().contains("nonce replayed")));
    assert!(fixture.nonce_consumed()?);
    assert_eq!(fixture.dpop_occupancy()?, 1);
    assert_eq!(fixture.writes(), (1, 0, 1, 0, 0));
    owner.commit()?;
    assert_eq!(fixture.writes(), (1, 0, 1, 1, 0));
    drop(owner);
    assert!(fixture.prepare()?.reserve().is_err());
    assert!(fixture.nonce_consumed()?);
    assert_eq!(fixture.dpop_occupancy()?, 1);
    Ok(())
}

#[test]
fn prepared_credentials_validate_the_complete_set_before_any_reservation() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.request.approval_token = Some(make_governed_approval_token(
        &fixture.kernel.config.keypair,
        &fixture.request.capability.subject,
        fixture.request.governed_intent.as_ref().ok_or("intent")?,
        "different-request",
    ));
    let refused = fixture.prepare();
    assert!(refused.as_ref().is_err_and(|error| error
        .to_string()
        .contains("approval token request binding does not match")));
    fixture.assert_no_writes()?;
    Ok(())
}

#[test]
fn prepared_credentials_reject_expiry_before_the_first_store_write() -> TestResult {
    for nonce_expiry in [true, false] {
        let mut fixture = Fixture::new()?;
        let expiry = if nonce_expiry {
            fixture.request.approval_token = None;
            u64::try_from(
                fixture
                    .request
                    .execution_nonce
                    .as_ref()
                    .ok_or("nonce")?
                    .expires_at(),
            )?
        } else {
            fixture.request.execution_nonce = None;
            fixture
                .request
                .approval_token
                .as_ref()
                .ok_or("approval")?
                .expires_at
        };
        let prepared = fixture.prepare()?;
        fixture.assert_no_writes()?;
        let _clock = crate::scope_fixed_runtime_for_current_thread(expiry, []);
        let refused = prepared.reserve();
        assert!(
            refused.as_ref().is_err_and(|error| {
                matches!(
                    (nonce_expiry, error),
                    (true, KernelError::Internal(_))
                        | (false, KernelError::GovernedTransactionDenied(_))
                ) && error.to_string().to_lowercase().contains("expired")
            }),
            "credential did not reject at its expiry boundary"
        );
        fixture.assert_no_writes()?;
    }
    Ok(())
}

#[test]
fn prepared_credentials_contain_capability_probe_panics_without_partial_reservation() -> TestResult
{
    for after_preparation in [false, true] {
        let fixture = Fixture::new()?;
        if after_preparation {
            let prepared = fixture.prepare()?;
            fixture.nonce.mode.store(2, Ordering::SeqCst);
            let refused = prepared.reserve();
            assert!(refused
                .as_ref()
                .is_err_and(|error| error.to_string().contains("capability panicked")));
        } else {
            fixture.nonce.mode.store(2, Ordering::SeqCst);
            let refused = fixture.prepare();
            assert!(refused
                .as_ref()
                .is_err_and(|error| error.to_string().contains("capability panicked")));
        }
        fixture.assert_no_writes()?;
    }
    Ok(())
}

#[test]
fn prepared_credentials_reject_changed_nonce_backend_semantics_before_mutation() -> TestResult {
    for initial in [0, 1] {
        let fixture = Fixture::new()?;
        fixture.nonce.mode.store(initial, Ordering::SeqCst);
        let prepared = fixture.prepare()?;
        fixture.nonce.mode.store(1 - initial, Ordering::SeqCst);
        let refused = prepared.reserve();
        assert!(refused.as_ref().is_err_and(|error| error
            .to_string()
            .contains("capability changed after preparation")));
        fixture.assert_no_writes()?;
    }
    Ok(())
}

#[test]
fn prepared_credentials_do_not_turn_approval_validation_into_replay_permission() -> TestResult {
    let fixture = Fixture::new()?;
    fixture
        .kernel
        .consume_governed_approval_for_dispatch(&fixture.request)?;
    let before = fixture.writes();
    let prepared = fixture.prepare()?;
    assert_eq!(fixture.writes(), before);
    let refused = prepared.reserve();
    assert!(refused.as_ref().is_err_and(|error| error
        .to_string()
        .contains("approval token has already been consumed")));
    assert!(!fixture.nonce_consumed()?);
    assert_eq!(fixture.dpop_occupancy()?, 0);
    assert_eq!(fixture.writes(), (1, 1, 2, 1, 0));
    Ok(())
}

#[test]
fn caller_authorization_preparation_preserves_no_presented_nonce_and_required_approval(
) -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.request.execution_nonce = None;
    fixture.nonce.mode.store(2, Ordering::SeqCst);
    let reservation = fixture.kernel.reserve_caller_authorization_credentials(
        &fixture.request,
        &fixture.request.capability,
        true,
        current_unix_timestamp(),
        true,
    )?;
    assert_eq!(fixture.writes(), (0, 0, 1, 0, 0));
    reservation.rollback_before_dispatch()?;
    let before = fixture.writes();
    fixture.request.approval_token = None;
    assert!(fixture
        .kernel
        .reserve_caller_authorization_credentials(
            &fixture.request,
            &fixture.request.capability,
            true,
            current_unix_timestamp(),
            true,
        )
        .is_err());
    assert_eq!(fixture.writes(), before);
    assert_eq!(fixture.dpop_occupancy()?, 0);
    Ok(())
}
