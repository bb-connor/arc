//! A test-only port. These tests prove the engine's consumption protocol,
//! not production durability, native custody, or external effect behavior.
use chio_core_types::{Keypair, SignedDeclassificationGrant};
use chio_flow::{DeclassificationDispatchOutcome, DeclassificationError, FlowDenial};
use chio_recovery_lab::{
    fixture::{Case, LabResult},
    prepare_approved_offer, RecoveryError,
};
use chio_security_types::ports::{
    CanonicalBody, DeclassificationConsume, DeclassificationConsumeRequest,
    DeclassificationOutcomeRequest, DeclassificationUseState, DeclassificationUseStore,
    DestinationId, Digest32, PortError, PortResult, RecordId,
};
use std::sync::Mutex;

#[derive(Default)]
struct TestPort {
    state: Mutex<Option<(Digest32, DeclassificationUseState)>>,
    unavailable: bool,
}

impl DeclassificationUseStore for TestPort {
    fn consume(
        &self,
        request: &DeclassificationConsumeRequest,
    ) -> PortResult<DeclassificationConsume> {
        if self.unavailable {
            return Err(PortError::unavailable());
        }
        let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
        if let Some((request_hash, use_state)) = *state {
            return Ok(DeclassificationConsume::AlreadyConsumed {
                request_hash,
                state: use_state,
            });
        }
        *state = Some((
            request.request_hash,
            DeclassificationUseState::ConsumedPendingDispatch,
        ));
        Ok(DeclassificationConsume::Consumed)
    }

    fn record_outcome(&self, request: &DeclassificationOutcomeRequest) -> PortResult<()> {
        let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
        let (hash, status) = state.as_mut().ok_or_else(PortError::invalid_data)?;
        if *hash != request.request_hash || *status != request.expected_state {
            return Err(PortError::conflict());
        }
        *status = request.new_state;
        Ok(())
    }
}

#[test]
fn the_real_engine_consumes_the_grant_once() -> LabResult<()> {
    let case = Case::new()?;
    let offer = case.offer()?;
    let grant = case.grant(200)?;
    let port = TestPort::default();
    let first = prepare_approved_offer(&offer, &case.intent, &case.host, &grant, 151_000)?;
    let admission = first.consume_declassification_at(&port, 152_000)?;
    assert!(admission.declassification.is_some());
    let second = prepare_approved_offer(&offer, &case.intent, &case.host, &grant, 153_000)?;
    assert!(matches!(
        second.consume_declassification_at(&port, 154_000),
        Err(FlowDenial::DeclassificationReplay)
    ));
    Ok(())
}

#[test]
fn the_consumption_clock_cannot_extend_a_previously_valid_grant() -> LabResult<()> {
    let case = Case::new()?;
    let port = TestPort::default();
    let prepared = prepare_approved_offer(
        &case.offer()?,
        &case.intent,
        &case.host,
        &case.grant(160)?,
        151_000,
    )?;
    assert!(matches!(
        prepared.consume_declassification_at(&port, 160_000),
        Err(FlowDenial::DeclassificationExpired)
    ));
    assert!(port
        .state
        .lock()
        .map_err(|_| "poisoned test port")?
        .is_none());
    Ok(())
}

#[test]
fn an_unavailable_consumption_port_cannot_release_the_prepared_flow() -> LabResult<()> {
    let case = Case::new()?;
    let port = TestPort {
        unavailable: true,
        ..TestPort::default()
    };
    let prepared = prepare_approved_offer(
        &case.offer()?,
        &case.intent,
        &case.host,
        &case.grant(200)?,
        151_000,
    )?;
    assert!(matches!(
        prepared.consume_declassification_at(&port, 152_000),
        Err(FlowDenial::DeclassificationStoreFailure)
    ));
    Ok(())
}

#[test]
fn released_failed_and_unknown_outcomes_do_not_make_a_grant_reusable() -> LabResult<()> {
    for outcome in [
        DeclassificationDispatchOutcome::Released,
        DeclassificationDispatchOutcome::DispatchFailed,
        DeclassificationDispatchOutcome::OutcomeUnknownAfterDispatch,
    ] {
        let case = Case::new()?;
        let port = TestPort::default();
        let offer = case.offer()?;
        let grant = case.grant(200)?;
        let prepared = prepare_approved_offer(&offer, &case.intent, &case.host, &grant, 151_000)?;
        let admission = prepared.consume_declassification_at(&port, 152_000)?;
        let consumed = admission.declassification.ok_or("missing consumed grant")?;
        consumed.record_dispatch_outcome(&port, outcome, RecordId::new("lab-outcome")?)?;
        let second = prepare_approved_offer(&offer, &case.intent, &case.host, &grant, 153_000)?;
        assert!(matches!(
            second.consume_declassification_at(&port, 154_000),
            Err(FlowDenial::DeclassificationReplay)
        ));
    }
    Ok(())
}

#[test]
fn a_fresh_offer_cannot_rebind_an_old_signed_grant() -> LabResult<()> {
    let original = Case::new()?;
    let grant = original.grant(200)?;
    for variant in 0..3 {
        let mut changed = Case::new()?;
        match variant {
            0 => {
                changed.intent.canonical_request =
                    CanonicalBody::new(br#"{"body":"new disclosure"}"#.to_vec())?
            }
            1 => changed.intent.destination = DestinationId::new("new-public-sink")?,
            _ => changed.intent.tool_name = RecordId::new("new-tool")?,
        }
        assert!(matches!(
            prepare_approved_offer(
                &changed.offer()?,
                &changed.intent,
                &changed.host,
                &grant,
                151_000
            ),
            Err(RecoveryError::Grant(DeclassificationError::BindingMismatch))
        ));
    }
    Ok(())
}

#[test]
fn a_valid_signature_from_an_untrusted_key_cannot_approve_the_offer() -> LabResult<()> {
    let case = Case::new()?;
    let original = case.grant(200)?;
    let wrong_key = Keypair::from_seed(&[62; 32]);
    let wrong = SignedDeclassificationGrant::sign(original.body().clone(), &wrong_key)?;
    assert!(matches!(
        prepare_approved_offer(&case.offer()?, &case.intent, &case.host, &wrong, 151_000),
        Err(RecoveryError::Grant(
            DeclassificationError::UntrustedAuthority
        ))
    ));
    Ok(())
}
