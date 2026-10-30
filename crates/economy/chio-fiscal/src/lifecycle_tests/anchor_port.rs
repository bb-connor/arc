//! External fiscal state anchor port: authenticated reads, compare-and-swap advance and checkpoint decoding.

use super::*;

pub(super) enum AnchorState {
    Available(Box<SignedFiscalContinuityCheckpoint>),
    Unavailable,
}

pub(super) struct TestAnchor {
    pub(super) state: Mutex<AnchorState>,
}

impl FiscalStateAnchor for TestAnchor {
    fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        match &*self
            .state
            .lock()
            .map_err(|_| FiscalStateAnchorError::Unavailable)?
        {
            AnchorState::Available(checkpoint) => Ok(checkpoint.as_ref().clone()),
            AnchorState::Unavailable => Err(FiscalStateAnchorError::Unavailable),
        }
    }

    fn compare_and_swap(
        &self,
        expected_checkpoint_digest: &str,
        advance: &VerifiedFiscalContinuityAdvance,
    ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FiscalStateAnchorError::Unavailable)?;
        let AnchorState::Available(current) = &*state else {
            return Err(FiscalStateAnchorError::Unavailable);
        };
        let current_digest = sha256_hex(
            &canonical_json_bytes(current).map_err(|_| FiscalStateAnchorError::Divergence)?,
        );
        if current_digest != expected_checkpoint_digest
            || expected_checkpoint_digest != advance.current().digest()
        {
            return Err(FiscalStateAnchorError::Conflict);
        }
        let committed = advance.next().signed().clone();
        *state = AnchorState::Available(Box::new(committed.clone()));
        Ok(committed)
    }
}

struct FalseAcknowledgingAnchor {
    current: SignedFiscalContinuityCheckpoint,
}

impl FiscalStateAnchor for FalseAcknowledgingAnchor {
    fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        Ok(self.current.clone())
    }

    fn compare_and_swap(
        &self,
        _expected_checkpoint_digest: &str,
        _advance: &VerifiedFiscalContinuityAdvance,
    ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        Ok(self.current.clone())
    }
}

#[test]
fn external_anchor_port_reads_authentically_and_cas_advances() -> TestResult {
    let fixture = continuity_fixture()?;
    let head = FiscalScheduleHead::from_signed(fixture.amendment.schedule.signed())?;
    let next = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(fixture.genesis.digest().to_owned()),
        pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
        pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
        pinned_charter_sequence: fixture.amendment.charter.body().sequence,
        runtime_readiness_digest: fixture.readiness.digest().to_owned(),
        domains: activated_domains(head.clone())?,
        trusted_clock_high_water: 70,
        staged_transition: Some(FiscalStagedTransition::new(
            fixture.amendment.activation.body().activation_id.clone(),
            fixture.amendment.activation.digest().to_owned(),
        )?),
    }
    .sign(&fixture.policy, &fixture.anchor_key)?;
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &fixture.genesis,
        next,
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(fixture.amendment.activation.clone()),
            readiness: Box::new(fixture.readiness.clone()),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(fixture.amendment.schedule.clone()),
        },
    )?;
    let anchor = TestAnchor {
        state: Mutex::new(AnchorState::Available(Box::new(
            fixture.genesis.signed().clone(),
        ))),
    };
    assert_eq!(
        read_verified_fiscal_checkpoint(&anchor, &fixture.policy, &fixture.charters)?.digest(),
        fixture.genesis.digest()
    );
    let commit = commit_fiscal_continuity_advance(
        &anchor,
        advance.clone(),
        &fixture.policy,
        &fixture.charters,
    )?;
    assert_eq!(
        read_verified_fiscal_checkpoint(&anchor, &fixture.policy, &fixture.charters)?.digest(),
        advance.next().digest()
    );
    let authority = commit.into_activation_authority()?;
    assert_eq!(authority.checkpoint_digest(), advance.next().digest());
    let history = FiscalActivationHistory::new(vec![authority])?;
    assert!(history
        .verify_head(&head, FiscalDomain::TierLimits, 70)
        .is_ok());
    let recovered = recover_fiscal_continuity_advance(
        &anchor,
        advance.clone(),
        &fixture.policy,
        &fixture.charters,
    )?;
    assert!(FiscalActivationHistory::new(vec![recovered.into_activation_authority()?]).is_ok());

    let false_acknowledgement = FalseAcknowledgingAnchor {
        current: fixture.genesis.signed().clone(),
    };
    assert!(matches!(
        commit_fiscal_continuity_advance(
            &false_acknowledgement,
            advance,
            &fixture.policy,
            &fixture.charters,
        ),
        Err(FiscalStateAnchorError::Divergence)
    ));
    let unavailable = TestAnchor {
        state: Mutex::new(AnchorState::Unavailable),
    };
    assert!(matches!(
        read_verified_fiscal_checkpoint(&unavailable, &fixture.policy, &fixture.charters),
        Err(FiscalStateAnchorError::Unavailable)
    ));
    Ok(())
}

#[test]
fn checkpoint_strict_decode_and_expiry_boundary_fail_closed() -> TestResult {
    let fixture = continuity_fixture()?;
    let bytes = fixture.activated.canonical_bytes()?;
    assert_eq!(
        VerifiedFiscalContinuityCheckpoint::from_canonical_bytes(
            &bytes,
            &fixture.policy,
            &fixture.charters,
        )?
        .digest(),
        fixture.activated.digest()
    );
    let mut noncanonical = bytes;
    noncanonical.push(b'\n');
    assert!(
        matches!(VerifiedFiscalContinuityCheckpoint::from_canonical_bytes(
        &noncanonical,
        &fixture.policy,
        &fixture.charters,
    ), Err(FiscalError::Input(source)) if source.code() == "urn:chio:error:attest:signed-json-noncanonical")
    );

    let expired_checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
        FiscalContinuityCheckpointBuilder {
            continuity_sequence: 2,
            previous_checkpoint_digest: Some(fixture.activated.digest().to_owned()),
            pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
            pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
            pinned_charter_sequence: fixture.amendment.charter.body().sequence,
            runtime_readiness_digest: fixture.readiness.digest().to_owned(),
            domains: fixture.activated.body().domains.clone(),
            trusted_clock_high_water: 900,
            staged_transition: fixture.activated.body().staged_transition.clone(),
        }
        .sign(&fixture.policy, &fixture.anchor_key)?,
        &fixture.policy,
        &fixture.charters,
    )?;
    let expired_authority = FiscalAuthorityState::from_checkpoint(
        &fixture.policy,
        &expired_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )?;
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&expired_checkpoint),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &expired_authority,
            &fixture.charters,
            &[fixture.amendment.schedule.signed().clone()],
            FiscalDomain::TierLimits,
            Some("USD"),
            900,
        ),
        FiscalResolution::Denied(FiscalDenialReason::NoValidLastKnownGood)
    );
    Ok(())
}
