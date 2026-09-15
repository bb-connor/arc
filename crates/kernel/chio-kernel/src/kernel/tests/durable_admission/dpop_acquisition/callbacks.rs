use super::*;

#[derive(Clone, Copy, Default, Debug)]
pub(super) enum Mode {
    #[default]
    Normal,
    NoOp,
    LostAck,
    Panic,
    WrongReference,
    WrongSuccessor,
    HistoryPanic,
    LostAckAndHistoryPanic,
}

#[derive(Default)]
pub(in super::super) struct TestDpop(pub(super) Mutex<State>);
#[derive(Default)]
pub(super) struct State {
    pub(super) authority: Option<DpopReplayAuthorityV1>,
    pub(super) history: Vec<DpopReplayClaimHistoryV1>,
    pub(super) mode: Mode,
    pub(super) history_panics: usize,
    pub(super) release_noop: bool,
}

impl TestDpop {
    pub(in super::super) fn activation(
        &self,
        expected: &DpopReplayAuthorityV1,
    ) -> Result<DpopReplayAuthorityV1, AdmissionOperationStoreError> {
        let state = self.0.lock().expect("DPoP state");
        let authority = state.authority.as_ref().ok_or_else(|| {
            AdmissionOperationStoreError::Unavailable("test DPoP authority unsupported".into())
        })?;
        if expected != authority {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        Ok(authority.clone())
    }

    pub(in super::super) fn claim(
        &self,
        store: &TestAdmissionOperationStore,
        original: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        intent: &DpopReplayClaimIntentV1,
        now: u64,
    ) -> Result<(AdmissionOperationV1, DpopReplayClaimReferenceV1), AdmissionOperationStoreError>
    {
        let mode = self.0.lock().expect("state").mode;
        let reference = DpopReplayClaimReferenceV1::new(
            original.binding().operation_id().clone(),
            intent.episode_id().clone(),
            digest('c'),
        );
        if matches!(mode, Mode::NoOp) {
            return Ok((original.clone(), reference));
        }
        let command = AdmissionOperationCommand::new(
            original.binding().operation_id().clone(),
            original.version(),
            lease.clone(),
            vec![AdmissionAttachment::DpopReplayLedgerDigest(digest('a'))],
            Some(original.state()),
            None,
            None,
        )?;
        let updated = original.apply_command(&command, now)?.into_operation();
        store.state.lock().expect("operation").operation = Some(updated.clone());
        {
            let mut state = self.0.lock().expect("state");
            state.history.push(DpopReplayClaimHistoryV1 {
                reference: reference.clone(),
                intent: intent.clone(),
                disposition: DpopReplayClaimDisposition::ReservedBeforeDispatch,
            });
            if matches!(mode, Mode::HistoryPanic | Mode::LostAckAndHistoryPanic) {
                state.history_panics = 1;
            }
        }
        match mode {
            Mode::LostAck | Mode::LostAckAndHistoryPanic => {
                Err(AdmissionOperationStoreError::OutcomeUnknown(
                    "lost DPoP claim acknowledgement".into(),
                ))
            }
            Mode::Panic => panic!("DPoP committed then callback panicked"),
            Mode::WrongReference => Ok((
                updated,
                DpopReplayClaimReferenceV1::new(
                    reference.operation_id().clone(),
                    reference.episode_id().clone(),
                    digest('f'),
                ),
            )),
            Mode::WrongSuccessor => Ok((original.clone(), reference)),
            _ => Ok((updated, reference)),
        }
    }

    pub(in super::super) fn history(
        &self,
        operation: Option<AdmissionOperationV1>,
    ) -> Result<
        Option<(AdmissionOperationV1, Vec<DpopReplayClaimHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        let mut state = self.0.lock().expect("state");
        if state.history_panics > 0 {
            state.history_panics -= 1;
            drop(state);
            panic!("DPoP history readback panicked");
        }
        Ok(operation.map(|operation| (operation, state.history.clone())))
    }

    pub(in super::super) fn release(
        &self,
        reference: &DpopReplayClaimReferenceV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut state = self.0.lock().expect("state");
        if state.release_noop {
            return Ok(());
        }
        let claim = state
            .history
            .iter_mut()
            .find(|claim| &claim.reference == reference)
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        claim.disposition = DpopReplayClaimDisposition::ReleasedBeforeDispatch;
        Ok(())
    }
}
