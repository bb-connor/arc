//! Driving one case through the composed receiver.

use crate::receiver::{
    AdmissionOutcome, BaselineProfile, ComposedReceiver, DurabilityMode, ReceiverError,
};
use crate::receiver_state::ReceiverState;
use crate::request::ComposedEnvelope;
use crate::scenario::{self, Keys};
use crate::store::BaselineStore;
use std::cell::Cell;
use std::path::{Path, PathBuf};

/// Which receiver-held state a case runs against. Every variant is the same
/// vendor with one fact changed, so a difference in outcome is attributable to
/// that fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateVariant {
    /// The vendor as provisioned.
    Default,
    /// The vendor pinned one key for both the counterparty's channel and its
    /// policy engine.
    CollapsedKeys,
    /// The vendor's own agreement record rates the counterparty self-asserted
    /// rather than attested.
    DowngradedAssurance,
    /// A different vendor that pinned the same counterparty keys and
    /// provisioned the same agreement identifier.
    SecondReceiver,
}

/// What one drive observed.
#[derive(Debug, Clone)]
pub struct Observed {
    pub admitted: bool,
    pub dispatched: bool,
    pub code: Option<String>,
    pub step: Option<u32>,
    pub decision_record_bytes: usize,
}

impl From<&AdmissionOutcome> for Observed {
    fn from(outcome: &AdmissionOutcome) -> Self {
        Self {
            admitted: outcome.admitted,
            dispatched: outcome.dispatched,
            code: outcome.denial_code.clone(),
            step: outcome.denial_step,
            decision_record_bytes: outcome.decision_record_bytes,
        }
    }
}

pub struct Runner<'a> {
    pub keys: &'a Keys,
    pub profile: BaselineProfile,
    pub durability: DurabilityMode,
    root: PathBuf,
    sequence: Cell<u64>,
}

impl<'a> Runner<'a> {
    pub fn new(
        keys: &'a Keys,
        profile: BaselineProfile,
        durability: DurabilityMode,
        root: &Path,
    ) -> Self {
        Self {
            keys,
            profile,
            durability,
            root: root.to_path_buf(),
            sequence: Cell::new(0),
        }
    }

    pub fn state(&self, variant: StateVariant) -> ReceiverState {
        let mut state = scenario::vendor_state(self.keys, variant == StateVariant::CollapsedKeys);
        match variant {
            StateVariant::DowngradedAssurance => {
                if let Some(agreement) = state.agreements.get_mut(scenario::AGREEMENT) {
                    agreement.assurance_level = "self_asserted".to_string();
                }
            }
            StateVariant::SecondReceiver => {
                state.receiver_id = scenario::OTHER_VENDOR.to_string();
            }
            StateVariant::Default | StateVariant::CollapsedKeys => {}
        }
        state
    }

    /// A store nobody else has written to, so a case's replay table starts
    /// empty.
    pub fn fresh_store(&self) -> Result<BaselineStore, String> {
        let next = self.sequence.get() + 1;
        self.sequence.set(next);
        let path = self.root.join(format!(
            "baseline-{}-{}-{next}.sqlite",
            self.profile.as_str(),
            match self.durability {
                DurabilityMode::BeforeDispatch => "before",
                DurabilityMode::AfterDispatch => "after",
            }
        ));
        BaselineStore::open(&path).map_err(|error| error.to_string())
    }

    pub fn admit(
        &self,
        state: &ReceiverState,
        store: &BaselineStore,
        envelope: &ComposedEnvelope,
        now_unix_ms: u64,
    ) -> Result<AdmissionOutcome, ReceiverError> {
        let mut dispatched = 0u32;
        let mut sink = |_: &ComposedEnvelope| {
            dispatched += 1;
        };
        let receiver = ComposedReceiver {
            state,
            profile: self.profile,
            durability: self.durability,
            signing_key: &self.keys.vendor_decision,
            store,
        };
        receiver.admit(envelope, now_unix_ms, &mut sink)
    }

    /// The common shape: one fresh store, one state variant, one envelope.
    pub fn drive_one(
        &self,
        variant: StateVariant,
        envelope: &ComposedEnvelope,
        now_unix_ms: u64,
    ) -> Result<Observed, String> {
        let state = self.state(variant);
        let store = self.fresh_store()?;
        let outcome = self
            .admit(&state, &store, envelope, now_unix_ms)
            .map_err(|error| error.to_string())?;
        Ok(Observed::from(&outcome))
    }
}
