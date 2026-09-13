//! Driving one case through the composed receiver.

use crate::receiver::{
    AdmissionOutcome, BaselineProfile, ComposedReceiver, DurabilityMode, PrivateProfile,
    ReceiverError,
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
    /// The vendor's trust bundle carries one key for both the counterparty's
    /// SVID and its authorization server.
    CollapsedKeys,
    /// The vendor's own agreement record rates the counterparty self-asserted
    /// rather than attested.
    DowngradedAssurance,
    /// A different vendor that installed the same trust bundle and provisioned
    /// the same agreement identifier.
    SecondReceiver,
    /// The vendor's own record for the live agreement has moved to a later
    /// version, which took effect a moment ago. Nothing else about the record
    /// changes: it is not retired, the participants, actions and ceilings are
    /// the ones the credential was issued under, and the only altered facts are
    /// the version the receiver now holds and when it took effect.
    AgreementVersionAdvanced,
}

impl StateVariant {
    /// Stable name for the receiver state a case runs against, so that two
    /// cases running the same drive against different state are recorded as
    /// two experiments and two cases running it against the same state are
    /// recorded as one.
    pub fn as_str(self) -> &'static str {
        match self {
            StateVariant::Default => "default",
            StateVariant::CollapsedKeys => "collapsed_keys",
            StateVariant::DowngradedAssurance => "downgraded_assurance",
            StateVariant::SecondReceiver => "second_receiver",
            StateVariant::AgreementVersionAdvanced => "agreement_version_advanced",
        }
    }
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
    /// Names an operator agreed to read out of a slot the formats leave open.
    /// Neither wiring carries one; a runner that does is measuring what such an
    /// agreement buys.
    pub private_profile: Option<PrivateProfile>,
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
            private_profile: None,
            root: root.to_path_buf(),
            sequence: Cell::new(0),
        }
    }

    /// The same wiring, with an operator's private profile installed.
    pub fn with_private_profile(mut self, private_profile: PrivateProfile) -> Self {
        self.private_profile = Some(private_profile);
        self
    }

    pub fn state(&self, variant: StateVariant) -> ReceiverState {
        let mut state = scenario::vendor_state(self.keys, variant == StateVariant::CollapsedKeys);
        match variant {
            StateVariant::DowngradedAssurance => {
                if let Some(agreement) = state.agreements.get_mut(scenario::AGREEMENT) {
                    agreement.assurance_level = "self_asserted".to_string();
                }
            }
            StateVariant::AgreementVersionAdvanced => {
                if let Some(agreement) = state.agreements.get_mut(scenario::AGREEMENT) {
                    agreement.version += 1;
                    agreement.version_effective_at_unix_ms = scenario::NOW_MS - 1_000;
                }
            }
            StateVariant::SecondReceiver => {
                state.receiver_id = scenario::OTHER_VENDOR.to_string();
                state.receiver_uri = scenario::OTHER_VENDOR_URI.to_string();
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
            "baseline-{}-{}-{}{next}.sqlite",
            self.profile.as_str(),
            match self.durability {
                DurabilityMode::BeforeDispatch => "before",
                DurabilityMode::AfterDispatch => "after",
            },
            if self.private_profile.is_some() {
                "private-"
            } else {
                ""
            },
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
            private_profile: self.private_profile,
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
