//! Resume-record integrity envelopes and the subscriptions only `v3` authenticates.
use super::*;

/// A client subscription the resume record carries across restore.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PersistedSubscription {
    /// A standard MCP `resources/subscribe`, keyed by URI within the session.
    Standard { uri: String, capability_id: String },
}

/// Integrity envelope a signed session record names. An absent value is `v2`,
/// so records written before the discriminator keep their exact bytes.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum RemoteSessionEnvelope {
    #[default]
    V2,
    V3,
}

impl RemoteSessionEnvelope {
    pub(super) fn is_v2(&self) -> bool {
        *self == Self::V2
    }
}

/// The resume-record envelope a session signs with. It only ever rises: a
/// session that has signed or loaded `v3` never signs `v2` again.
#[derive(Debug)]
pub(super) struct ResumeEnvelopeRatchet(AtomicBool);

impl ResumeEnvelopeRatchet {
    pub(super) fn new(floor: RemoteSessionEnvelope) -> Self {
        Self(AtomicBool::new(floor == RemoteSessionEnvelope::V3))
    }

    pub(super) fn raise(&self, envelope: RemoteSessionEnvelope) {
        if envelope == RemoteSessionEnvelope::V3 {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    pub(super) fn select(&self, subscriptions: &[PersistedSubscription]) -> RemoteSessionEnvelope {
        if !subscriptions.is_empty() {
            self.raise(RemoteSessionEnvelope::V3);
        }
        self.current()
    }

    pub(super) fn current(&self) -> RemoteSessionEnvelope {
        if self.0.load(Ordering::SeqCst) {
            RemoteSessionEnvelope::V3
        } else {
            RemoteSessionEnvelope::V2
        }
    }
}
