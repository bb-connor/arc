#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationChallengeId(String);
ledger_text!(PresentationChallengeId, identifier, "challenge_id");

/// SHA-256 of a challenge's canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeHash(String);
ledger_text!(ChallengeHash, digest, "challenge_hash");

/// SHA-256 of the canonical JSON of the presentation that spent a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationHash(String);
ledger_text!(PresentationHash, digest, "presentation_hash");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    Issued,
    Verified,
    Consumed,
    Expired,
}

/// A status a challenge can still leave by a spend or an expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveChallengeStatus {
    Issued,
    Verified,
}

impl From<LiveChallengeStatus> for ChallengeStatus {
    fn from(status: LiveChallengeStatus) -> Self {
        match status {
            LiveChallengeStatus::Issued => Self::Issued,
            LiveChallengeStatus::Verified => Self::Verified,
        }
    }
}

/// The spends a challenge admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeTransition {
    Verify,
    Issue,
    IssueVerified,
}

impl ChallengeTransition {
    pub const fn from(self) -> LiveChallengeStatus {
        match self {
            Self::Verify | Self::Issue => LiveChallengeStatus::Issued,
            Self::IssueVerified => LiveChallengeStatus::Verified,
        }
    }

    pub const fn to(self) -> ChallengeStatus {
        match self {
            Self::Verify => ChallengeStatus::Verified,
            Self::Issue | Self::IssueVerified => ChallengeStatus::Consumed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationChallengeRecord {
    pub challenge_id: PresentationChallengeId,
    pub challenge_hash: ChallengeHash,
    pub challenge_json: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPresentationChallenge {
    pub record: PresentationChallengeRecord,
    pub status: ChallengeStatus,
    pub presentation_hash: Option<PresentationHash>,
}

/// Every method is one atomic unit.
pub trait PresentationChallengeLedger {
    type Error;

    /// Refuses a duplicate identifier.
    fn insert(&self, record: &PresentationChallengeRecord) -> Result<(), Self::Error>;

    fn get(
        &self,
        challenge_id: &PresentationChallengeId,
    ) -> Result<Option<StoredPresentationChallenge>, Self::Error>;

    /// Expires the row only while it is still at `from`; returns whether it was.
    fn expire(
        &self,
        challenge_id: &PresentationChallengeId,
        from: LiveChallengeStatus,
    ) -> Result<bool, Self::Error>;

    /// Applies `transition` at `at` only while the row is still at
    /// `transition.from()`; returns whether it was.
    fn consume(
        &self,
        challenge_id: &PresentationChallengeId,
        transition: ChallengeTransition,
        at: u64,
        presentation_hash: &PresentationHash,
    ) -> Result<bool, Self::Error>;
}
