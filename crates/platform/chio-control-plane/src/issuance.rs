mod attestation;
mod authority;
mod reputation;
mod scope;
mod types;

pub use self::authority::{wrap_capability_authority, wrap_capability_authority_with_clock};
pub(crate) use self::authority::{
    wrap_capability_authority_with_deferred_lineage, wrap_capability_authority_with_receipt_store,
};
pub use self::reputation::{
    build_local_reputation_corpus, build_local_reputation_corpus_with_read_context,
};
pub use self::types::{
    ImportedTrustReport, LocalReputationInspection, LocalReputationTierView, ProbationaryStatus,
    ReputationScoringSource,
};

pub(crate) use self::reputation::{
    inspect_local_reputation, inspect_local_reputation_with_read_context,
    inspect_local_reputation_with_store,
};

#[cfg(test)]
use self::attestation::verify_runtime_attestation_for_issuance;
#[cfg(test)]
use chio_test_support::clock::unix_seconds as unix_now;

#[cfg(test)]
mod tests;
