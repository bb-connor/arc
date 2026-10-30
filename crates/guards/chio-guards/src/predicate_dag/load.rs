use chio_core::crypto::sha256_hex;
use chio_kernel::weights_binding::{evaluate_weights_binding, WeightsBindingRequest};
use chio_predicate_dag::{DagError, HeapScheduleStorage, ATOM_WORDS};
use chio_weights::{weights_hash_of, StringSet, VerifiedModelCard, WeightsError};

use super::{PredicateDagGuard, ScoreSource};

/// The capability scopes and tools the pipeline guarding this model admits.
/// The card's `allowed_capability_set` must cover the scopes and its
/// `banned_tools` must not intersect the tools.
#[derive(Clone, Debug)]
pub struct DecisionModelBinding {
    pub requested_scopes: StringSet,
    pub requested_tools: StringSet,
}

#[derive(Debug, thiserror::Error)]
pub enum DecisionModelLoadError {
    #[error("model card could not be encoded: {0}")]
    Card(WeightsError),
    #[error("model card bytes do not match the verified attestation subject")]
    CardDigestMismatch,
    #[error("model card refuses the artifact binding: {0}")]
    Binding(WeightsError),
    #[error("decision-model artifact is invalid: {0:?}")]
    Artifact(DagError),
    #[error("decision-model artifact references atom {atom}, which no score source provides")]
    UnprovidedAtom { atom: usize },
    #[error("score source does not cover exactly the artifact's {atoms} atoms")]
    SourceCoverage { atoms: usize },
    #[error("work cap {cap} is below the schedule's {ops} ops")]
    WorkCapBelowSchedule { cap: u32, ops: u32 },
}

impl PredicateDagGuard {
    /// Pin a decision model. Every check runs here, so a guard that loads
    /// never refuses a call for a reason knowable at load:
    /// the card bytes match the attestation subject, the card binds the
    /// artifact digest, scopes and tools; the artifact decodes and validates;
    /// the source provides every referenced atom; and `work_cap` covers the
    /// schedule.
    pub fn load(
        card: &VerifiedModelCard,
        artifact: &[u8],
        source: Box<dyn ScoreSource>,
        binding: &DecisionModelBinding,
        work_cap: u32,
    ) -> Result<Self, DecisionModelLoadError> {
        let card_bytes = card
            .card
            .to_canonical_json()
            .map_err(DecisionModelLoadError::Card)?;
        let model_card_digest = sha256_hex(&card_bytes);
        if model_card_digest != hex_lower(&card.attestation.subject_digest_sha256) {
            return Err(DecisionModelLoadError::CardDigestMismatch);
        }
        let artifact_digest = weights_hash_of(artifact);
        evaluate_weights_binding(
            &card.card,
            &WeightsBindingRequest {
                loaded_weights_hash: &artifact_digest,
                requested_scopes: &binding.requested_scopes,
                requested_tools: &binding.requested_tools,
            },
        )
        .map_err(DecisionModelLoadError::Binding)?;

        let mut storage = HeapScheduleStorage::new();
        let thresholds = storage
            .decode(artifact)
            .map_err(DecisionModelLoadError::Artifact)?;
        let schedule = storage
            .schedule()
            .map_err(DecisionModelLoadError::Artifact)?;
        let provided = source.provided_atoms();
        if let Some(atom) = first_unprovided(schedule.referenced_atoms(), &provided) {
            return Err(DecisionModelLoadError::UnprovidedAtom { atom });
        }
        if provided != atom_mask(schedule.atom_count()) {
            return Err(DecisionModelLoadError::SourceCoverage {
                atoms: schedule.atom_count(),
            });
        }
        let ops = schedule.op_count();
        if work_cap < ops.max(1) {
            return Err(DecisionModelLoadError::WorkCapBelowSchedule { cap: work_cap, ops });
        }
        Ok(Self {
            model_card_digest,
            artifact_digest,
            storage,
            thresholds,
            source,
            op_count: ops,
            work_cap,
        })
    }
}

fn first_unprovided(referenced: &[u64; ATOM_WORDS], provided: &[u64; ATOM_WORDS]) -> Option<usize> {
    referenced
        .iter()
        .zip(provided)
        .enumerate()
        .find_map(|(word, (referenced, provided))| {
            let missing = referenced & !provided;
            (missing != 0).then(|| {
                let bit = usize::try_from(missing.trailing_zeros()).unwrap_or(usize::MAX);
                word.saturating_mul(64).saturating_add(bit)
            })
        })
}

fn atom_mask(atoms: usize) -> [u64; ATOM_WORDS] {
    let mut words = [0u64; ATOM_WORDS];
    for atom in 0..atoms {
        if let Some(word) = words.get_mut(atom / 64) {
            *word |= 1u64 << (atom % 64);
        }
    }
    words
}

fn hex_lower(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
