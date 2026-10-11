use chio_core_types::merkle::MerkleConsistencyProof;
use chio_core_types::Hash;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{
    KeyLogPolicy, KeyLogState, KeyringError, Result, SignedKeyActivationCommit,
    SignedKeyLogCheckpoint, SignedKeyLogEvent, WitnessedActivationSet,
};

pub const MAX_SYNC_ITEMS: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogPin {
    pub checkpoint_sequence: u64,
    pub tree_size: u64,
    pub checkpoint_hash: Hash,
    pub root_hash: Hash,
    pub signing_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogSyncResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_checkpoint_hash: Option<Hash>,
    #[serde(deserialize_with = "deserialize_bounded_sync_vec")]
    pub checkpoints: Vec<SignedKeyLogCheckpoint>,
    #[serde(deserialize_with = "deserialize_bounded_sync_vec")]
    pub event_envelopes: Vec<SignedKeyLogEvent>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_nonempty_bounded_sync_vec"
    )]
    pub activation_commits: Vec<SignedKeyActivationCommit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_proof: Option<MerkleConsistencyProof>,
}

fn deserialize_bounded_sync_vec<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct SyncVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T> Visitor<'de> for SyncVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 4096 synchronization records")
        }

        fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|size| size > MAX_SYNC_ITEMS)
            {
                return Err(serde::de::Error::custom(
                    "synchronization record count exceeds 4096",
                ));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_SYNC_ITEMS));
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX_SYNC_ITEMS {
                    return Err(serde::de::Error::custom(
                        "synchronization record count exceeds 4096",
                    ));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(SyncVisitor(std::marker::PhantomData))
}

fn deserialize_nonempty_bounded_sync_vec<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let values = deserialize_bounded_sync_vec(deserializer)?;
    if values.is_empty() {
        return Err(serde::de::Error::custom(
            "activation_commits must contain at least one record when present",
        ));
    }
    Ok(values)
}

impl KeyLogSyncResponse {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let response: Self = crate::from_bounded_json(bytes)?;
        response.validate_bounds()?;
        Ok(response)
    }

    pub fn validate_bounds(&self) -> Result<()> {
        if self.checkpoints.len() > MAX_SYNC_ITEMS
            || self.event_envelopes.len() > MAX_SYNC_ITEMS
            || self.activation_commits.len() > MAX_SYNC_ITEMS
        {
            return Err(KeyringError::Canonical(
                "key-log synchronization response exceeds item limit".to_string(),
            ));
        }
        if chio_core_types::canonical_json_bytes(self)?.len() > crate::MAX_CANONICAL_RECORD_BYTES {
            return Err(KeyringError::Canonical(
                "key-log synchronization response exceeds 1048576 bytes".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedKeyLog {
    pub events: Vec<SignedKeyLogEvent>,
    pub checkpoints: Vec<SignedKeyLogCheckpoint>,
    pub activation_commits: Vec<SignedKeyActivationCommit>,
    pub state: KeyLogState,
    pub pin: KeyLogPin,
}

struct RetainedKeyLog<'a> {
    events: &'a [SignedKeyLogEvent],
    checkpoints: &'a [SignedKeyLogCheckpoint],
    activation_commits: &'a [SignedKeyActivationCommit],
}

struct SyncVerification<'a> {
    retained: RetainedKeyLog<'a>,
    response: &'a KeyLogSyncResponse,
    policy: &'a KeyLogPolicy,
    now: u64,
    require_witness_quorum: bool,
    enforce_response_bounds: bool,
}

pub(crate) fn verify_sync_update(
    retained_events: &[SignedKeyLogEvent],
    retained_checkpoints: &[SignedKeyLogCheckpoint],
    retained_commits: &[SignedKeyActivationCommit],
    response: &KeyLogSyncResponse,
    policy: &KeyLogPolicy,
    now: u64,
    require_witness_quorum: bool,
) -> Result<VerifiedKeyLog> {
    verify_sync_update_inner(SyncVerification {
        retained: RetainedKeyLog {
            events: retained_events,
            checkpoints: retained_checkpoints,
            activation_commits: retained_commits,
        },
        response,
        policy,
        now,
        require_witness_quorum,
        enforce_response_bounds: true,
    })
}

pub(crate) fn verify_retained_history(
    events: &[SignedKeyLogEvent],
    checkpoints: &[SignedKeyLogCheckpoint],
    commits: &[SignedKeyActivationCommit],
    policy: &KeyLogPolicy,
    now: u64,
    require_witness_quorum: bool,
) -> Result<VerifiedKeyLog> {
    verify_sync_update_inner(SyncVerification {
        retained: RetainedKeyLog {
            events: &[],
            checkpoints: &[],
            activation_commits: &[],
        },
        response: &KeyLogSyncResponse {
            base_checkpoint_hash: None,
            checkpoints: checkpoints.to_vec(),
            event_envelopes: events.to_vec(),
            activation_commits: commits.to_vec(),
            consistency_proof: None,
        },
        policy,
        now,
        require_witness_quorum,
        enforce_response_bounds: false,
    })
}

fn verify_sync_update_inner(verification: SyncVerification<'_>) -> Result<VerifiedKeyLog> {
    let SyncVerification {
        retained:
            RetainedKeyLog {
                events: retained_events,
                checkpoints: retained_checkpoints,
                activation_commits: retained_commits,
            },
        response,
        policy,
        now,
        require_witness_quorum,
        enforce_response_bounds,
    } = verification;
    if enforce_response_bounds {
        response.validate_bounds()?;
    }
    if !synchronization_shape_is_valid(
        retained_events.len(),
        retained_checkpoints.len(),
        response.event_envelopes.len(),
        response.checkpoints.len(),
    ) {
        return Err(KeyringError::InvalidCheckpoint(
            "synchronization ranges are not contiguous",
        ));
    }

    match retained_checkpoints.last() {
        Some(base) => {
            if response.base_checkpoint_hash != Some(base.checkpoint_hash()?) {
                return Err(KeyringError::InvalidCheckpoint(
                    "synchronization base checkpoint mismatch",
                ));
            }
        }
        None => {
            if response.base_checkpoint_hash.is_some() || response.consistency_proof.is_some() {
                return Err(KeyringError::InvalidCheckpoint(
                    "genesis synchronization has an unexpected base",
                ));
            }
        }
    }

    let mut events = retained_events.to_vec();
    events.extend(response.event_envelopes.iter().cloned());
    let mut checkpoints = retained_checkpoints.to_vec();
    checkpoints.extend(response.checkpoints.iter().cloned());
    let mut activation_commits = retained_commits.to_vec();
    activation_commits.extend(response.activation_commits.iter().cloned());

    for checkpoint in &checkpoints {
        policy.validate_checkpoint_time(checkpoint.body.issued_at, now)?;
        if require_witness_quorum {
            checkpoint.verify_witnesses(&policy.witness_keys)?;
        } else {
            checkpoint.verify_witness_signatures(&policy.witness_keys)?;
        }
    }
    for activation in &activation_commits {
        policy.validate_checkpoint_time(activation.body.committed_at, now)?;
    }

    if let Some(base) = retained_checkpoints.last() {
        let candidate = checkpoints.last().ok_or(KeyringError::InvalidCheckpoint(
            "synchronization candidate is absent",
        ))?;
        if candidate.body.tree_size > base.body.tree_size {
            let proof =
                response
                    .consistency_proof
                    .as_ref()
                    .ok_or(KeyringError::InvalidCheckpoint(
                        "growing synchronization omitted consistency proof",
                    ))?;
            if proof.old_size
                != usize::try_from(base.body.tree_size).map_err(|_| KeyringError::NumericRange)?
                || proof.new_size
                    != usize::try_from(candidate.body.tree_size)
                        .map_err(|_| KeyringError::NumericRange)?
            {
                return Err(KeyringError::InvalidCheckpoint(
                    "consistency proof size mismatch",
                ));
            }
            proof.verify(&base.body.root_hash, &candidate.body.root_hash)?;
        } else if response.consistency_proof.is_some() {
            return Err(KeyringError::InvalidCheckpoint(
                "non-growing synchronization supplied consistency proof",
            ));
        }
    }

    let history = WitnessedActivationSet::verify_complete(
        &events,
        &checkpoints,
        &activation_commits,
        policy,
    )?;
    let state = KeyLogState::replay(events.iter(), &history, policy)?;
    let candidate = checkpoints.last().ok_or(KeyringError::InvalidCheckpoint(
        "synchronization candidate is absent",
    ))?;
    let pin = KeyLogPin {
        checkpoint_sequence: candidate.body.checkpoint_sequence,
        tree_size: candidate.body.tree_size,
        checkpoint_hash: candidate.checkpoint_hash()?,
        root_hash: candidate.body.root_hash,
        signing_epoch: state.signing_epoch(),
    };
    Ok(VerifiedKeyLog {
        events,
        checkpoints,
        activation_commits,
        state,
        pin,
    })
}

fn synchronization_shape_is_valid(
    retained_event_count: usize,
    retained_checkpoint_count: usize,
    response_event_count: usize,
    response_checkpoint_count: usize,
) -> bool {
    retained_event_count == retained_checkpoint_count
        && response_event_count == response_checkpoint_count
        && retained_event_count
            .checked_add(response_event_count)
            .is_some_and(|count| count > 0)
}

pub(crate) fn synchronization_page_end(start: usize, total: usize) -> Result<usize> {
    start
        .checked_add(MAX_SYNC_ITEMS)
        .ok_or(KeyringError::NumericRange)
        .map(|end| end.min(total))
}

#[cfg(test)]
mod tests {
    use super::{synchronization_page_end, synchronization_shape_is_valid, MAX_SYNC_ITEMS};

    #[test]
    fn synchronization_limit_applies_to_each_page_not_retained_history() -> crate::Result<()> {
        assert!(synchronization_shape_is_valid(
            MAX_SYNC_ITEMS,
            MAX_SYNC_ITEMS,
            1,
            1,
        ));
        assert_eq!(
            synchronization_page_end(0, MAX_SYNC_ITEMS + 1)?,
            MAX_SYNC_ITEMS,
        );
        assert_eq!(
            synchronization_page_end(MAX_SYNC_ITEMS, MAX_SYNC_ITEMS + 1)?,
            MAX_SYNC_ITEMS + 1,
        );
        Ok(())
    }

    #[test]
    fn synchronization_shape_rejects_mismatched_and_empty_ranges() {
        assert!(synchronization_shape_is_valid(2, 2, 1, 1));
        assert!(!synchronization_shape_is_valid(2, 2, 0, 1));
        assert!(!synchronization_shape_is_valid(2, 1, 1, 1));
        assert!(!synchronization_shape_is_valid(0, 0, 0, 0));
    }
}
