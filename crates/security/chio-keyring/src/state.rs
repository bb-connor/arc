use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::{Hash, PublicKey, SigningAlgorithm};
use serde::{Deserialize, Serialize};

use crate::{
    derive_key_id, AnchorId, ArtifactTimeEvidence, ArtifactTimeVerifier, AuthorityId, EventId,
    KeyId, KeyLogOperation, KeyringError, LogId, RecoveryAuthorizerId, RecoveryPolicyId, Result,
    SignedKeyActivationCommit, SignedKeyLogCheckpoint, SignedKeyLogEvent, TrustedClock, WitnessId,
    WitnessRosterId, MAX_RECOVERY_AUTHORIZATIONS, MAX_WITNESS_SIGNATURES,
};

#[derive(Clone, Debug)]
pub struct KeyLogPolicy {
    pub(crate) log_id: LogId,
    pub(crate) authority_id: AuthorityId,
    pub(crate) bootstrap_key: PublicKey,
    pub(crate) operator_key: PublicKey,
    pub(crate) witness_roster_id: WitnessRosterId,
    pub(crate) witness_keys: BTreeMap<WitnessId, PublicKey>,
    pub(crate) recovery_policy_id: RecoveryPolicyId,
    pub(crate) recovery_keys: BTreeMap<RecoveryAuthorizerId, PublicKey>,
    pub(crate) recovery_threshold: usize,
    pub(crate) artifact_time_keys: BTreeMap<AnchorId, PublicKey>,
    pub(crate) auditor_keys: BTreeMap<String, PublicKey>,
    pub(crate) independent_role_key_ids: BTreeSet<KeyId>,
    pub(crate) max_checkpoint_future_skew: u64,
}

#[derive(Clone, Debug)]
pub struct KeyLogPolicyConfig {
    pub log_id: LogId,
    pub authority_id: AuthorityId,
    pub bootstrap_key: PublicKey,
    pub operator_key: PublicKey,
    pub witness_roster_id: WitnessRosterId,
    pub witness_keys: BTreeMap<WitnessId, PublicKey>,
    pub recovery_policy_id: RecoveryPolicyId,
    pub recovery_keys: BTreeMap<RecoveryAuthorizerId, PublicKey>,
    pub recovery_threshold: usize,
    pub max_checkpoint_future_skew: u64,
}

impl KeyLogPolicy {
    pub fn new(config: KeyLogPolicyConfig) -> Result<Self> {
        let KeyLogPolicyConfig {
            log_id,
            authority_id,
            bootstrap_key,
            operator_key,
            witness_roster_id,
            witness_keys,
            recovery_policy_id,
            recovery_keys,
            recovery_threshold,
            max_checkpoint_future_skew,
        } = config;
        if witness_keys.is_empty() || witness_keys.len() > MAX_WITNESS_SIGNATURES {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        if recovery_keys.len() > MAX_RECOVERY_AUTHORIZATIONS
            || (recovery_keys.is_empty() && recovery_threshold != 0)
            || (!recovery_keys.is_empty()
                && (recovery_threshold == 0 || recovery_threshold > recovery_keys.len()))
        {
            return Err(KeyringError::InvalidAuthorizationSet);
        }
        let mut role_key_ids = BTreeSet::new();
        for key in std::iter::once(&bootstrap_key)
            .chain(std::iter::once(&operator_key))
            .chain(witness_keys.values())
            .chain(recovery_keys.values())
        {
            if !role_key_ids.insert(derive_key_id(key.algorithm(), key)?) {
                return Err(KeyringError::DuplicateIdentifier);
            }
        }
        Ok(Self {
            log_id,
            authority_id,
            bootstrap_key,
            operator_key,
            witness_roster_id,
            witness_keys,
            recovery_policy_id,
            recovery_keys,
            recovery_threshold,
            artifact_time_keys: BTreeMap::new(),
            auditor_keys: BTreeMap::new(),
            independent_role_key_ids: role_key_ids,
            max_checkpoint_future_skew,
        })
    }

    #[must_use]
    pub fn log_id(&self) -> &LogId {
        &self.log_id
    }

    #[must_use]
    pub fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }

    #[must_use]
    pub fn operator_public_key(&self) -> &PublicKey {
        &self.operator_key
    }

    pub fn witness_threshold(&self) -> Result<usize> {
        self.witness_keys
            .len()
            .checked_div(2)
            .and_then(|half| half.checked_add(1))
            .ok_or(KeyringError::NumericRange)
    }

    #[must_use]
    pub fn witness_public_keys(&self) -> &BTreeMap<WitnessId, PublicKey> {
        &self.witness_keys
    }

    #[must_use]
    pub fn witness_public_key(&self, witness_id: &WitnessId) -> Option<&PublicKey> {
        self.witness_keys.get(witness_id)
    }

    #[must_use]
    pub fn witness_roster_id(&self) -> &WitnessRosterId {
        &self.witness_roster_id
    }

    pub fn witness_roster_binding(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Binding<'a> {
            schema: &'static str,
            log_id: &'a LogId,
            authority_id: &'a AuthorityId,
            witness_roster_id: &'a WitnessRosterId,
            witness_threshold: usize,
            witness_keys: &'a BTreeMap<WitnessId, PublicKey>,
        }
        let canonical = chio_core_types::canonical_json_bytes(&Binding {
            schema: "chio.key-log.witness-roster-binding.v1",
            log_id: &self.log_id,
            authority_id: &self.authority_id,
            witness_roster_id: &self.witness_roster_id,
            witness_threshold: self.witness_threshold()?,
            witness_keys: &self.witness_keys,
        })?;
        Ok(chio_core_types::sha256(&canonical))
    }

    pub fn recovery_policy_binding(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Binding<'a> {
            schema: &'static str,
            log_id: &'a LogId,
            authority_id: &'a AuthorityId,
            recovery_policy_id: &'a RecoveryPolicyId,
            recovery_threshold: usize,
            recovery_keys: &'a BTreeMap<RecoveryAuthorizerId, PublicKey>,
        }
        let canonical = chio_core_types::canonical_json_bytes(&Binding {
            schema: "chio.key-log.recovery-policy-binding.v1",
            log_id: &self.log_id,
            authority_id: &self.authority_id,
            recovery_policy_id: &self.recovery_policy_id,
            recovery_threshold: self.recovery_threshold,
            recovery_keys: &self.recovery_keys,
        })?;
        Ok(chio_core_types::sha256(&canonical))
    }

    pub fn configuration_binding(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Binding<'a> {
            schema: &'static str,
            log_id: &'a LogId,
            authority_id: &'a AuthorityId,
            bootstrap_key: &'a PublicKey,
            operator_key: &'a PublicKey,
            witness_roster_binding: Hash,
            recovery_policy_binding: Hash,
            artifact_time_policy_binding: Hash,
            auditor_policy_binding: Hash,
            max_checkpoint_future_skew: u64,
        }
        let canonical = chio_core_types::canonical_json_bytes(&Binding {
            schema: "chio.key-log.configuration-binding.v1",
            log_id: &self.log_id,
            authority_id: &self.authority_id,
            bootstrap_key: &self.bootstrap_key,
            operator_key: &self.operator_key,
            witness_roster_binding: self.witness_roster_binding()?,
            recovery_policy_binding: self.recovery_policy_binding()?,
            artifact_time_policy_binding: self.artifact_time_policy_binding()?,
            auditor_policy_binding: self.auditor_policy_binding()?,
            max_checkpoint_future_skew: self.max_checkpoint_future_skew,
        })?;
        Ok(chio_core_types::sha256(&canonical))
    }

    pub fn with_artifact_time_roots(
        mut self,
        artifact_time_keys: BTreeMap<AnchorId, PublicKey>,
    ) -> Result<Self> {
        if artifact_time_keys.is_empty() || artifact_time_keys.len() > MAX_WITNESS_SIGNATURES {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        for key in artifact_time_keys.values() {
            let key_id = derive_key_id(key.algorithm(), key)?;
            if !self.independent_role_key_ids.insert(key_id) {
                return Err(KeyringError::DuplicateIdentifier);
            }
        }
        self.artifact_time_keys = artifact_time_keys;
        Ok(self)
    }

    pub fn with_auditor_roots(mut self, auditor_keys: BTreeMap<String, PublicKey>) -> Result<Self> {
        if auditor_keys.len() != 2 || !self.auditor_keys.is_empty() {
            return Err(KeyringError::StateInvariant(
                "production key-log policy requires exactly two auditor trust roots",
            ));
        }
        for (monitor_id, key) in &auditor_keys {
            crate::ipc::validate_service_identifier(monitor_id, "audit monitor identifier")?;
            let key_id = derive_key_id(key.algorithm(), key)?;
            if !self.independent_role_key_ids.insert(key_id) {
                return Err(KeyringError::DuplicateIdentifier);
            }
        }
        self.auditor_keys = auditor_keys;
        Ok(self)
    }

    #[must_use]
    pub fn auditor_public_keys(&self) -> &BTreeMap<String, PublicKey> {
        &self.auditor_keys
    }

    #[must_use]
    pub fn auditor_public_key(&self, monitor_id: &str) -> Option<&PublicKey> {
        self.auditor_keys.get(monitor_id)
    }

    pub fn auditor_policy_binding(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Binding<'a> {
            schema: &'static str,
            log_id: &'a LogId,
            authority_id: &'a AuthorityId,
            auditor_public_keys: &'a BTreeMap<String, PublicKey>,
        }
        let canonical = chio_core_types::canonical_json_bytes(&Binding {
            schema: "chio.key-log.auditor-policy-binding.v1",
            log_id: &self.log_id,
            authority_id: &self.authority_id,
            auditor_public_keys: &self.auditor_keys,
        })?;
        Ok(chio_core_types::sha256(&canonical))
    }

    pub fn artifact_time_verifier(
        &self,
        clock: std::sync::Arc<dyn TrustedClock>,
        max_future_skew: u64,
    ) -> Result<ArtifactTimeVerifier> {
        ArtifactTimeVerifier::new(
            self.artifact_time_keys.clone(),
            self.artifact_time_policy_binding()?,
            clock,
            max_future_skew,
        )
    }

    pub(crate) fn artifact_time_key(&self, anchor_id: &AnchorId) -> Option<&PublicKey> {
        self.artifact_time_keys.get(anchor_id)
    }

    pub fn validate_checkpoint_time(&self, issued_at: u64, now: u64) -> Result<()> {
        let latest = now
            .checked_add(self.max_checkpoint_future_skew)
            .ok_or(KeyringError::NumericRange)?;
        if issued_at > latest {
            return Err(KeyringError::InvalidTimeOrdering);
        }
        Ok(())
    }

    pub(crate) fn artifact_time_policy_binding(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Binding<'a> {
            schema: &'static str,
            log_id: &'a LogId,
            authority_id: &'a AuthorityId,
            trust_roots: &'a BTreeMap<AnchorId, PublicKey>,
        }
        let canonical = chio_core_types::canonical_json_bytes(&Binding {
            schema: "chio.key-log.artifact-time-policy.v1",
            log_id: &self.log_id,
            authority_id: &self.authority_id,
            trust_roots: &self.artifact_time_keys,
        })?;
        Ok(chio_core_types::sha256(&canonical))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Pending,
    VerificationOnly,
    Retired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    pub key_id: KeyId,
    pub algorithm: SigningAlgorithm,
    pub public_key: PublicKey,
    pub status: KeyStatus,
    pub activated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_until: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedActivation {
    committed_at: u64,
    signing_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessedActivationSet {
    activations: BTreeMap<EventId, VerifiedActivation>,
    tree_size: u64,
    final_root: Option<Hash>,
    last_event_hash: Option<Hash>,
}

impl WitnessedActivationSet {
    #[must_use]
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    #[must_use]
    pub fn activation_count(&self) -> usize {
        self.activations.len()
    }

    pub fn verify_complete(
        events: &[SignedKeyLogEvent],
        checkpoints: &[SignedKeyLogCheckpoint],
        activation_commits: &[SignedKeyActivationCommit],
        policy: &KeyLogPolicy,
    ) -> Result<Self> {
        if events.len() != checkpoints.len() || activation_commits.len() > events.len() {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        if events.is_empty() {
            if activation_commits.is_empty() {
                return Ok(Self {
                    activations: BTreeMap::new(),
                    tree_size: 0,
                    final_root: None,
                    last_event_hash: None,
                });
            }
            return Err(KeyringError::InvalidWitnessActivation);
        }

        let mut leaves = Vec::with_capacity(events.len());
        let mut previous_event_hash = None;
        let mut previous_event_time = None;
        for (index, event) in events.iter().enumerate() {
            let sequence = u64::try_from(index).map_err(|_| KeyringError::NumericRange)?;
            event.validate_common(
                sequence,
                previous_event_hash.as_ref(),
                &policy.log_id,
                &policy.authority_id,
                previous_event_time,
            )?;
            leaves.push(event.canonical_envelope_bytes()?);
            previous_event_hash = Some(event.envelope_hash()?);
            previous_event_time = Some(event.body.issued_at);
        }

        let mut previous_checkpoint_hash = None;
        let mut previous_checkpoint_time = None;
        let mut checkpoint_indices = BTreeMap::new();
        for (index, checkpoint) in checkpoints.iter().enumerate() {
            let sequence = u64::try_from(index).map_err(|_| KeyringError::NumericRange)?;
            let tree_size = sequence.checked_add(1).ok_or(KeyringError::NumericRange)?;
            let root = chio_core_types::MerkleTree::from_leaves(&leaves[..=index])?.root();
            checkpoint.validate(crate::KeyLogCheckpointExpectation {
                log_id: &policy.log_id,
                sequence,
                tree_size,
                root: &root,
                previous_checkpoint_hash: previous_checkpoint_hash.as_ref(),
                last_issued_at: previous_checkpoint_time,
            })?;
            checkpoint.verify_operator(&policy.operator_key)?;
            if checkpoint.body.issued_at < events[index].body.issued_at {
                return Err(KeyringError::InvalidTimeOrdering);
            }
            let hash = checkpoint.checkpoint_hash()?;
            if checkpoint_indices.insert(hash.to_string(), index).is_some() {
                return Err(KeyringError::DuplicateIdentifier);
            }
            previous_checkpoint_hash = Some(hash);
            previous_checkpoint_time = Some(checkpoint.body.issued_at);
        }

        let mut activations = BTreeMap::new();
        let mut previous_activation_index = None;
        let mut previous_activation_time = None;
        for (position, commit) in activation_commits.iter().enumerate() {
            commit.verify_operator(&policy.operator_key)?;
            if commit.body.log_id != policy.log_id {
                return Err(KeyringError::IdentityMismatch);
            }
            let expected_epoch = u64::try_from(position)
                .map_err(|_| KeyringError::NumericRange)?
                .checked_add(1)
                .ok_or(KeyringError::NumericRange)?;
            if commit.body.signing_epoch != expected_epoch {
                return Err(KeyringError::InvalidWitnessActivation);
            }
            let checkpoint_index = *checkpoint_indices
                .get(&commit.body.checkpoint_hash.to_string())
                .ok_or(KeyringError::InvalidWitnessActivation)?;
            if previous_activation_index.is_some_and(|previous| checkpoint_index <= previous) {
                return Err(KeyringError::InvalidWitnessActivation);
            }
            let event = &events[checkpoint_index];
            if commit.body.event_id != event.body.event_id
                || !matches!(
                    event.body.operation,
                    KeyLogOperation::Rotate { .. } | KeyLogOperation::Recover { .. }
                )
            {
                return Err(KeyringError::InvalidWitnessActivation);
            }
            let checkpoint = &checkpoints[checkpoint_index];
            let mut witnessed_checkpoint = checkpoint.clone();
            witnessed_checkpoint.witness_signatures = commit.body.witness_signatures.clone();
            witnessed_checkpoint.verify_witnesses(&policy.witness_keys)?;
            if commit.body.checkpoint_body_hash != checkpoint.checkpoint_body_hash()?
                || commit.body.checkpoint_sequence != checkpoint.body.checkpoint_sequence
                || commit.body.tree_size != checkpoint.body.tree_size
                || commit.body.root_hash != checkpoint.body.root_hash
                || commit.body.event_leaf_hash != event.merkle_leaf_hash()?
                || commit.body.witness_set_hash != witnessed_checkpoint.witness_set_hash()?
            {
                return Err(KeyringError::InvalidWitnessActivation);
            }
            if commit.body.committed_at < checkpoint.body.issued_at
                || previous_activation_time
                    .is_some_and(|previous| commit.body.committed_at < previous)
            {
                return Err(KeyringError::InvalidTimeOrdering);
            }
            if activations
                .insert(
                    event.body.event_id.clone(),
                    VerifiedActivation {
                        committed_at: commit.body.committed_at,
                        signing_epoch: commit.body.signing_epoch,
                    },
                )
                .is_some()
            {
                return Err(KeyringError::DuplicateIdentifier);
            }
            previous_activation_index = Some(checkpoint_index);
            previous_activation_time = Some(commit.body.committed_at);
        }

        let final_root = chio_core_types::MerkleTree::from_leaves(&leaves)?.root();
        Ok(Self {
            activations,
            tree_size: u64::try_from(events.len()).map_err(|_| KeyringError::NumericRange)?,
            final_root: Some(final_root),
            last_event_hash: previous_event_hash,
        })
    }

    pub(crate) fn get(&self, event_id: &EventId) -> Option<&VerifiedActivation> {
        self.activations.get(event_id)
    }

    fn verify_event_binding(&self, events: &[&SignedKeyLogEvent]) -> Result<()> {
        if u64::try_from(events.len()).map_err(|_| KeyringError::NumericRange)? != self.tree_size {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        if events.is_empty() {
            if self.final_root.is_none() && self.last_event_hash.is_none() {
                return Ok(());
            }
            return Err(KeyringError::InvalidWitnessActivation);
        }
        let leaves = events
            .iter()
            .map(|event| event.canonical_envelope_bytes())
            .collect::<Result<Vec<_>>>()?;
        let final_root = chio_core_types::MerkleTree::from_leaves(&leaves)?.root();
        let last_event_hash = events
            .last()
            .ok_or(KeyringError::InvalidWitnessActivation)?
            .envelope_hash()?;
        if self.final_root != Some(final_root) || self.last_event_hash != Some(last_event_hash) {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLogState {
    keys: BTreeMap<KeyId, KeyRecord>,
    active_key_id: Option<KeyId>,
    pending_key_id: Option<KeyId>,
    pending_event_id: Option<EventId>,
    signing_epoch: u64,
    artifact_time_policy_binding: Hash,
}

impl KeyLogState {
    pub fn replay<'a>(
        events: impl IntoIterator<Item = &'a SignedKeyLogEvent>,
        witnessed_activations: &WitnessedActivationSet,
        policy: &KeyLogPolicy,
    ) -> Result<Self> {
        let events = events.into_iter().collect::<Vec<_>>();
        witnessed_activations.verify_event_binding(&events)?;
        let mut state = Self {
            keys: BTreeMap::new(),
            active_key_id: None,
            pending_key_id: None,
            pending_event_id: None,
            signing_epoch: 0,
            artifact_time_policy_binding: policy.artifact_time_policy_binding()?,
        };
        let mut seen_event_ids = BTreeSet::new();
        let mut introduced_key_ids = BTreeSet::new();
        let mut used_activations = BTreeSet::new();
        let mut previous_hash = None;
        let mut last_issued_at = None;

        for (index, event) in events.into_iter().enumerate() {
            let expected_sequence = u64::try_from(index).map_err(|_| KeyringError::NumericRange)?;
            event.validate_common(
                expected_sequence,
                previous_hash.as_ref(),
                &policy.log_id,
                &policy.authority_id,
                last_issued_at,
            )?;
            if !seen_event_ids.insert(event.body.event_id.clone()) {
                return Err(KeyringError::DuplicateIdentifier);
            }
            if policy.independent_role_key_ids.contains(&event.body.key_id) {
                return Err(KeyringError::StateInvariant(
                    "lifecycle key overlaps an independent trust role",
                ));
            }
            match &event.body.operation {
                KeyLogOperation::Genesis => {
                    if index != 0 || state.active_key_id.is_some() {
                        return Err(KeyringError::StateInvariant("genesis must be first"));
                    }
                    event.verify_genesis(&policy.bootstrap_key)?;
                    introduce_key(&mut introduced_key_ids, event.body.key_id)?;
                    state.keys.insert(
                        event.body.key_id,
                        KeyRecord {
                            key_id: event.body.key_id,
                            algorithm: event.body.algorithm,
                            public_key: event.body.public_key.clone(),
                            status: KeyStatus::Active,
                            activated_at: event.body.effective_at,
                            deactivated_at: None,
                            verify_until: None,
                        },
                    );
                    state.active_key_id = Some(event.body.key_id);
                }
                KeyLogOperation::Rotate {
                    previous_key_id,
                    witness_roster_id,
                    witness_roster_binding,
                } => {
                    ensure_no_pending(&state)?;
                    let active = state.active_signing_key()?;
                    if active.key_id != *previous_key_id
                        || witness_roster_id != &policy.witness_roster_id
                        || *witness_roster_binding != policy.witness_roster_binding()?
                    {
                        return Err(KeyringError::StateInvariant(
                            "rotation does not name active key and configured roster",
                        ));
                    }
                    event.verify_rotation(&active.public_key)?;
                    introduce_key(&mut introduced_key_ids, event.body.key_id)?;
                    state.insert_pending(event)?;
                    if let Some(activation) = witnessed_activations.get(&event.body.event_id) {
                        state.apply_activation(event, activation, false)?;
                        used_activations.insert(event.body.event_id.clone());
                    }
                }
                KeyLogOperation::Recover {
                    previous_key_id,
                    witness_roster_id,
                    witness_roster_binding,
                    recovery_policy_id,
                    recovery_policy_binding,
                } => {
                    if witness_roster_id != &policy.witness_roster_id
                        || *witness_roster_binding != policy.witness_roster_binding()?
                        || recovery_policy_id != &policy.recovery_policy_id
                        || *recovery_policy_binding != policy.recovery_policy_binding()?
                        || state.active_signing_key()?.key_id != *previous_key_id
                    {
                        return Err(KeyringError::StateInvariant(
                            "recovery policy, roster, or prior key mismatch",
                        ));
                    }
                    event.verify_recovery(&policy.recovery_keys, policy.recovery_threshold)?;
                    introduce_key(&mut introduced_key_ids, event.body.key_id)?;
                    if let Some(pending_key_id) = state.pending_key_id.take() {
                        let pending = state
                            .keys
                            .get_mut(&pending_key_id)
                            .ok_or(KeyringError::UnknownKey)?;
                        pending.status = KeyStatus::Revoked;
                        pending.deactivated_at = Some(event.body.issued_at);
                        state.pending_event_id = None;
                    }
                    state.insert_pending(event)?;
                    if let Some(activation) = witnessed_activations.get(&event.body.event_id) {
                        state.apply_activation(event, activation, true)?;
                        used_activations.insert(event.body.event_id.clone());
                    }
                }
                KeyLogOperation::AbortRotation {
                    previous_key_id,
                    recovery_policy_id,
                    recovery_policy_binding,
                } => {
                    let active = state.active_signing_key()?.clone();
                    let pending_key_id = state
                        .pending_key_id
                        .ok_or(KeyringError::StateInvariant("no pending rotation to abort"))?;
                    let pending = state
                        .keys
                        .get(&pending_key_id)
                        .ok_or(KeyringError::UnknownKey)?
                        .clone();
                    if *previous_key_id != active.key_id
                        || event.body.key_id != pending.key_id
                        || event.body.public_key != pending.public_key
                    {
                        return Err(KeyringError::StateInvariant(
                            "abort does not bind active and pending keys",
                        ));
                    }
                    if let Some(recovery_policy_id) = recovery_policy_id {
                        if recovery_policy_id != &policy.recovery_policy_id {
                            return Err(KeyringError::InvalidAuthorizationSet);
                        }
                        if *recovery_policy_binding != Some(policy.recovery_policy_binding()?) {
                            return Err(KeyringError::InvalidAuthorizationSet);
                        }
                        event.verify_recovery(&policy.recovery_keys, policy.recovery_threshold)?;
                    } else {
                        if recovery_policy_binding.is_some() {
                            return Err(KeyringError::InvalidAuthorizationSet);
                        }
                        event.verify_dual_key_authorization(
                            &active.public_key,
                            &pending.public_key,
                        )?;
                    }
                    let pending = state
                        .keys
                        .get_mut(&pending_key_id)
                        .ok_or(KeyringError::UnknownKey)?;
                    pending.status = KeyStatus::Retired;
                    pending.deactivated_at = Some(event.body.effective_at);
                    state.pending_key_id = None;
                    state.pending_event_id = None;
                }
                KeyLogOperation::Retire | KeyLogOperation::Revoke => {
                    ensure_no_pending(&state)?;
                    let active = state.active_signing_key()?.clone();
                    if event.body.key_id == active.key_id {
                        return Err(KeyringError::StateInvariant(
                            "active key cannot be retired or revoked without recovery",
                        ));
                    }
                    event.verify_active_key_authorization(&active.public_key)?;
                    let target = state
                        .keys
                        .get_mut(&event.body.key_id)
                        .ok_or(KeyringError::UnknownKey)?;
                    if target.public_key != event.body.public_key
                        || target.algorithm != event.body.algorithm
                    {
                        return Err(KeyringError::KeyIdMismatch);
                    }
                    target.status = if matches!(event.body.operation, KeyLogOperation::Retire) {
                        KeyStatus::Retired
                    } else {
                        KeyStatus::Revoked
                    };
                    target.deactivated_at = Some(event.body.effective_at);
                }
            }

            previous_hash = Some(event.envelope_hash()?);
            last_issued_at = Some(event.body.issued_at);
        }

        if state.active_key_id.is_none()
            || state
                .keys
                .values()
                .filter(|record| record.status == KeyStatus::Active)
                .count()
                != 1
        {
            return Err(KeyringError::StateInvariant(
                "replay must end with exactly one active key",
            ));
        }
        if used_activations.len() != witnessed_activations.activations.len() {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        Ok(state)
    }

    pub fn active_signing_key(&self) -> Result<&KeyRecord> {
        let key_id = self
            .active_key_id
            .ok_or(KeyringError::StateInvariant("active key is absent"))?;
        let record = self.keys.get(&key_id).ok_or(KeyringError::UnknownKey)?;
        if record.status != KeyStatus::Active {
            return Err(KeyringError::StateInvariant(
                "active selector names a non-active key",
            ));
        }
        Ok(record)
    }

    #[must_use]
    pub fn pending_rotation_key(&self) -> Option<&KeyRecord> {
        self.pending_key_id
            .and_then(|key_id| self.keys.get(&key_id))
    }

    pub fn key(&self, key_id: &KeyId) -> Result<&KeyRecord> {
        self.keys.get(key_id).ok_or(KeyringError::UnknownKey)
    }

    #[must_use]
    pub fn signing_epoch(&self) -> u64 {
        self.signing_epoch
    }

    /// Keys whose historical verification window is established by the
    /// witnessed activation log. Revoked, retired, and merely pending keys are
    /// deliberately excluded.
    #[must_use]
    pub fn witnessed_verification_keys(&self) -> Vec<KeyRecord> {
        self.keys
            .values()
            .filter(|record| {
                matches!(
                    record.status,
                    KeyStatus::Active | KeyStatus::VerificationOnly
                )
            })
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn pending_event_id(&self) -> Option<&EventId> {
        self.pending_event_id.as_ref()
    }

    pub fn verification_key_for_artifact(
        &self,
        key_id: &KeyId,
        artifact_hash: &Hash,
        time_evidence: &ArtifactTimeEvidence,
    ) -> Result<&KeyRecord> {
        if time_evidence.artifact_hash() != *artifact_hash {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        if time_evidence.policy_binding() != self.artifact_time_policy_binding {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        let record = self.key(key_id)?;
        let valid = match record.status {
            KeyStatus::Active => time_evidence.anchored_at() >= record.activated_at,
            KeyStatus::VerificationOnly => {
                time_evidence.anchored_at() >= record.activated_at
                    && record
                        .deactivated_at
                        .is_some_and(|deactivated| time_evidence.anchored_at() < deactivated)
                    && record
                        .verify_until
                        .is_some_and(|until| time_evidence.anchored_at() <= until)
            }
            KeyStatus::Pending | KeyStatus::Retired | KeyStatus::Revoked => false,
        };
        if valid {
            Ok(record)
        } else {
            Err(KeyringError::InvalidArtifactTimeEvidence)
        }
    }

    fn insert_pending(&mut self, event: &SignedKeyLogEvent) -> Result<()> {
        if self.keys.contains_key(&event.body.key_id) {
            return Err(KeyringError::DuplicateIdentifier);
        }
        self.keys.insert(
            event.body.key_id,
            KeyRecord {
                key_id: event.body.key_id,
                algorithm: event.body.algorithm,
                public_key: event.body.public_key.clone(),
                status: KeyStatus::Pending,
                activated_at: 0,
                deactivated_at: None,
                verify_until: None,
            },
        );
        self.pending_key_id = Some(event.body.key_id);
        self.pending_event_id = Some(event.body.event_id.clone());
        Ok(())
    }

    fn apply_activation(
        &mut self,
        event: &SignedKeyLogEvent,
        activation: &VerifiedActivation,
        recovery: bool,
    ) -> Result<()> {
        let next_epoch = self
            .signing_epoch
            .checked_add(1)
            .ok_or(KeyringError::NumericRange)?;
        if activation.signing_epoch != next_epoch {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        let activation_time = activation.committed_at;
        let old_key_id = self
            .active_key_id
            .ok_or(KeyringError::StateInvariant("active key is absent"))?;
        let old = self
            .keys
            .get_mut(&old_key_id)
            .ok_or(KeyringError::UnknownKey)?;
        old.status = if recovery {
            KeyStatus::Revoked
        } else {
            KeyStatus::VerificationOnly
        };
        old.deactivated_at = Some(activation_time);
        old.verify_until = if recovery {
            None
        } else {
            event.body.verify_until
        };

        let pending = self
            .keys
            .get_mut(&event.body.key_id)
            .ok_or(KeyringError::UnknownKey)?;
        if pending.status != KeyStatus::Pending {
            return Err(KeyringError::StateInvariant(
                "activation target is not pending",
            ));
        }
        pending.status = KeyStatus::Active;
        pending.activated_at = activation_time;
        self.active_key_id = Some(event.body.key_id);
        self.pending_key_id = None;
        self.pending_event_id = None;
        self.signing_epoch = next_epoch;
        Ok(())
    }
}

fn introduce_key(introduced: &mut BTreeSet<KeyId>, key_id: KeyId) -> Result<()> {
    if !introduced.insert(key_id) {
        return Err(KeyringError::DuplicateIdentifier);
    }
    Ok(())
}

fn ensure_no_pending(state: &KeyLogState) -> Result<()> {
    if state.pending_key_id.is_some() || state.pending_event_id.is_some() {
        return Err(KeyringError::StateInvariant(
            "pending rotation blocks this transition",
        ));
    }
    Ok(())
}
