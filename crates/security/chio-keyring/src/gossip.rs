use crate::{
    CheckpointEquivocationEvidence, CheckpointGossip, KeyLogPolicy, KeyLogSyncResponse,
    KeyringError, Result, SignedKeyLogCheckpoint, CHECKPOINT_EQUIVOCATION_SCHEMA,
    KEY_LOG_CHECKPOINT_SCHEMA,
};

pub(crate) fn ensure_local_checkpoint(
    checkpoint: &SignedKeyLogCheckpoint,
    policy: &KeyLogPolicy,
) -> Result<()> {
    if checkpoint.body.log_id != policy.log_id {
        return Err(KeyringError::IdentityMismatch);
    }
    Ok(())
}

pub(crate) fn ensure_local_sync(
    response: &KeyLogSyncResponse,
    policy: &KeyLogPolicy,
) -> Result<()> {
    if response
        .checkpoints
        .iter()
        .any(|checkpoint| checkpoint.body.log_id != policy.log_id)
        || response
            .event_envelopes
            .iter()
            .any(|event| event.body.log_id != policy.log_id)
        || response
            .activation_commits
            .iter()
            .any(|commit| commit.body.log_id != policy.log_id)
    {
        return Err(KeyringError::IdentityMismatch);
    }
    Ok(())
}

fn verify_checkpoint_evidence(
    checkpoint: &SignedKeyLogCheckpoint,
    policy: &KeyLogPolicy,
) -> Result<()> {
    if checkpoint.body.schema != KEY_LOG_CHECKPOINT_SCHEMA {
        return Err(KeyringError::UnsupportedSchema(
            checkpoint.body.schema.clone(),
        ));
    }
    checkpoint.verify_operator(&policy.operator_key)
}

/// Foreign signed rows remain in the durable archive. Authenticate every row
/// before using its signed namespace to select the configured log's live view.
pub(crate) fn scoped_gossip(
    observations: Vec<CheckpointGossip>,
    policy: &KeyLogPolicy,
    now: u64,
) -> Result<Vec<CheckpointGossip>> {
    let mut local = Vec::new();
    for gossip in observations {
        verify_checkpoint_evidence(&gossip.checkpoint, policy)?;
        let key = policy
            .witness_keys
            .get(&gossip.witness_signature.witness_id)
            .ok_or(KeyringError::InvalidSignature)?;
        gossip.witness_signature.verify(&gossip.checkpoint, key)?;
        if gossip.checkpoint.body.log_id == policy.log_id {
            policy.validate_checkpoint_time(gossip.checkpoint.body.issued_at, now)?;
            local.push(gossip);
        }
    }
    Ok(local)
}

pub(crate) fn scoped_conflicts(
    conflicts: Vec<CheckpointEquivocationEvidence>,
    policy: &KeyLogPolicy,
) -> Result<Vec<CheckpointEquivocationEvidence>> {
    let mut local = Vec::new();
    for conflict in conflicts {
        if conflict.schema != CHECKPOINT_EQUIVOCATION_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(conflict.schema));
        }
        verify_checkpoint_evidence(&conflict.first, policy)?;
        verify_checkpoint_evidence(&conflict.conflicting, policy)?;
        if conflict.first.body.log_id == policy.log_id
            && conflict.conflicting.body.log_id == policy.log_id
        {
            local.push(conflict);
        }
    }
    Ok(local)
}
