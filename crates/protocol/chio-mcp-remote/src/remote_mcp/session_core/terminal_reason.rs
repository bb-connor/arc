//! Typed terminal reasons and the signed terminal fence and tombstone pair.
use super::*;

/// Why a session became terminal. A `v3` terminal record carries it, so the
/// two subscription failures stay distinct from an ordinary close.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TerminalReason {
    Deleted,
    Expired,
    Closed,
    /// A standard subscription failed re-authorization before activation.
    SubscriptionNotRestored,
    /// A standard subscription lost its authority after activation.
    SubscriptionAuthorityLost,
}

impl TerminalReason {
    pub(super) fn state(self) -> RemoteSessionState {
        match self {
            Self::Deleted => RemoteSessionState::Deleted,
            Self::Expired => RemoteSessionState::Expired,
            Self::Closed | Self::SubscriptionNotRestored | Self::SubscriptionAuthorityLost => {
                RemoteSessionState::Closed
            }
        }
    }
}

#[derive(Serialize)]
struct RemoteSessionTombstoneIntegrityEnvelope<'a> {
    schema: &'static str,
    record: &'a RemoteSessionDiagnosticRecord,
    resume_generation: u64,
    terminal_epoch: u64,
    key_id: &'a str,
    key_version: u64,
}

#[derive(Serialize)]
struct RemoteSessionTerminalFenceIntegrityEnvelope<'a> {
    schema: &'static str,
    session_id: &'a str,
    terminal_at: u64,
    terminal_state: RemoteSessionState,
    terminal_reason: TerminalReason,
    resume_generation: u64,
    terminal_epoch: u64,
    key_id: &'a str,
    key_version: u64,
}

pub(super) fn sign_terminal_session_records(
    keyring: &RemoteSessionHmacKeyring,
    mut record: RemoteSessionDiagnosticRecord,
    reason: TerminalReason,
    resume_generation: u64,
    terminal_epoch: u64,
) -> Result<(RemoteSessionTombstoneRecord, RemoteSessionTerminalFence), CliError> {
    if resume_generation == 0 || terminal_epoch == 0 || terminal_epoch != resume_generation {
        return Err(CliError::cli_other_error(
            "remote MCP terminal persistence requires a nonzero matching generation and epoch"
                .to_string(),
        ));
    }
    if reason.state() != record.lifecycle.state {
        return Err(CliError::cli_other_error(format!(
            "terminal MCP session {} reason {reason:?} does not match state {}",
            record.session_id,
            record.lifecycle.state.as_str()
        )));
    }
    record.terminal_reason = Some(reason);
    let integrity = keyring.empty_tag_for_current();
    let mut tombstone = RemoteSessionTombstoneRecord {
        record,
        resume_generation,
        terminal_epoch,
        resume_integrity: integrity.clone(),
    };
    tombstone.resume_integrity.tag =
        compute_terminal_tombstone_integrity_tag(&keyring.current, &tombstone)?;
    let mut fence = RemoteSessionTerminalFence {
        session_id: tombstone.record.session_id.clone(),
        terminal_at: tombstone.record.terminal_at,
        terminal_state: tombstone.record.lifecycle.state,
        terminal_reason: reason,
        resume_generation,
        terminal_epoch,
        resume_integrity: integrity,
    };
    fence.resume_integrity.tag = compute_terminal_fence_integrity_tag(&keyring.current, &fence)?;
    Ok((tombstone, fence))
}

pub(super) fn compute_terminal_tombstone_integrity_tag(
    key: &RemoteSessionHmacKey,
    tombstone: &RemoteSessionTombstoneRecord,
) -> Result<String, CliError> {
    let envelope = RemoteSessionTombstoneIntegrityEnvelope {
        schema: "chio.remote-mcp.terminal-tombstone-integrity.v1",
        record: &tombstone.record,
        resume_generation: tombstone.resume_generation,
        terminal_epoch: tombstone.terminal_epoch,
        key_id: &tombstone.resume_integrity.key_id,
        key_version: tombstone.resume_integrity.key_version,
    };
    compute_remote_session_hmac(
        REMOTE_SESSION_TOMBSTONE_HMAC_LABEL,
        key.key.as_slice(),
        &envelope,
        "terminal MCP session tombstone",
    )
}

pub(super) fn compute_terminal_fence_integrity_tag(
    key: &RemoteSessionHmacKey,
    fence: &RemoteSessionTerminalFence,
) -> Result<String, CliError> {
    let envelope = RemoteSessionTerminalFenceIntegrityEnvelope {
        schema: "chio.remote-mcp.terminal-fence-integrity.v1",
        session_id: &fence.session_id,
        terminal_at: fence.terminal_at,
        terminal_state: fence.terminal_state,
        terminal_reason: fence.terminal_reason,
        resume_generation: fence.resume_generation,
        terminal_epoch: fence.terminal_epoch,
        key_id: &fence.resume_integrity.key_id,
        key_version: fence.resume_integrity.key_version,
    };
    compute_remote_session_hmac(
        REMOTE_SESSION_TERMINAL_FENCE_HMAC_LABEL,
        key.key.as_slice(),
        &envelope,
        "terminal MCP session generation fence",
    )
}

pub(super) fn validate_terminal_tombstone_integrity(
    keyring: &RemoteSessionHmacKeyring,
    tombstone: &RemoteSessionTombstoneRecord,
    now: u64,
) -> Result<(), CliError> {
    if tombstone.resume_generation == 0
        || tombstone.terminal_epoch == 0
        || tombstone.resume_generation != tombstone.terminal_epoch
        || !matches!(
            tombstone.record.lifecycle.state,
            RemoteSessionState::Deleted | RemoteSessionState::Expired | RemoteSessionState::Closed
        )
        || tombstone
            .record
            .terminal_reason
            .is_none_or(|reason| reason.state() != tombstone.record.lifecycle.state)
    {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} has an invalid terminal generation or state",
            tombstone.record.session_id
        )));
    }
    let key = keyring
        .verification_key(&tombstone.resume_integrity, now)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "stored MCP session {} uses an unknown or expired tombstone HMAC key",
                tombstone.record.session_id
            ))
        })?;
    let expected = compute_terminal_tombstone_integrity_tag(key, tombstone)?;
    verify_remote_session_hmac(
        &expected,
        &tombstone.resume_integrity.tag,
        &tombstone.record.session_id,
        "terminal tombstone integrity",
    )
}

pub(super) fn validate_terminal_fence_integrity(
    keyring: &RemoteSessionHmacKeyring,
    fence: &RemoteSessionTerminalFence,
    now: u64,
) -> Result<(), CliError> {
    if fence.resume_generation == 0
        || fence.terminal_epoch == 0
        || fence.resume_generation != fence.terminal_epoch
        || !matches!(
            fence.terminal_state,
            RemoteSessionState::Deleted | RemoteSessionState::Expired | RemoteSessionState::Closed
        )
        || fence.terminal_reason.state() != fence.terminal_state
    {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} has an invalid terminal fence generation",
            fence.session_id
        )));
    }
    let key = keyring
        .verification_key(&fence.resume_integrity, now)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "stored MCP session {} uses an unknown or expired terminal fence HMAC key",
                fence.session_id
            ))
        })?;
    let expected = compute_terminal_fence_integrity_tag(key, fence)?;
    verify_remote_session_hmac(
        &expected,
        &fence.resume_integrity.tag,
        &fence.session_id,
        "terminal fence integrity",
    )
}
