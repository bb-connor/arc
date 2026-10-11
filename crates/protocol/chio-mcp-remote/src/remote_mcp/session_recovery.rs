//! Startup recovery adjudicates expiry before any upstream is launched.
use super::*;
use chio_security_types::clock::ClockReading;

pub(super) fn resume_deadline(
    record: &RemoteSessionResumeRecord,
    reading: ClockReading,
) -> Result<Option<AuthorityDeadline>, ClockError> {
    if record.lifecycle.state != RemoteSessionState::Ready {
        return Ok(None);
    }
    if record.lifecycle.created_at > record.lifecycle.last_seen_at {
        return Err(ClockError::InvalidWindow);
    }
    AuthorityDeadline::new(
        UnixMillis::new(record.lifecycle.last_seen_at),
        UnixMillis::new(record.lifecycle.idle_expires_at),
        reading,
    )
    .map(Some)
}

pub(super) async fn restore_persisted_sessions(
    path: &FsPath,
    keyring: &RemoteSessionHmacKeyring,
    sessions: &RemoteSessionLedger,
    mut restore: impl FnMut(&RemoteSessionResumeRecord) -> Result<Option<Arc<RemoteSession>>, CliError>,
) -> Result<(), CliError> {
    let loaded = load_active_session_records(path, keyring, sessions.clock.millis()?)?;
    for session_id in loaded.invalid_session_ids {
        if let Err(error) = delete_active_session_record(path, &session_id) {
            warn!(session_id = %session_id, error = %error,
                "failed to delete malformed persisted MCP session record");
        }
    }
    for record in loaded.records {
        let reading = sessions.clock.read()?;
        let mut deadline = match resume_deadline(&record, reading) {
            Ok(deadline) => deadline,
            Err(ClockError::Expired) => {
                expire_record(path, keyring, sessions, &record, reading).await?;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let restored = restore(&record);
        // Keep the original monotonic deadline while restoration does I/O.
        // A fresh constructor must not extend it when wall time is frozen.
        if let Some(deadline) = deadline.as_mut() {
            let reading = match sessions.clock.read() {
                Ok(reading) => reading,
                Err(error) => {
                    stop_restored(&restored)?;
                    return Err(error.into());
                }
            };
            match deadline.remaining(reading) {
                Ok(_) => {}
                Err(ClockError::Expired) => {
                    let persisted = expire_record(path, keyring, sessions, &record, reading).await;
                    let stopped = stop_restored(&restored);
                    persisted?;
                    stopped?;
                    continue;
                }
                Err(error) => {
                    stop_restored(&restored)?;
                    return Err(error.into());
                }
            }
        }
        match restored {
            Ok(Some(session)) => {
                if let Some(deadline) = deadline {
                    session
                        .lifecycle
                        .lock()
                        .map_err(|_| ClockError::Unavailable)?
                        .deadline = Some(deadline);
                }
                sessions.insert_active(session).await;
            }
            Ok(None) => warn!(session_id = %record.session_id,
                "retaining incompatible MCP session without activating it"),
            Err(error) => {
                // An expired capability or an authority outage is not proof
                // that the authenticated session itself expired.
                return Err(error);
            }
        }
    }
    Ok(())
}

fn stop_restored(result: &Result<Option<Arc<RemoteSession>>, CliError>) -> Result<(), CliError> {
    if let Ok(Some(session)) = result {
        session.shutdown_upstream_transport()?;
    }
    Ok(())
}

async fn expire_record(
    path: &FsPath,
    keyring: &RemoteSessionHmacKeyring,
    sessions: &RemoteSessionLedger,
    record: &RemoteSessionResumeRecord,
    reading: ClockReading,
) -> Result<(), CliError> {
    let epoch = record
        .resume_generation
        .checked_add(1)
        .ok_or(ClockError::Overflow)?;
    let terminal_at = reading.unix_millis().get();
    let mut lifecycle = record.lifecycle.clone();
    lifecycle.state = RemoteSessionState::Expired;
    lifecycle.last_seen_at = terminal_at;
    lifecycle.deadline = None;
    lifecycle.drain_deadline_at = None;
    let diagnostic = RemoteSessionDiagnosticRecord {
        session_id: record.session_id.clone(),
        auth_context: record.auth_context.clone(),
        capabilities: record
            .issued_capabilities
            .iter()
            .map(|capability| RemoteSessionCapability {
                id: capability.id.clone(),
                issuer_public_key: capability.issuer.to_hex(),
                subject_public_key: capability.subject.to_hex(),
            })
            .collect(),
        lifecycle,
        protocol_version: record.protocol_version.clone(),
        ownership: RemoteSessionOwnershipSnapshot::default(),
        terminal_at,
    };
    let (tombstone, fence) = sign_terminal_session_records(keyring, diagnostic, epoch, epoch)?;
    prepare_terminal_session_transition(path, &fence, keyring, terminal_at)?;
    finalize_terminal_session_transition(path, &tombstone, keyring, terminal_at)?;
    sessions
        .terminal
        .lock()
        .await
        .insert(record.session_id.clone(), Arc::new(tombstone.record));
    Ok(())
}
