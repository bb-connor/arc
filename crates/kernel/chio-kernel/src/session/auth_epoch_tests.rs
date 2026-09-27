use super::*;
use std::sync::{Arc, Barrier};

fn authenticated(principal: &str) -> SessionAuthContext {
    SessionAuthContext::streamable_http_static_bearer(principal, "credential", None)
}

fn at_epoch(epoch: u64) -> Result<Session, SessionError> {
    let session = Session::new(SessionId::new("epoch-boundary"), "agent".into(), vec![]);
    session.activate()?;
    session.auth_state.replace_with(|current| {
        let mut next = current.clone();
        next.session_anchor = SessionAnchorState::new(&session.id, &next.auth_context, epoch);
        (Some(next), ())
    });
    Ok(session)
}

#[test]
fn last_active_epoch_refuses_rotation_but_preserves_terminal_closure() -> Result<(), SessionError> {
    let session = at_epoch(u64::MAX - 2)?;
    let auth = authenticated("last-principal");
    let (rotated, snapshot, _) = session.set_auth_context(auth.clone())?;
    assert!(rotated);
    assert_eq!(snapshot.session_anchor.auth_epoch(), u64::MAX - 1);
    assert!(!session.set_auth_context(auth.clone())?.0);
    assert!(matches!(
        session.set_auth_context(authenticated("cannot-publish")),
        Err(SessionError::AuthEpochExhausted { .. })
    ));
    assert_eq!(session.session_anchor(), snapshot.session_anchor);
    assert_eq!(session.auth_context(), auth);
    let active_snapshot = session.clone();
    session.close()?;
    assert_eq!(session.state(), SessionState::Closed);
    assert_eq!(session.session_anchor().auth_epoch(), u64::MAX);
    assert_eq!(
        session.auth_context(),
        SessionAuthContext::in_process_anonymous()
    );
    assert_eq!(active_snapshot.state(), SessionState::Ready);
    assert_eq!(active_snapshot.session_anchor().auth_epoch(), u64::MAX - 1);
    active_snapshot.close()?;
    assert_eq!(active_snapshot.session_anchor().auth_epoch(), u64::MAX);
    let terminal_snapshot = session.clone();
    assert_eq!(terminal_snapshot.state(), SessionState::Closed);
    terminal_snapshot.close()?;
    assert!(matches!(
        session.set_auth_context(authenticated("after-close")),
        Err(SessionError::OperationNotAllowed {
            operation: "set_auth_context",
            state: "closed",
            ..
        })
    ));
    Ok(())
}

#[test]
fn exhausted_persisted_rotation_never_calls_the_writer() -> Result<(), SessionError> {
    let session = at_epoch(u64::MAX - 1)?;
    let before = session.session_anchor_snapshot();
    let mut writes = 0;
    let result = session.set_auth_context_persisted(authenticated("new"), |_, _| {
        writes += 1;
        Ok::<_, ()>(())
    });
    assert!(matches!(
        result,
        Err(SessionPersistError::Session(
            SessionError::AuthEpochExhausted { .. }
        ))
    ));
    assert_eq!(writes, 0);
    assert_eq!(session.session_anchor(), before.session_anchor);
    assert_eq!(session.auth_context(), before.auth_context);
    assert_eq!(session.state(), SessionState::Ready);
    Ok(())
}

#[test]
fn persistence_failure_leaves_auth_and_closing_epoch_available() -> Result<(), SessionError> {
    let session = at_epoch(u64::MAX - 2)?;
    let before = session.session_anchor_snapshot();
    assert_eq!(
        session.set_auth_context_persisted(authenticated("new"), |_, _| Err("disk full")),
        Err(SessionPersistError::Persist("disk full"))
    );
    assert_eq!(session.session_anchor(), before.session_anchor);
    assert_eq!(session.auth_context(), before.auth_context);
    session.set_auth_context(authenticated("new"))?;
    let active = session.session_anchor_snapshot();
    assert_eq!(
        session.close_persisted(|_, _| Err("disk full")),
        Err(SessionPersistError::Persist("disk full"))
    );
    assert_eq!(session.state(), SessionState::Ready);
    assert_eq!(session.session_anchor(), active.session_anchor);
    assert_eq!(session.auth_context(), active.auth_context);
    let mut writes = 0;
    let result = session.close_persisted(|snapshot, supersedes| {
        writes += 1;
        assert_eq!(supersedes, Some(active.session_anchor.id()));
        assert_eq!(snapshot.session_anchor.auth_epoch(), u64::MAX);
        Ok::<_, ()>(())
    });
    assert_eq!(result, Ok(()));
    assert_eq!(
        session.close_persisted(|_, _| {
            writes += 1;
            Ok::<_, ()>(())
        }),
        Ok(())
    );
    assert_eq!(writes, 1);
    assert_eq!(session.state(), SessionState::Closed);
    Ok(())
}

#[test]
fn competing_rotations_cannot_publish_the_same_epoch() -> Result<(), Box<dyn std::error::Error>> {
    let session = Arc::new(at_epoch(u64::MAX - 2)?);
    let barrier = Arc::new(Barrier::new(2));
    let workers = ["a", "b"].map(|principal| {
        let session = Arc::clone(&session);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            let mut persisted = None;
            let result =
                session.set_auth_context_persisted(authenticated(principal), |snapshot, _| {
                    persisted = Some(snapshot.clone());
                    Ok::<_, ()>(())
                });
            (result, persisted)
        })
    });
    let mut winners = Vec::new();
    let mut refusals = 0;
    for worker in workers {
        let (result, persisted) = worker.join().map_err(|_| "rotation worker panicked")?;
        match result {
            Ok(()) => winners.push(persisted.ok_or("successful rotation did not persist")?),
            Err(SessionPersistError::Session(SessionError::AuthEpochExhausted { .. })) => {
                assert!(persisted.is_none());
                refusals += 1;
            }
            other => panic!("unexpected rotation result: {other:?}"),
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(refusals, 1);
    assert_eq!(session.session_anchor(), winners[0].session_anchor);
    assert_eq!(session.auth_context(), winners[0].auth_context);
    session.close()?;
    assert_eq!(session.session_anchor().auth_epoch(), u64::MAX);
    Ok(())
}
