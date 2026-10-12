//! A hosted session persists its standard subscriptions before answering.
use super::cursor_seed::{ready_factory_session, ReadOnlyTransport};
use super::*;
use chio_mcp_adapter::edge::ResourceSubscriptionObserver;

const URI: &str = "file:///workspace/notes.txt";

fn stored(
    path: &FsPath,
    factory: &RemoteSessionFactory,
) -> Result<RemoteSessionResumeRecord, Box<dyn std::error::Error>> {
    let keyring = factory
        .resume_hmac_keyring
        .clone()
        .ok_or("resume keyring")?;
    let mut loaded = load_active_session_records(path, &keyring, factory.config.clock.millis()?)?;
    assert!(loaded.invalid_session_ids.is_empty());
    Ok(loaded.records.pop().ok_or("no active record")?)
}

#[tokio::test]
async fn subscription_changes_persist_before_they_take_effect(
) -> Result<(), Box<dyn std::error::Error>> {
    let (directory, path) = private_test_session_database("subscription-persist");
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(
        &config.policy_path,
        "capabilities:\n  default:\n    tools: []\n",
    )?;
    config.test_transport = Some(Arc::new(ReadOnlyTransport));
    config.session_db_path = Some(path.clone());
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
    configure_signed_manifest(&mut config, &directory);
    let factory = RemoteSessionFactory::new(config)?;
    let session = factory.spawn_session(SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:subscription-persist",
        sha256_hex(b"subscription-persist-agent"),
        None,
    ))?;
    ready_factory_session(&session).await?;
    let observer = session_core_session::SubscriptionPersistence(Arc::downgrade(&session));
    let expected = vec![PersistedSubscription::Standard {
        uri: URI.into(),
        capability_id: "capability-subscribe".into(),
    }];

    observer.subscribed(URI, "capability-subscribe")?;
    let record = stored(&path, &factory)?;
    assert_eq!(record.subscriptions, expected);
    assert_eq!(record.resume_integrity.envelope, RemoteSessionEnvelope::V3);
    assert_eq!(session.persisted_subscriptions()?, expected);

    let generation = record.resume_generation;
    observer.subscribed(URI, "capability-subscribe")?;
    assert_eq!(stored(&path, &factory)?.resume_generation, generation);

    rusqlite::Connection::open(&path)?.execute_batch(
        "CREATE TRIGGER refuse_active_update BEFORE UPDATE ON remote_active_sessions \
         BEGIN SELECT RAISE(ABORT, 'injected subscription persist outage'); END; \
         CREATE TRIGGER refuse_active_insert BEFORE INSERT ON remote_active_sessions \
         BEGIN SELECT RAISE(ABORT, 'injected subscription persist outage'); END;",
    )?;
    assert!(observer.unsubscribed(URI).is_err());
    assert_eq!(session.persisted_subscriptions()?, expected);
    assert!(observer
        .subscribed("file:///workspace/other.txt", "capability-subscribe")
        .is_err());
    assert_eq!(session.persisted_subscriptions()?, expected);
    assert_eq!(stored(&path, &factory)?.subscriptions, expected);

    rusqlite::Connection::open(&path)?
        .execute_batch("DROP TRIGGER refuse_active_update; DROP TRIGGER refuse_active_insert;")?;
    observer.unsubscribed(URI)?;
    let record = stored(&path, &factory)?;
    assert!(record.subscriptions.is_empty());
    assert_eq!(record.resume_integrity.envelope, RemoteSessionEnvelope::V3);
    assert!(session.persisted_subscriptions()?.is_empty());

    drop((observer, session, factory));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
