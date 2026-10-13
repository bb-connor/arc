//! Terminal records carry the typed reason their terminal state permits.
use super::*;

const REASONS: [TerminalReason; 5] = [
    TerminalReason::Deleted,
    TerminalReason::Expired,
    TerminalReason::Closed,
    TerminalReason::SubscriptionNotRestored,
    TerminalReason::SubscriptionAuthorityLost,
];

fn terminal_record(state: RemoteSessionState) -> RemoteSessionDiagnosticRecord {
    let active = sample_resume_record();
    let mut lifecycle = active.lifecycle.clone();
    lifecycle.state = state;
    RemoteSessionDiagnosticRecord {
        session_id: active.session_id,
        auth_context: active.auth_context,
        capabilities: Vec::new(),
        lifecycle,
        protocol_version: active.protocol_version,
        ownership: RemoteSessionOwnershipSnapshot::default(),
        terminal_at: 13,
        terminal_reason: None,
    }
}

fn sign(
    keyring: &RemoteSessionHmacKeyring,
    reason: TerminalReason,
) -> (RemoteSessionTombstoneRecord, RemoteSessionTerminalFence) {
    sign_terminal_session_records(keyring, terminal_record(reason.state()), reason, 2, 2)
        .expect("sign terminal pair")
}

fn verifies(
    keyring: &RemoteSessionHmacKeyring,
    tombstone: &RemoteSessionTombstoneRecord,
    fence: &RemoteSessionTerminalFence,
) -> (bool, bool) {
    (
        validate_terminal_tombstone_integrity(keyring, tombstone, 13).is_ok(),
        validate_terminal_fence_integrity(keyring, fence, 13).is_ok(),
    )
}

#[test]
fn every_reason_round_trips_with_its_state() {
    let keyring = test_resume_hmac_keyring();
    for reason in REASONS {
        let (tombstone, fence) = sign(&keyring, reason);
        let tombstone: RemoteSessionTombstoneRecord =
            serde_json::from_str(&serde_json::to_string(&tombstone).unwrap()).unwrap();
        let fence: RemoteSessionTerminalFence =
            serde_json::from_str(&serde_json::to_string(&fence).unwrap()).unwrap();
        assert_eq!(tombstone.record.terminal_reason, Some(reason));
        assert_eq!(fence.terminal_reason, reason);
        assert_eq!(verifies(&keyring, &tombstone, &fence), (true, true));
    }
    let (tombstone, _) = sign(&keyring, TerminalReason::SubscriptionAuthorityLost);
    assert_eq!(
        serde_json::to_value(&tombstone).unwrap()["record"]["terminal_reason"],
        "subscription_authority_lost"
    );
}

#[test]
fn reason_must_match_the_terminal_state() {
    let keyring = test_resume_hmac_keyring();
    assert!(sign_terminal_session_records(
        &keyring,
        terminal_record(RemoteSessionState::Closed),
        TerminalReason::Expired,
        2,
        2,
    )
    .is_err());

    let (mut tombstone, mut fence) = sign(&keyring, TerminalReason::SubscriptionNotRestored);
    tombstone.record.terminal_reason = Some(TerminalReason::Deleted);
    fence.terminal_reason = TerminalReason::Deleted;
    assert_eq!(verifies(&keyring, &tombstone, &fence), (false, false));
}

#[test]
fn tampered_missing_or_unknown_reasons_are_refused() {
    let keyring = test_resume_hmac_keyring();
    let (tombstone, fence) = sign(&keyring, TerminalReason::SubscriptionNotRestored);

    let (mut swapped_tombstone, mut swapped_fence) = (tombstone.clone(), fence.clone());
    swapped_tombstone.record.terminal_reason = Some(TerminalReason::Closed);
    swapped_fence.terminal_reason = TerminalReason::Closed;
    assert_eq!(
        verifies(&keyring, &swapped_tombstone, &swapped_fence),
        (false, false)
    );

    let mut missing_tombstone = tombstone;
    missing_tombstone.record.terminal_reason = None;
    assert!(validate_terminal_tombstone_integrity(&keyring, &missing_tombstone, 13).is_err());

    let mut missing_fence = serde_json::to_value(&fence).unwrap();
    missing_fence
        .as_object_mut()
        .unwrap()
        .remove("terminal_reason");
    assert!(serde_json::from_value::<RemoteSessionTerminalFence>(missing_fence).is_err());

    let mut unknown = serde_json::to_value(&fence).unwrap();
    unknown["terminal_reason"] = json!("operator_whim");
    assert!(serde_json::from_value::<RemoteSessionTerminalFence>(unknown).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn store_keeps_the_reason_and_refuses_a_mismatched_pair() {
    let (directory, path) = private_test_session_database("terminal-reason");
    let lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let active = sample_resume_record_with_keyring(&keyring);
    persist_active_session_record(&path, &active, &keyring, 13).unwrap();

    let (tombstone, fence) = sign(&keyring, TerminalReason::SubscriptionNotRestored);
    let (other_tombstone, _) = sign(&keyring, TerminalReason::SubscriptionAuthorityLost);
    assert!(
        prepare_terminal_session_transition(&path, &fence, &other_tombstone, &keyring, 13).is_err()
    );
    prepare_terminal_session_transition(&path, &fence, &tombstone, &keyring, 13).unwrap();
    assert!(finalize_terminal_session_transition(&path, &other_tombstone, &keyring, 13).is_err());
    finalize_terminal_session_transition(&path, &tombstone, &keyring, 13).unwrap();
    let loaded = load_terminal_session_records(&path, &keyring, 13).unwrap();
    assert_eq!(
        loaded[&active.session_id].terminal_reason,
        Some(TerminalReason::SubscriptionNotRestored)
    );
    drop(lease);
    std::fs::remove_dir_all(directory).unwrap();
}
