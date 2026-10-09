use super::*;

/// Parameters of `assert_catalog_retractions`.
pub(crate) struct CatalogRetractionCase<'a> {
    pub(crate) other_tenant: &'a HostedTenantId,
    pub(crate) signer: &'a Keypair,
    pub(crate) finding_id: &'a str,
    pub(crate) replicator: &'a PostgresFindingMarketReplicator,
    pub(crate) source_signer: &'a Keypair,
    pub(crate) authority_now: u64,
}

/// Parameters of `assert_terminal_job_retention_gc`.
pub(crate) struct TerminalJobRetentionCase<'a> {
    pub(crate) retention_signer: &'a Keypair,
    pub(crate) retention_public_key: &'a chio_core_types::crypto::PublicKey,
    pub(crate) authority_now: u64,
    pub(crate) request_sha256: &'a str,
    pub(crate) payload: &'a [u8],
}

/// Parameters of `apply_authority_transition`.
pub(crate) struct AuthorityTransition<'a> {
    pub(crate) signer: &'a Keypair,
    pub(crate) operation: HostedAuthorityTransitionOperation,
    pub(crate) from_authority: HostedMarketAuthority,
    pub(crate) to_authority: HostedMarketAuthority,
    pub(crate) from_epoch: u64,
    pub(crate) to_epoch: u64,
    pub(crate) through_sequence: u64,
    pub(crate) checkpoint_sha256: &'a str,
    pub(crate) rollback_window_ends_at: Option<u64>,
    pub(crate) created_at: u64,
}

pub(crate) async fn put_buyer_api_key(
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
) -> Result<(), HostedMarketStoreError> {
    store
        .put_api_key(
            tenant,
            ApiKeyWrite {
                key_id: "key-a",
                principal_id: "buyer-a",
                verifier_sha256: &"c".repeat(64),
                allowed_actions: &["finding.purchase".to_owned()]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                active_from: 1_700_000_000,
                expires_at: 1_700_003_600,
                rotated_from_key_id: None,
                now: 1_700_000_000,
            },
        )
        .await?;
    Ok(())
}

pub(crate) async fn rotate_buyer_api_key(
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
    let actions = ["finding.purchase".to_owned()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    store
        .put_api_key_with_security_event(
            tenant,
            ApiKeyWithSecurityEvent {
                key_id: "key-b",
                principal_id: "buyer-a",
                verifier_sha256: &"e".repeat(64),
                allowed_actions: &actions,
                active_from: 1_700_000_000,
                expires_at: 1_700_003_600,
                rotated_from_key_id: Some("key-a"),
                event_id: "event-key-b-issued",
                event_kind: "hosted.api_key.issued",
                artifact_json: br#"{"event":"issue"}"#,
                now: 1_700_000_000,
            },
        )
        .await
}
