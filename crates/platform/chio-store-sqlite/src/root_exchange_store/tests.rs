use chio_core::capability::scope::ChioScope;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_core::root_authority::Sha256Digest;
use chio_core::tenant_index::KeyedIndexValue;
use serde_json::{json, Value};

use super::projection::RootRow;
use super::{canonical_blob, RootExchangeStoreError, RootTags};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const DELEGATION_CONTEXT_DIGEST_DOMAIN: &[u8] = b"chio.delegation-context.v1\0";

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

/// A root row whose columns, blobs and projection agree, over the context
/// `edit` produces from a `chio_local_as` context. The context blob is built
/// from JSON, not decoded, so the row check alone judges it.
fn local_as_row(edit: impl FnOnce(&mut Value)) -> TestResult<RootRow> {
    let exchange = Keypair::from_seed(&[2; 32]);
    let scope = ChioScope::default();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-1".into(),
            issuer: exchange.public_key(),
            subject: Keypair::from_seed(&[3; 32]).public_key(),
            scope: scope.clone(),
            issued_at: 995,
            expires_at: 1_300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &exchange,
    )?;
    let mut context = json!({
        "schema": "chio.delegation-context.v1",
        "anchor": {
            "kind": "chio_local_as",
            "issuer": "urn:chio:local-as",
            "artifact_retained": false,
            "replay_key_digest": digest(0x11),
            "token_iat": 995,
            "token_exp": 1_300,
            "subject": { "commit": digest(0x21), "salt_ref": "anchor.sub" },
            "tenant": { "commit": digest(0x22), "salt_ref": "anchor.tenant" },
            "claims": {}
        },
        "exchange": {
            "exchange_key": exchange.public_key(),
            "exchanged_at": 995,
            "request_digest": digest(0x12),
            "holder": "edge_session"
        },
        "root_policy_rule_id": "local-as",
        "effective_root_scope_hash": Sha256Digest::of_scope(&scope)?
    });
    edit(&mut context);
    let context_bytes = canonical_blob(&context)?;
    let key_id = digest(0xa1);
    let mut row = RootRow {
        capability_id: "cap-1".into(),
        root_policy_rule_id: "local-as".into(),
        tags: RootTags {
            subject: KeyedIndexValue {
                key_id,
                value: digest(0xb1),
            },
            tenant: KeyedIndexValue {
                key_id,
                value: digest(0xc1),
            },
        },
        replay_key_digest: digest(0x11),
        replay_bound_at: 1_000,
        client_id: "mcp-client-claude".into(),
        artifact_digest: digest(0x13),
        request_digest: digest(0x12),
        expires_at: 1_300,
        anchor_kind: "chio_local_as".into(),
        holder: "edge_session".into(),
        root_policy_digest: digest(0x14),
        provider_identity_digest: None,
        key_snapshot_digest: None,
        context_digest: Sha256Digest::of_domain(DELEGATION_CONTEXT_DIGEST_DOMAIN, &context_bytes),
        delegation_context: context_bytes,
        root_capability: canonical_blob(&capability)?,
        minted_at: 1_000,
        authorization_projection_digest: digest(0),
    };
    row.authorization_projection_digest = row.projection_digest()?;
    Ok(row)
}

#[test]
fn row_check_passes_a_non_jws_context_without_artifact_digest() -> TestResult {
    let stored = local_as_row(|_| {})?.verify()?;
    assert_eq!(stored.context.anchor.artifact_digest, None);
    Ok(())
}

#[test]
fn row_check_refuses_a_non_jws_context_carrying_artifact_digest() -> TestResult {
    let row = local_as_row(|context| {
        context["anchor"]["artifact_digest"] = json!(digest(0x13));
    })?;
    assert_eq!(
        row.verify().err(),
        Some(RootExchangeStoreError::AnchoredRootTampered {
            capability_id: "cap-1".into()
        })
    );
    Ok(())
}
