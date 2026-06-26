//! Chio Pass data-stream access gating (M0 T5).
//!
//! The Chio Pass mints a permanent tier_0 baseline RIGHT: free Read/Subscribe
//! over three aggregate trust feeds plus the holder's OWN receipts and OWN
//! lineage. This module is the kernel-side gate for that right. It builds the
//! Pass-minted [`ResourceGrant`] set for the five gifted streams, enforces the
//! own-tenant baseline binding, and applies the deny-list that keeps raw
//! pheromone deposits and financial market surfaces out of scope.
//!
//! The five gifted streams (pinned indices `0..=4`, no `TrustTier` predicate, so
//! a tier_0 newcomer and a Premier holder get byte-identical decisions):
//!
//! | idx | uri_pattern                                  | kind                              |
//! |-----|----------------------------------------------|-----------------------------------|
//! | 0   | `chio://trust/reputation/tier/*`             | aggregate (coarse tier label)     |
//! | 1   | `chio://marketplace/listings*`               | aggregate (advertised prices)     |
//! | 2   | `chio://trust/pheromone/concentration/*`     | aggregate (collapsed origin)      |
//! | 3   | `chio://receipts/tenant/<subject_tenant>/*`  | OWN (tenant-bound baseline right) |
//! | 4   | `chio://lineage/tenant/<subject_tenant>/*`   | OWN (tenant-bound baseline right) |
//!
//! Own patterns use the MANDATORY `/` delimiter before the trailing `*` so a
//! tenant `did:chioabcd` cannot prefix-match `did:chioabcde...`.
//!
//! GIFT-BOUNDARY POSTURE (own receipts / own lineage). The read grants this
//! module mints are the SCOPE boundary. They are NOT the disclosed-artifact
//! boundary for the holder's own data. Per the disclosure binding, the
//! own-receipts/own-lineage gift MUST be served through the shipped
//! disclosure-lineage export
//! (`chio-disclosure-lineage::verify_disclosure_lineage_bundle`): a pinned-key
//! signed lineage subgraph bound to a transaction-passport ref, a verifier
//! privacy profile, a mandatory leakage ledger (required even when empty), and
//! hashed identifiers. [`project_pass_stream_view`] in this module is only an
//! INTERNAL whitelist-by-removal redaction step; it is deliberately weaker than
//! that disclosure layer mandates and is never the gift boundary on its own. The
//! orchestrator that wires the disclosure-lineage bundle lives outside T5.
//!
//! Naming note: `ChioPassStream` here is the gated data stream, distinct from the
//! `ChioPass` soulbound credential in `chio-credentials`.

use chio_core_types::capability::scope::{ChioScope, Operation, ResourceGrant, ToolGrant};
use chio_core_types::capability::token::CapabilityToken;

use crate::kernel::KernelError;
use crate::receipt_query::ReceiptReadContext;
use crate::request_matching::{
    capability_matches_resource_request, capability_matches_resource_subscription,
};

/// Tool-server id the metered XCC compute grant pins (Section 2.7).
pub const PASS_COMPUTE_SERVER_ID: &str = "chio.pass.compute";

/// Private-use allotment unit the metered grant denominates (Section 2.3). It is
/// intentionally never priced, so it carries no money leg.
pub const PASS_ALLOTMENT_UNIT: &str = "XCC";

/// Deny-listed raw pheromone deposit surface (origin-identifying); only the
/// collapsed aggregate `concentration` feed is gifted.
pub const PASS_DENY_PHEROMONE_DEPOSITS: &str = "chio://trust/pheromone/deposits";

/// Deny-listed financial market surface. Note the trailing `/`: it does NOT
/// collide with the gifted `chio://marketplace/listings*` aggregate stream.
pub const PASS_DENY_MARKET_FINANCIAL: &str = "chio://market/";

/// Economic envelope keys removed from every served free-read VIEW
/// (whitelist-by-removal, fail-closed). Stripping `"financial"` alone was
/// fail-open because `metadata["budget_authority"]` and `metadata["cost"]` carry
/// cost data too.
pub const PASS_REDACTED_METADATA_KEYS: [&str; 3] = ["financial", "budget_authority", "cost"];

/// One of the five gifted data streams (pinned indices `0..=4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChioPassStream {
    /// idx 0: aggregate coarse reputation tier feed.
    ReputationTier,
    /// idx 1: aggregate listing/pricing discovery.
    MarketplaceListings,
    /// idx 2: aggregate pheromone concentration (collapsed origin counts).
    PheromoneConcentration,
    /// idx 3: the holder's OWN receipts (tenant-bound baseline right).
    OwnReceipts,
    /// idx 4: the holder's OWN lineage (tenant-bound baseline right).
    OwnLineage,
}

impl ChioPassStream {
    /// The five streams in their pinned `0..=4` order.
    pub const ALL: [ChioPassStream; 5] = [
        ChioPassStream::ReputationTier,
        ChioPassStream::MarketplaceListings,
        ChioPassStream::PheromoneConcentration,
        ChioPassStream::OwnReceipts,
        ChioPassStream::OwnLineage,
    ];

    /// True for the two tenant-bound OWN streams (receipts, lineage).
    #[must_use]
    pub fn is_own_tenant(self) -> bool {
        matches!(
            self,
            ChioPassStream::OwnReceipts | ChioPassStream::OwnLineage
        )
    }
}

/// Validates a subject tenant string for use in an own-stream URI. Fail-closed:
/// rejects an empty tenant, a wildcard, or a path delimiter, any of which would
/// widen the own-tenant binding past a single identity.
fn validated_tenant(tenant: &str) -> Result<&str, KernelError> {
    let trimmed = tenant.trim();
    if trimmed.is_empty() || trimmed.contains('*') || trimmed.contains('/') {
        return Err(KernelError::PassTenantBindingInvalid(tenant.to_string()));
    }
    Ok(trimmed)
}

/// Returns the canonical URI pattern for a single gifted stream.
///
/// The own streams bind `subject_tenant` (validated fail-closed); the three
/// aggregate streams ignore it.
///
/// # Errors
///
/// Returns [`KernelError::PassTenantBindingInvalid`] when an own stream is asked
/// for and `subject_tenant` is empty, wildcarded, or path-delimited.
pub fn pass_stream_uri(
    stream: ChioPassStream,
    subject_tenant: &str,
) -> Result<String, KernelError> {
    Ok(match stream {
        ChioPassStream::ReputationTier => "chio://trust/reputation/tier/*".to_string(),
        ChioPassStream::MarketplaceListings => "chio://marketplace/listings*".to_string(),
        ChioPassStream::PheromoneConcentration => {
            "chio://trust/pheromone/concentration/*".to_string()
        }
        ChioPassStream::OwnReceipts => {
            let tenant = validated_tenant(subject_tenant)?;
            format!("chio://receipts/tenant/{tenant}/*")
        }
        ChioPassStream::OwnLineage => {
            let tenant = validated_tenant(subject_tenant)?;
            format!("chio://lineage/tenant/{tenant}/*")
        }
    })
}

/// The five canonical baseline read URI strings, in pinned `0..=4` order.
///
/// This MUST stay byte-identical to the credential-layer builder
/// `chio_credentials::pass_baseline_read_uris(subject_did)` so a minted Pass
/// scope and the credential `read_scopes` bind the same identity. The two crates
/// cannot share one function (the credential crate does not depend on the kernel),
/// so the literals are kept in lockstep and cross-checked by tests on both sides.
/// Callers pass the canonical `did:chio` (which carries no `/`), matching the
/// issuance `tenant_id` used verbatim in the SQL `r.tenant_id = ?` own-stream
/// guard.
///
/// # Errors
///
/// Returns [`KernelError::PassTenantBindingInvalid`] when `subject_tenant` is
/// empty, wildcarded, or path-delimited.
pub fn pass_baseline_read_uris(subject_tenant: &str) -> Result<Vec<String>, KernelError> {
    ChioPassStream::ALL
        .iter()
        .map(|stream| pass_stream_uri(*stream, subject_tenant))
        .collect()
}

/// The five Pass-minted [`ResourceGrant`]s, each `operations: [Read, Subscribe]`,
/// at pinned indices `0..=4`. These carry no `max_*` limits and never open budget
/// rows.
///
/// # Errors
///
/// Propagates [`pass_baseline_read_uris`] failures.
pub fn pass_baseline_resource_grants(
    subject_tenant: &str,
) -> Result<Vec<ResourceGrant>, KernelError> {
    Ok(pass_baseline_read_uris(subject_tenant)?
        .into_iter()
        .map(|uri_pattern| ResourceGrant {
            uri_pattern,
            operations: vec![Operation::Read, Operation::Subscribe],
        })
        .collect())
}

/// True if `uri` reaches a deny-listed surface (raw pheromone deposits or any
/// financial market surface). Prefix-based and fail-closed.
#[must_use]
pub fn uri_is_pass_denied(uri: &str) -> bool {
    uri.starts_with(PASS_DENY_PHEROMONE_DEPOSITS) || uri.starts_with(PASS_DENY_MARKET_FINANCIAL)
}

/// Validates that the single metered tool grant is the canonical XCC compute
/// allotment (Section 2.7): `server_id == chio.pass.compute`, `tool_name == "*"`,
/// `operations == [Invoke]`, a positive-unit XCC `max_cost_per_invocation`, and
/// an XCC `max_total_cost`.
fn validate_metered_grant(grant: &ToolGrant) -> Result<(), KernelError> {
    if grant.server_id != PASS_COMPUTE_SERVER_ID {
        return Err(KernelError::PassScopeInflation(format!(
            "metered grant server_id must be {PASS_COMPUTE_SERVER_ID}"
        )));
    }
    if grant.tool_name != "*" {
        return Err(KernelError::PassScopeInflation(
            "metered grant tool_name must be \"*\"".to_string(),
        ));
    }
    if grant.operations != [Operation::Invoke] {
        return Err(KernelError::PassScopeInflation(
            "metered grant operations must be exactly [Invoke]".to_string(),
        ));
    }
    match &grant.max_cost_per_invocation {
        Some(amount) if amount.currency == PASS_ALLOTMENT_UNIT && amount.units > 0 => {}
        _ => {
            return Err(KernelError::PassScopeInflation(
                "metered grant max_cost_per_invocation must be a positive XCC amount".to_string(),
            ));
        }
    }
    match &grant.max_total_cost {
        Some(amount) if amount.currency == PASS_ALLOTMENT_UNIT => {}
        _ => {
            return Err(KernelError::PassScopeInflation(
                "metered grant max_total_cost must be Some XCC amount".to_string(),
            ));
        }
    }
    Ok(())
}

/// Scope-inflation backstop (fail-closed, covers ALL grant kinds).
///
/// A valid Pass scope carries EXACTLY one metered XCC tool grant, ZERO prompt
/// grants, and the five canonical baseline resource grants (exact count, order,
/// pattern, and operations). Anything else is rejected. The exact-equality check
/// on the resource grants both pins ordering and guarantees no deny-listed
/// surface slipped in.
///
/// # Errors
///
/// Returns [`KernelError::PassScopeInflation`] on any tool/prompt inflation or any
/// deviation from the canonical baseline, and propagates tenant-binding failures.
pub fn validate_pass_scope_is_baseline(
    scope: &ChioScope,
    subject_tenant: &str,
) -> Result<(), KernelError> {
    if scope.grants.len() != 1 {
        return Err(KernelError::PassScopeInflation(
            "expected exactly one metered grant".to_string(),
        ));
    }
    if !scope.prompt_grants.is_empty() {
        return Err(KernelError::PassScopeInflation(
            "prompt grants are not permitted".to_string(),
        ));
    }
    let metered = scope.grants.first().ok_or_else(|| {
        KernelError::PassScopeInflation("expected exactly one metered grant".to_string())
    })?;
    validate_metered_grant(metered)?;

    let baseline = pass_baseline_resource_grants(subject_tenant)?;
    if scope.resource_grants != baseline {
        return Err(KernelError::PassScopeInflation(
            "resource grants are not the canonical baseline".to_string(),
        ));
    }
    for grant in &scope.resource_grants {
        if uri_is_pass_denied(&grant.uri_pattern) {
            return Err(KernelError::PassScopeInflation(grant.uri_pattern.clone()));
        }
    }
    Ok(())
}

/// The tenant-scoped receipt read context for the OWN-receipts stream. This is
/// the independent second denial behind the URI binding: tenant-scoped with
/// `include_null_tenant = false`, so untenanted rows stay hidden and the store's
/// no-widening guard constrains the read to `r.tenant_id = <subject_tenant>`.
///
/// # Errors
///
/// Returns [`KernelError::PassTenantBindingInvalid`] when `subject_tenant` is
/// empty, wildcarded, or path-delimited.
pub fn pass_receipt_read_context(subject_tenant: &str) -> Result<ReceiptReadContext, KernelError> {
    let tenant = validated_tenant(subject_tenant)?;
    Ok(ReceiptReadContext::authenticated_tenant(tenant))
}

/// Projects a redacted COPY of a served free-read VIEW. INTERNAL redaction step
/// only (see the module-level gift-boundary posture). It removes every key in
/// [`PASS_REDACTED_METADATA_KEYS`] from `metadata` and stamps
/// `redaction: "summary"`. It never mutates or re-signs the stored artifact, and
/// the CONTROL 3 genuine-use scan reads the STORED receipt directly, so stripping
/// `"cost"` from the served view does not affect that scan.
///
/// # Errors
///
/// Fail-closed: a body that is not a JSON object, or a `metadata` that is neither
/// an object nor null, returns [`KernelError::PassRedactionFailed`] so the row is
/// denied rather than served with cost data leaked.
pub fn project_pass_stream_view(
    receipt_body: &serde_json::Value,
) -> Result<serde_json::Value, KernelError> {
    let serde_json::Value::Object(map) = receipt_body else {
        return Err(KernelError::PassRedactionFailed(
            "receipt body is not a JSON object".to_string(),
        ));
    };
    let mut redacted = map.clone();
    match redacted.get_mut("metadata") {
        Some(serde_json::Value::Object(metadata)) => {
            for key in PASS_REDACTED_METADATA_KEYS {
                metadata.remove(key);
            }
        }
        Some(serde_json::Value::Null) | None => {}
        Some(_) => {
            return Err(KernelError::PassRedactionFailed(
                "receipt metadata is neither an object nor null".to_string(),
            ));
        }
    }
    redacted.insert(
        "redaction".to_string(),
        serde_json::Value::String("summary".to_string()),
    );
    Ok(serde_json::Value::Object(redacted))
}

/// Serving gate for a Read against a gifted stream. Deny-list FIRST, then defer
/// to the unchanged resource matcher. No `TrustTier` branch exists, so the
/// decision is identical for a tier_0 newcomer and a Premier holder.
///
/// # Errors
///
/// Propagates resource-matcher failures.
pub fn pass_authorizes_read(cap: &CapabilityToken, uri: &str) -> Result<bool, KernelError> {
    if uri_is_pass_denied(uri) {
        return Ok(false);
    }
    capability_matches_resource_request(cap, uri)
}

/// Serving gate for a Subscribe against a gifted stream. Deny-list FIRST, then
/// defer to the unchanged subscription matcher.
///
/// # Errors
///
/// Propagates subscription-matcher failures.
pub fn pass_authorizes_subscription(cap: &CapabilityToken, uri: &str) -> Result<bool, KernelError> {
    if uri_is_pass_denied(uri) {
        return Ok(false);
    }
    capability_matches_resource_subscription(cap, uri)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core_types::capability::scope::{MonetaryAmount, PromptGrant};
    use chio_core_types::capability::token::CapabilityTokenBody;
    use chio_core_types::crypto::Keypair;

    const TENANT: &str = "did:chioabcd";

    fn xcc_metered_grant() -> ToolGrant {
        ToolGrant {
            server_id: PASS_COMPUTE_SERVER_ID.to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 1,
                currency: PASS_ALLOTMENT_UNIT.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: PASS_ALLOTMENT_UNIT.to_string(),
            }),
            dpop_required: None,
        }
    }

    fn baseline_scope(tenant: &str) -> ChioScope {
        ChioScope {
            grants: vec![xcc_metered_grant()],
            resource_grants: pass_baseline_resource_grants(tenant).expect("baseline grants"),
            prompt_grants: Vec::new(),
        }
    }

    fn pass_capability(scope: ChioScope) -> CapabilityToken {
        let issuer = Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "chiopass:test".to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope,
                issued_at: 1,
                expires_at: u64::MAX,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .expect("sign capability")
    }

    #[test]
    fn baseline_read_uris_match_canonical_literals() {
        let uris = pass_baseline_read_uris(TENANT).expect("uris");
        assert_eq!(
            uris,
            vec![
                "chio://trust/reputation/tier/*".to_string(),
                "chio://marketplace/listings*".to_string(),
                "chio://trust/pheromone/concentration/*".to_string(),
                format!("chio://receipts/tenant/{TENANT}/*"),
                format!("chio://lineage/tenant/{TENANT}/*"),
            ],
            "kernel baseline URIs must stay byte-identical to the credential-layer builder",
        );
    }

    #[test]
    fn baseline_resource_grants_are_five_read_subscribe_grants_in_order() {
        let grants = pass_baseline_resource_grants(TENANT).expect("grants");
        assert_eq!(grants.len(), 5);
        for (index, stream) in ChioPassStream::ALL.iter().enumerate() {
            let expected_uri = pass_stream_uri(*stream, TENANT).expect("uri");
            assert_eq!(grants[index].uri_pattern, expected_uri);
            assert_eq!(
                grants[index].operations,
                vec![Operation::Read, Operation::Subscribe],
                "every gifted stream is Read/Subscribe only",
            );
        }
    }

    #[test]
    fn own_streams_reject_invalid_tenant_fail_closed() {
        for bad in ["", "*", "did/chio", "did:chio*"] {
            assert!(matches!(
                pass_stream_uri(ChioPassStream::OwnReceipts, bad),
                Err(KernelError::PassTenantBindingInvalid(_))
            ));
            assert!(matches!(
                pass_baseline_read_uris(bad),
                Err(KernelError::PassTenantBindingInvalid(_))
            ));
            assert!(matches!(
                pass_receipt_read_context(bad),
                Err(KernelError::PassTenantBindingInvalid(_))
            ));
        }
    }

    #[test]
    fn own_tenant_uri_uses_mandatory_delimiter_blocking_prefix_collision() {
        // A shorter tenant must not prefix-match a longer sibling tenant.
        let short = pass_stream_uri(ChioPassStream::OwnReceipts, "did:chioabcd").expect("uri");
        let long = "chio://receipts/tenant/did:chioabcde/extra";
        assert!(
            !long.starts_with(short.trim_end_matches('*')),
            "the mandatory `/` before `*` must block did:chioabcd matching did:chioabcde",
        );
    }

    #[test]
    fn deny_list_covers_raw_deposits_and_market_financial() {
        assert!(uri_is_pass_denied("chio://trust/pheromone/deposits"));
        assert!(uri_is_pass_denied(
            "chio://trust/pheromone/deposits/origin/abc"
        ));
        assert!(uri_is_pass_denied("chio://market/financials/spot"));
    }

    #[test]
    fn deny_list_does_not_collide_with_gifted_marketplace_listings() {
        // The gifted aggregate listing stream must NOT be deny-listed by the
        // chio://market/ financial prefix (marketplace != market/).
        assert!(!uri_is_pass_denied("chio://marketplace/listings"));
        assert!(!uri_is_pass_denied("chio://marketplace/listings/abc"));
        assert!(!uri_is_pass_denied(
            "chio://trust/pheromone/concentration/x"
        ));
    }

    #[test]
    fn baseline_scope_validates() {
        validate_pass_scope_is_baseline(&baseline_scope(TENANT), TENANT).expect("baseline valid");
    }

    #[test]
    fn scope_rejects_extra_tool_grant() {
        let mut scope = baseline_scope(TENANT);
        scope.grants.push(xcc_metered_grant());
        assert!(matches!(
            validate_pass_scope_is_baseline(&scope, TENANT),
            Err(KernelError::PassScopeInflation(_))
        ));
    }

    #[test]
    fn scope_rejects_prompt_grant_inflation() {
        let mut scope = baseline_scope(TENANT);
        scope.prompt_grants.push(PromptGrant {
            prompt_name: "*".to_string(),
            operations: vec![Operation::Get],
        });
        assert!(matches!(
            validate_pass_scope_is_baseline(&scope, TENANT),
            Err(KernelError::PassScopeInflation(_))
        ));
    }

    #[test]
    fn scope_rejects_non_xcc_metered_grant() {
        let mut scope = baseline_scope(TENANT);
        scope.grants[0].max_cost_per_invocation = Some(MonetaryAmount {
            units: 1,
            currency: "USD".to_string(),
        });
        assert!(matches!(
            validate_pass_scope_is_baseline(&scope, TENANT),
            Err(KernelError::PassScopeInflation(_))
        ));
    }

    #[test]
    fn scope_rejects_zero_per_invocation_cost() {
        let mut scope = baseline_scope(TENANT);
        scope.grants[0].max_cost_per_invocation = Some(MonetaryAmount {
            units: 0,
            currency: PASS_ALLOTMENT_UNIT.to_string(),
        });
        assert!(matches!(
            validate_pass_scope_is_baseline(&scope, TENANT),
            Err(KernelError::PassScopeInflation(_))
        ));
    }

    #[test]
    fn scope_rejects_resource_grant_reordering() {
        let mut scope = baseline_scope(TENANT);
        scope.resource_grants.reverse();
        assert!(matches!(
            validate_pass_scope_is_baseline(&scope, TENANT),
            Err(KernelError::PassScopeInflation(_))
        ));
    }

    #[test]
    fn scope_rejects_widened_resource_operations() {
        let mut scope = baseline_scope(TENANT);
        scope.resource_grants[0].operations.push(Operation::Invoke);
        assert!(matches!(
            validate_pass_scope_is_baseline(&scope, TENANT),
            Err(KernelError::PassScopeInflation(_))
        ));
    }

    #[test]
    fn serving_gate_authorizes_each_gifted_stream_and_denies_out_of_scope() {
        let cap = pass_capability(baseline_scope(TENANT));
        for stream in ChioPassStream::ALL {
            // Pick a concrete URI inside each gifted pattern.
            let uri = match stream {
                ChioPassStream::ReputationTier => "chio://trust/reputation/tier/coarse".to_string(),
                ChioPassStream::MarketplaceListings => {
                    "chio://marketplace/listings/abc".to_string()
                }
                ChioPassStream::PheromoneConcentration => {
                    "chio://trust/pheromone/concentration/ns".to_string()
                }
                ChioPassStream::OwnReceipts => format!("chio://receipts/tenant/{TENANT}/r1"),
                ChioPassStream::OwnLineage => format!("chio://lineage/tenant/{TENANT}/n1"),
            };
            assert!(pass_authorizes_read(&cap, &uri).expect("read"));
            assert!(pass_authorizes_subscription(&cap, &uri).expect("subscribe"));
        }
        // A sibling tenant's receipts are out of scope.
        assert!(
            !pass_authorizes_read(&cap, "chio://receipts/tenant/did:chioabcde/r1")
                .expect("read other tenant")
        );
    }

    #[test]
    fn serving_gate_deny_list_wins_even_if_a_grant_matched() {
        // Even a cap whose scope nominally pattern-matches a deny-listed URI is
        // denied because the deny-list runs first.
        let scope = ChioScope {
            grants: vec![xcc_metered_grant()],
            resource_grants: vec![ResourceGrant {
                uri_pattern: "chio://market/*".to_string(),
                operations: vec![Operation::Read, Operation::Subscribe],
            }],
            prompt_grants: Vec::new(),
        };
        let cap = pass_capability(scope);
        assert!(!pass_authorizes_read(&cap, "chio://market/financials/spot").expect("read"));
        assert!(
            !pass_authorizes_subscription(&cap, "chio://market/financials/spot")
                .expect("subscribe")
        );
    }

    #[test]
    fn redaction_strips_all_economic_envelope_keys_and_stamps_summary() {
        let body = serde_json::json!({
            "capability_id": "chiopass:test",
            "metadata": {
                "financial": { "cost_charged": 42 },
                "budget_authority": { "authority": "x" },
                "cost": { "dimensions": [] },
                "trust_level": "mediated"
            }
        });
        let view = project_pass_stream_view(&body).expect("redacted view");
        let metadata = view
            .get("metadata")
            .and_then(|m| m.as_object())
            .expect("metadata object");
        assert!(!metadata.contains_key("financial"));
        assert!(!metadata.contains_key("budget_authority"));
        assert!(!metadata.contains_key("cost"));
        assert_eq!(
            metadata.get("trust_level").and_then(|v| v.as_str()),
            Some("mediated")
        );
        assert_eq!(
            view.get("redaction").and_then(|v| v.as_str()),
            Some("summary")
        );
    }

    #[test]
    fn redaction_allows_null_or_absent_metadata() {
        let null_meta = serde_json::json!({ "metadata": null });
        let view = project_pass_stream_view(&null_meta).expect("null metadata ok");
        assert_eq!(
            view.get("redaction").and_then(|v| v.as_str()),
            Some("summary")
        );

        let no_meta = serde_json::json!({ "capability_id": "chiopass:test" });
        let view = project_pass_stream_view(&no_meta).expect("absent metadata ok");
        assert_eq!(
            view.get("redaction").and_then(|v| v.as_str()),
            Some("summary")
        );
    }

    #[test]
    fn redaction_fails_closed_on_non_object_body_or_bad_metadata() {
        assert!(matches!(
            project_pass_stream_view(&serde_json::json!("not an object")),
            Err(KernelError::PassRedactionFailed(_))
        ));
        assert!(matches!(
            project_pass_stream_view(&serde_json::json!({ "metadata": ["not", "an", "object"] })),
            Err(KernelError::PassRedactionFailed(_))
        ));
    }

    #[test]
    fn receipt_read_context_is_tenant_scoped_without_null_tenant() {
        let ctx = pass_receipt_read_context(TENANT).expect("ctx");
        assert!(!ctx.include_null_tenant);
    }
}
