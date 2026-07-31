//! Chio Pass data-stream access gating.
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
//! boundary for the holder's own data. The disclosure binding is authoritative
//! (a bare metadata strip is never sufficient for the own streams): the
//! own-receipts/own-lineage gift (streams `3..=4`) MUST be emitted as a verified
//! [`DisclosureLineageBundle`], routed ONLY through
//! [`chio_disclosure_lineage::verify_disclosure_lineage_bundle`]. That artifact
//! is a lineage subgraph signed by a caller-pinned trusted key
//! bound to a transaction-passport ref, a verifier privacy profile, a MANDATORY
//! leakage ledger (present even when empty), a sha256 `tenant_hash` (never the
//! plaintext tenant), and accounted issuer-status / revocation-freshness /
//! presentation-timing derived facts. [`emit_own_data_gift_bundle`] is that
//! emission boundary; [`emit_pass_stream_gift`] is the per-stream dispatcher that
//! routes the two own streams through it and the three aggregate streams through
//! the redacted view.
//!
//! The raw `SiemEvent` receipt stream and any plaintext lineage walk are INTERNAL
//! selection steps only, never the emitted artifact. [`project_pass_stream_view`]
//! is likewise an INTERNAL whitelist-by-removal redaction step used ONLY for the
//! three aggregate streams; it is deliberately weaker than the disclosure layer
//! mandates, and a raw-stream or metadata-strip emission for the two own streams
//! fails closed.
//!
//! Naming note: `ChioPassStream` here is the gated data stream, distinct from the
//! `ChioPass` soulbound credential in `chio-credentials`.

use chio_core_types::capability::scope::{ChioScope, Operation, ResourceGrant, ToolGrant};
use chio_core_types::capability::token::{
    window_scoped_capability_id, AttestationWindowId, CapabilityToken,
    CHIO_PASS_CAPABILITY_ID_PREFIX,
};
use chio_core_types::crypto::SigningAlgorithm;
use chio_disclosure_lineage::{
    verify_disclosure_lineage_bundle_with_trust, DisclosureLeakageLedger, DisclosureLineageBundle,
    DisclosureLineageVerifierReport, DisclosureLineageVerifierTrust,
};

use crate::kernel::KernelError;
use crate::receipt_query::ReceiptReadContext;
use crate::request_matching::{
    capability_matches_resource_request, capability_matches_resource_subscription,
};

/// Tool-server id the metered XCC compute grant pins.
pub const PASS_COMPUTE_SERVER_ID: &str = "chio.pass.compute";

/// Private-use allotment unit the metered grant denominates. It is
/// intentionally never priced, so it carries no money leg.
pub const PASS_ALLOTMENT_UNIT: &str = "XCC";

/// Metering cost-metadata schema id stamped on free-tier receipts. Mirrors
/// `chio_metering::cost::COST_METADATA_SCHEMA`; the kernel must not depend on the
/// metering crate, so the literal is reproduced here (and cross-checked by tests).
pub const PASS_COST_METADATA_SCHEMA: &str = "chio.cost-metadata.v1";

/// Custom cost-dimension name the free-tier XCC allotment debit is recorded under
/// on served receipts. This MUST stay byte-identical to
/// `chio_credentials::CHIO_PASS_ALLOTMENT_COST_NAME` so the genuine-use
/// scan (which reads `metadata["cost"].dimensions[].name`) recognizes a real
/// metered Pass debit. The kernel cannot depend on `chio-credentials`, so the two
/// literals are kept in lockstep.
pub const PASS_ALLOTMENT_COST_NAME: &str = "chio.pass.allotment.v1";

/// Stamp the free-tier XCC allotment debit onto a served receipt's `metadata`.
///
/// Genuine-use binding: the scan recognizes a real metered Pass debit by
/// a `metadata["cost"].dimensions[]` entry whose `name == PASS_ALLOTMENT_COST_NAME`
/// and `value > 0`. A normal Pass invocation does not inject a custom `cost` block,
/// so without this the kernel-charged XCC debit would scan as non-genuine and the
/// refresh would withhold the next allotment despite actual usage. The allotment
/// dimension is APPENDED to an existing `cost.dimensions` array when present (never
/// clobbering tool-provided dimensions) and otherwise the `cost` block is created.
///
/// Fail-closed: a non-object `metadata`, or a `cost`/`dimensions` of the wrong JSON
/// shape, is replaced so the metadata still carries the allotment dimension; the
/// genuine-use signal is never silently dropped.
#[must_use]
pub fn stamp_pass_allotment_cost_dimension(
    metadata: Option<serde_json::Value>,
    allotment_units: u64,
) -> serde_json::Value {
    let dimension = serde_json::json!({
        "dimension": "custom",
        "name": PASS_ALLOTMENT_COST_NAME,
        "value": allotment_units,
        "unit": PASS_ALLOTMENT_UNIT,
    });
    let mut root = match metadata {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    let cost = root.entry("cost".to_string()).or_insert_with(
        || serde_json::json!({ "schema": PASS_COST_METADATA_SCHEMA, "dimensions": [] }),
    );
    if let Some(cost_obj) = cost.as_object_mut() {
        cost_obj
            .entry("schema".to_string())
            .or_insert_with(|| serde_json::Value::String(PASS_COST_METADATA_SCHEMA.to_string()));
        let dimensions = cost_obj
            .entry("dimensions".to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(array) = dimensions.as_array_mut() {
            array.push(dimension);
        } else {
            *dimensions = serde_json::Value::Array(vec![dimension]);
        }
    } else {
        *cost = serde_json::json!({
            "schema": PASS_COST_METADATA_SCHEMA,
            "dimensions": [dimension],
        });
    }
    serde_json::Value::Object(root)
}

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
/// allotment: `server_id == chio.pass.compute`, `tool_name == "*"`,
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

/// Build the [`KernelError::PassCapabilityIdNotDeterministic`] denial.
fn pass_id_not_deterministic(reason: &str) -> KernelError {
    KernelError::PassCapabilityIdNotDeterministic(reason.to_string())
}

/// True if any tool grant in `scope` is denominated in the private-use Pass
/// allotment unit ([`PASS_ALLOTMENT_UNIT`], `"XCC"`). This is the scope-shaped
/// Pass signal: a token carrying the XCC metered grant is a free-tier Pass even
/// when a non-canonical mint site stamped it with a UUIDv7 id.
fn scope_carries_xcc_metered_grant(scope: &ChioScope) -> bool {
    scope.grants.iter().any(|grant| {
        grant
            .max_cost_per_invocation
            .as_ref()
            .is_some_and(|amount| amount.currency == PASS_ALLOTMENT_UNIT)
            || grant
                .max_total_cost
                .as_ref()
                .is_some_and(|amount| amount.currency == PASS_ALLOTMENT_UNIT)
    })
}

/// The UTC calendar-month attestation window containing `issued_at`.
///
/// This mirrors `chio_credentials::attestation_window_containing` byte-for-byte
/// (same `window_ym`, `since`, and `until`) so the kernel admission assertion and
/// the credential-layer `verify_window_scoped_capability_id` recompute the same
/// id. The kernel must NOT depend on `chio-credentials`, so the derivation is
/// reproduced here against the same `chrono` primitives instead of being shared.
///
/// # Errors
///
/// Returns [`KernelError::PassCapabilityIdNotDeterministic`], fail-closed, on an
/// out-of-range timestamp or a month overflow.
fn pass_attestation_window(issued_at: u64) -> Result<AttestationWindowId, KernelError> {
    use chrono::{DateTime, Datelike, Months, TimeZone, Utc};

    let secs = i64::try_from(issued_at)
        .map_err(|_| pass_id_not_deterministic("issued_at is out of range"))?;
    let dt = DateTime::from_timestamp(secs, 0)
        .ok_or_else(|| pass_id_not_deterministic("issued_at is not a representable timestamp"))?;
    let month_start_naive = dt
        .date_naive()
        .with_day(1)
        .and_then(|day| day.and_hms_opt(0, 0, 0))
        .ok_or_else(|| pass_id_not_deterministic("attestation month start is not representable"))?;
    let month_start = Utc.from_utc_datetime(&month_start_naive);
    let next_month = month_start
        .checked_add_months(Months::new(1))
        .ok_or_else(|| pass_id_not_deterministic("attestation month overflowed"))?;
    let since = u64::try_from(month_start.timestamp())
        .map_err(|_| pass_id_not_deterministic("window since is out of range"))?;
    let until = u64::try_from(next_month.timestamp())
        .map_err(|_| pass_id_not_deterministic("window until is out of range"))?;
    Ok(AttestationWindowId {
        window_ym: month_start.format("%Y-%m").to_string(),
        since,
        until,
    })
}

/// Kernel admission assertion: a Pass-shaped capability MUST carry the
/// deterministic, window-scoped `chiopass:<hash>` id.
///
/// A capability is Pass-shaped when EITHER its id carries the
/// [`CHIO_PASS_CAPABILITY_ID_PREFIX`] OR its scope carries the XCC metered grant
/// (the free-tier compute allotment). For any Pass-shaped capability this asserts,
/// fail-closed, that:
///
/// 1. the id carries the `chiopass:` prefix (so a token whose scope is Pass-shaped
///    but whose id is a UUIDv7 is rejected, closing the three other UUIDv7 mint
///    sites at `chio-kernel`, `chio-store-sqlite`, and `chio-http-core`);
/// 2. the subject is an ed25519 `did:chio` key (the only key the canonical id
///    derives from);
/// 3. `issued_at`/`expires_at` are pinned to the attestation-window boundaries
///    derived from `issued_at`; and
/// 4. the id equals the canonical [`window_scoped_capability_id`] recomputed from
///    the token's OWN subject DID and that window.
///
/// This closes the loophole where another mint site could stamp a non-canonical id
/// on a Pass-shaped capability and so open a fresh `(capability_id, 0)` budget row
/// that resets the free-tier counter. The recompute mirrors the credential-layer
/// `chio_credentials::verify_window_scoped_capability_id`; because the kernel
/// cannot depend on `chio-credentials`, it derives the canonical `did:chio` as
/// `did:chio:<subject hex>` (identical to `DidChio::from_public_key(..).to_string()`)
/// and the window from `issued_at`, against the same shared
/// [`window_scoped_capability_id`] formula, so both layers agree byte-for-byte.
/// A capability that is NOT Pass-shaped is admitted unchanged.
///
/// # Errors
///
/// Returns [`KernelError::PassCapabilityIdNotDeterministic`] on any mismatch.
pub fn assert_pass_capability_id_deterministic(cap: &CapabilityToken) -> Result<(), KernelError> {
    let id_is_pass_shaped = cap.id.starts_with(CHIO_PASS_CAPABILITY_ID_PREFIX);
    let scope_is_pass_shaped = scope_carries_xcc_metered_grant(&cap.scope);
    if !id_is_pass_shaped && !scope_is_pass_shaped {
        // Not a Pass capability: existing admission behavior is unchanged.
        return Ok(());
    }

    if !id_is_pass_shaped {
        return Err(pass_id_not_deterministic(
            "a capability carrying the XCC metered grant must use the deterministic chiopass: id",
        ));
    }

    if cap.subject.algorithm() != SigningAlgorithm::Ed25519 {
        return Err(pass_id_not_deterministic(
            "Pass capability subject must be an ed25519 did:chio key",
        ));
    }
    let subject_did = format!("did:chio:{}", cap.subject.to_hex());

    let window = pass_attestation_window(cap.issued_at)?;
    if cap.issued_at != window.since {
        return Err(pass_id_not_deterministic(
            "Pass issued_at is not pinned to its attestation-window start",
        ));
    }
    if cap.expires_at != window.until {
        return Err(pass_id_not_deterministic(
            "Pass expires_at is not pinned to its attestation-window boundary",
        ));
    }

    let expected = window_scoped_capability_id(&subject_did, &window)
        .map_err(|error| KernelError::PassCapabilityIdNotDeterministic(error.to_string()))?;
    if cap.id != expected {
        return Err(pass_id_not_deterministic(
            "Pass capability id is not the canonical window-scoped id",
        ));
    }

    // Admission-side mirror of the mint-choke scope check: a Pass admitted here
    // must still carry EXACTLY the canonical baseline scope (one metered XCC
    // grant, the five baseline resource grants, no prompt grants). The mint choke
    // is the primary defense; re-running the predicate at admission means a Pass
    // signed by any other trusted-authority path, or narrowed via delegation,
    // cannot smuggle an inflated (or attenuated, hence non-canonical) scope past
    // the id equality above. Soulbound Passes have no legitimate delegated or
    // reshaped form, so any deviation denies fail-closed.
    validate_pass_scope_is_baseline(&cap.scope, &subject_did)?;
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
/// the genuine-use scan reads the STORED receipt directly, so stripping
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

/// The crypto-context derived facts the own-data gift MUST account in its leakage
/// ledger, even when the holder discloses no receipt field. These bind issuer
/// status, revocation freshness, and presentation timing into the emitted
/// artifact. The kernel enforces all three UNCONDITIONALLY; the upstream verifier
/// only requires them when the bundle discloses a field or hidden predicate, so
/// this is a deliberate strengthening for the always-on own-data gift.
pub const PASS_OWN_DATA_REQUIRED_DERIVED_FACTS: [&str; 3] = [
    "derived.crypto.issuer_status",
    "derived.crypto.revocation_freshness",
    "derived.crypto.presentation_timing",
];

/// The emitted artifact for one gifted Pass stream.
///
/// The three aggregate streams emit a redacted summary VIEW (the internal 3-key
/// strip). The two OWN streams emit the VERIFIED [`DisclosureLineageBundle`] (the
/// gifted own data the holder can actually receive) PLUS its verifier report, and
/// NOTHING weaker. The report alone carries only refs and counts (not the receipt
/// or lineage nodes), so a serving path wired through this dispatcher would be
/// unable to emit the gifted own data from the report alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassStreamGift {
    /// Streams `0..=2` (reputation tier, marketplace listings, pheromone
    /// concentration): a redacted summary view.
    AggregateView(serde_json::Value),
    /// Streams `3..=4` (own receipts, own lineage): the verified
    /// disclosure-lineage bundle the holder receives, paired with its verifier
    /// report.
    OwnDataBundle {
        /// The verified bundle: the pinned-key signed lineage subgraph, privacy
        /// profile, and mandatory leakage ledger bound to the holder tenant hash.
        bundle: Box<DisclosureLineageBundle>,
        /// The verifier report (refs, counts, and accounted derived facts).
        report: Box<DisclosureLineageVerifierReport>,
    },
}

/// The INTERNAL selection that feeds a Pass stream emission.
///
/// For aggregate streams it is the served receipt/listing VIEW body; for OWN
/// streams it is the verified disclosure-lineage bundle. Supplying an aggregate
/// body for an OWN stream (the raw `SiemEvent` stream or the weaker 3-key strip)
/// is rejected fail-closed: the OWN gift boundary is the bundle and nothing
/// weaker.
pub enum PassStreamSelection<'a> {
    /// A served receipt/listing VIEW body (aggregate streams only).
    AggregateBody(&'a serde_json::Value),
    /// A verified disclosure-lineage bundle (OWN streams only).
    OwnDataBundle(&'a DisclosureLineageBundle),
}

/// Per-stream emission dispatcher. Routes the two OWN streams through the
/// verified [`DisclosureLineageBundle`] boundary and the three aggregate streams
/// through the redacted view. Fail-closed: an OWN stream fed a raw/3-key-strip
/// body is denied, and an aggregate stream fed a bundle is denied.
///
/// # Errors
///
/// Returns [`KernelError::PassOwnDataGiftInvalid`] when an OWN stream is not
/// emitted as a verified bundle (or the bundle/tenant binding is invalid),
/// [`KernelError::PassTenantBindingInvalid`] when `subject_tenant` is empty,
/// wildcarded, or path-delimited, and [`KernelError::PassRedactionFailed`] on an
/// aggregate-view redaction failure or a bundle supplied for an aggregate stream.
pub fn emit_pass_stream_gift(
    stream: ChioPassStream,
    subject_tenant: &str,
    selection: PassStreamSelection<'_>,
    trust: &DisclosureLineageVerifierTrust,
) -> Result<PassStreamGift, KernelError> {
    match (stream.is_own_tenant(), selection) {
        (true, PassStreamSelection::OwnDataBundle(bundle)) => {
            let report = emit_own_data_gift_bundle(stream, subject_tenant, bundle, trust)?;
            // Return the VERIFIED bundle (the gifted own data the holder receives)
            // alongside its report, so a serving path wired through this
            // dispatcher can actually emit the own receipts/lineage rather than
            // only a refs-and-counts summary.
            Ok(PassStreamGift::OwnDataBundle {
                bundle: Box::new(bundle.clone()),
                report: Box::new(report),
            })
        }
        (true, PassStreamSelection::AggregateBody(_)) => Err(KernelError::PassOwnDataGiftInvalid(
            "own receipts and own lineage must be emitted as a verified \
                 DisclosureLineageBundle, never the raw stream or the 3-key strip view"
                .to_string(),
        )),
        (false, PassStreamSelection::AggregateBody(body)) => Ok(PassStreamGift::AggregateView(
            project_pass_stream_view(body)?,
        )),
        (false, PassStreamSelection::OwnDataBundle(_)) => Err(KernelError::PassRedactionFailed(
            "aggregate streams are not emitted as disclosure-lineage bundles".to_string(),
        )),
    }
}

/// Emit the OWN-data gift (streams `3..=4`) as a verified [`DisclosureLineageBundle`].
///
/// This is the disclosed-artifact boundary for the holder's own receipts and own
/// lineage. The bundle is routed ONLY through
/// [`chio_disclosure_lineage::verify_disclosure_lineage_bundle_with_trust`]: the
/// caller pins the trusted lineage-signer set (empty trust verifies nothing,
/// fail-closed) and the subgraph must be signed by a pinned key and bound to a
/// transaction-passport ref, a verifier privacy profile, and a mandatory leakage
/// ledger. On TOP of the verifier, the kernel binds, fail-closed:
///
/// 1. the stream is one of the two OWN streams (receipts, lineage);
/// 2. the holder tenant is carried ONLY as a sha256 `tenant_hash`: every lineage
///    node's `tenant_hash` equals `sha256(subject_tenant)` and the plaintext
///    tenant appears nowhere in the emitted bundle;
/// 3. the mandatory leakage ledger is present and accepted; and
/// 4. the three [`PASS_OWN_DATA_REQUIRED_DERIVED_FACTS`] (issuer status,
///    revocation freshness, presentation timing) are accounted in that ledger,
///    even when the bundle discloses no receipt field.
///
/// # Errors
///
/// Returns [`KernelError::PassOwnDataGiftInvalid`] on any verifier failure or
/// missing/invalid binding, and [`KernelError::PassTenantBindingInvalid`] when
/// `subject_tenant` is empty, wildcarded, or path-delimited. It never panics.
pub fn emit_own_data_gift_bundle(
    stream: ChioPassStream,
    subject_tenant: &str,
    bundle: &DisclosureLineageBundle,
    trust: &DisclosureLineageVerifierTrust,
) -> Result<DisclosureLineageVerifierReport, KernelError> {
    if !stream.is_own_tenant() {
        return Err(KernelError::PassOwnDataGiftInvalid(
            "the verified-bundle gift boundary is only for own receipts and own lineage"
                .to_string(),
        ));
    }
    let tenant = validated_tenant(subject_tenant)?;
    // The pinned-key signed subgraph, verifier privacy profile, leakage ledger,
    // and crypto-context report are all verified here. Any failure denies.
    let report = verify_disclosure_lineage_bundle_with_trust(bundle, trust)
        .map_err(|error| KernelError::PassOwnDataGiftInvalid(error.to_string()))?;
    bind_own_data_bundle_to_tenant(bundle, tenant)?;
    require_own_data_leakage_ledger(&bundle.leakage_ledger)?;
    Ok(report)
}

/// Binds the verified bundle to the holder by hashed tenant, fail-closed. Every
/// lineage node MUST carry `sha256(tenant)` as its `tenant_hash`, and the
/// plaintext tenant MUST appear nowhere in the serialized bundle.
fn bind_own_data_bundle_to_tenant(
    bundle: &DisclosureLineageBundle,
    tenant: &str,
) -> Result<(), KernelError> {
    let expected_tenant_hash = chio_core_types::sha256_hex(tenant.as_bytes());
    for node in &bundle.lineage.nodes {
        if node.tenant_hash != expected_tenant_hash {
            return Err(KernelError::PassOwnDataGiftInvalid(format!(
                "own-data lineage node {} is not bound to the holder tenant hash",
                node.id
            )));
        }
    }
    let serialized = serde_json::to_string(bundle).map_err(|error| {
        KernelError::PassOwnDataGiftInvalid(format!("own-data bundle is not serializable: {error}"))
    })?;
    if serialized.contains(tenant) {
        return Err(KernelError::PassOwnDataGiftInvalid(
            "own-data bundle leaks the plaintext tenant; only the sha256 tenant hash may appear"
                .to_string(),
        ));
    }
    Ok(())
}

/// Affirms the MANDATORY leakage ledger and its accounted runtime-assurance
/// facts, fail-closed. The ledger struct is structurally mandatory; this also
/// requires it accepted and the three [`PASS_OWN_DATA_REQUIRED_DERIVED_FACTS`]
/// accounted even when nothing is disclosed.
fn require_own_data_leakage_ledger(ledger: &DisclosureLeakageLedger) -> Result<(), KernelError> {
    if !ledger.accepted {
        return Err(KernelError::PassOwnDataGiftInvalid(
            "own-data leakage ledger is not accepted by policy".to_string(),
        ));
    }
    for fact in PASS_OWN_DATA_REQUIRED_DERIVED_FACTS {
        let accounted = ledger.entries.iter().any(|entry| {
            entry.field == fact && entry.leakage_kind == "derived_fact" && entry.allowed_by_profile
        });
        if !accounted {
            return Err(KernelError::PassOwnDataGiftInvalid(format!(
                "own-data leakage ledger is missing the accounted derived fact: {fact}"
            )));
        }
    }
    Ok(())
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

    // 2026-06-01T00:00:00Z and 2026-07-01T00:00:00Z (real UTC month boundaries),
    // matching the credential-layer window so the recomputed id agrees.
    const JUNE_SINCE: u64 = 1_780_272_000;
    const JULY_SINCE: u64 = 1_782_864_000;

    fn june_window() -> AttestationWindowId {
        AttestationWindowId {
            window_ym: "2026-06".to_string(),
            since: JUNE_SINCE,
            until: JULY_SINCE,
        }
    }

    fn signed_token(
        id: String,
        subject: &Keypair,
        scope: ChioScope,
        issued_at: u64,
        expires_at: u64,
    ) -> CapabilityToken {
        let issuer = Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id,
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope,
                issued_at,
                expires_at,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .expect("sign capability")
    }

    #[test]
    fn admission_accepts_canonical_window_scoped_pass_id() {
        let subject = Keypair::generate();
        let subject_did = format!("did:chio:{}", subject.public_key().to_hex());
        let window = june_window();
        let id = window_scoped_capability_id(&subject_did, &window).expect("id");
        // The mint choke builds the baseline against the subject DID itself, so a
        // mint-shaped fixture must bind its own-data URIs to the same DID.
        let token = signed_token(
            id,
            &subject,
            baseline_scope(&subject_did),
            window.since,
            window.until,
        );
        assert!(assert_pass_capability_id_deterministic(&token).is_ok());
    }

    #[test]
    fn admission_rejects_pass_scope_that_is_not_the_canonical_baseline() {
        let subject = Keypair::generate();
        let subject_did = format!("did:chio:{}", subject.public_key().to_hex());
        let window = june_window();
        let id = window_scoped_capability_id(&subject_did, &window).expect("id");

        // Inflated: one resource grant beyond the canonical baseline.
        let mut inflated = baseline_scope(&subject_did);
        inflated.resource_grants.push(ResourceGrant {
            uri_pattern: "chio://receipts/*".to_string(),
            operations: vec![Operation::Read],
        });
        let token = signed_token(id.clone(), &subject, inflated, window.since, window.until);
        assert!(matches!(
            assert_pass_capability_id_deterministic(&token),
            Err(KernelError::PassScopeInflation(_))
        ));

        // Attenuated: one baseline resource grant removed. A narrowed Pass is
        // still non-canonical and denies (soulbound Passes have no reshaped form).
        let mut attenuated = baseline_scope(&subject_did);
        attenuated.resource_grants.pop();
        let token = signed_token(id, &subject, attenuated, window.since, window.until);
        assert!(matches!(
            assert_pass_capability_id_deterministic(&token),
            Err(KernelError::PassScopeInflation(_))
        ));
    }

    #[test]
    fn admission_rejects_chiopass_id_that_is_not_canonical() {
        let subject = Keypair::generate();
        let window = june_window();
        let token = signed_token(
            "chiopass:0000".to_string(),
            &subject,
            baseline_scope(TENANT),
            window.since,
            window.until,
        );
        assert!(matches!(
            assert_pass_capability_id_deterministic(&token),
            Err(KernelError::PassCapabilityIdNotDeterministic(_))
        ));
    }

    #[test]
    fn admission_rejects_uuid_id_bearing_the_xcc_metered_grant() {
        // A non-canonical (UUIDv7) mint site stamped an XCC Pass scope. The
        // missing chiopass: prefix is rejected at admission, closing the three
        // other mint sites (chio-kernel/chio-store-sqlite/chio-http-core).
        let subject = Keypair::generate();
        let window = june_window();
        let token = signed_token(
            "cap-018f-7a3c-uuidv7".to_string(),
            &subject,
            baseline_scope(TENANT),
            window.since,
            window.until,
        );
        assert!(matches!(
            assert_pass_capability_id_deterministic(&token),
            Err(KernelError::PassCapabilityIdNotDeterministic(_))
        ));
    }

    #[test]
    fn admission_rejects_window_boundary_drift() {
        let subject = Keypair::generate();
        let subject_did = format!("did:chio:{}", subject.public_key().to_hex());
        let window = june_window();
        let id = window_scoped_capability_id(&subject_did, &window).expect("id");
        // expires_at is not pinned to the attestation-window boundary.
        let token = signed_token(
            id,
            &subject,
            baseline_scope(TENANT),
            window.since,
            window.until + 1,
        );
        assert!(matches!(
            assert_pass_capability_id_deterministic(&token),
            Err(KernelError::PassCapabilityIdNotDeterministic(_))
        ));
    }

    #[test]
    fn allotment_cost_name_matches_credential_layer_literal() {
        // The kernel-stamped dimension name MUST stay byte-identical
        // to the credential-layer constant the genuine-use scan keys on.
        assert_eq!(PASS_ALLOTMENT_COST_NAME, "chio.pass.allotment.v1");
        assert_eq!(PASS_COST_METADATA_SCHEMA, "chio.cost-metadata.v1");
    }

    #[test]
    fn stamp_allotment_dimension_creates_cost_block_when_absent() {
        // A normal Pass invocation carries no custom `cost` block;
        // the stamp must create one so the genuine-use scan recognizes the debit.
        let stamped = stamp_pass_allotment_cost_dimension(None, 7);
        let dimensions = stamped
            .get("cost")
            .and_then(|cost| cost.get("dimensions"))
            .and_then(serde_json::Value::as_array)
            .expect("cost.dimensions array");
        assert_eq!(dimensions.len(), 1);
        let dim = &dimensions[0];
        assert_eq!(
            dim.get("name").and_then(serde_json::Value::as_str),
            Some(PASS_ALLOTMENT_COST_NAME)
        );
        assert_eq!(
            dim.get("value").and_then(serde_json::Value::as_u64),
            Some(7)
        );
        assert_eq!(
            dim.get("unit").and_then(serde_json::Value::as_str),
            Some(PASS_ALLOTMENT_UNIT)
        );
        assert_eq!(
            dim.get("dimension").and_then(serde_json::Value::as_str),
            Some("custom")
        );
    }

    #[test]
    fn stamp_allotment_dimension_appends_without_clobbering_existing() {
        // An existing financial block and a pre-existing cost dimension must both
        // survive: the allotment dimension is appended, not overwritten.
        let existing = serde_json::json!({
            "financial": { "cost_charged": 0, "currency": "XCC" },
            "cost": {
                "schema": PASS_COST_METADATA_SCHEMA,
                "dimensions": [
                    { "dimension": "custom", "name": "other.metric.v1", "value": 3, "unit": "x" }
                ]
            }
        });
        let stamped = stamp_pass_allotment_cost_dimension(Some(existing), 5);
        assert!(stamped.get("financial").is_some(), "financial preserved");
        let dimensions = stamped
            .get("cost")
            .and_then(|cost| cost.get("dimensions"))
            .and_then(serde_json::Value::as_array)
            .expect("cost.dimensions array");
        assert_eq!(
            dimensions.len(),
            2,
            "existing dimension preserved, allotment appended"
        );
        assert!(dimensions.iter().any(|dim| {
            dim.get("name").and_then(serde_json::Value::as_str) == Some("other.metric.v1")
        }));
        assert!(dimensions.iter().any(|dim| {
            dim.get("name").and_then(serde_json::Value::as_str) == Some(PASS_ALLOTMENT_COST_NAME)
                && dim.get("value").and_then(serde_json::Value::as_u64) == Some(5)
        }));
    }

    #[test]
    fn admission_leaves_non_pass_capability_unaffected() {
        // A USD tool grant under a UUIDv7 id: Pass-shaped by neither id nor scope.
        let subject = Keypair::generate();
        let usd_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "svc".to_string(),
                tool_name: "*".to_string(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 1,
                    currency: "USD".to_string(),
                }),
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };
        let token = signed_token(
            "cap-018f-7a3c-uuidv7".to_string(),
            &subject,
            usd_scope,
            100,
            200,
        );
        assert!(assert_pass_capability_id_deterministic(&token).is_ok());
    }

    // -- Own-data gift as a verified DisclosureLineageBundle -------------------

    use chio_core_types::sha256_hex;
    use chio_disclosure_lineage::{
        compute_signed_lineage_subgraph_digest, sign_crypto_context_report, sign_lineage_subgraph,
        DisclosureCapsule, DisclosureContextVerdict, DisclosureCryptoContextReport,
        DisclosureHiddenPredicate, DisclosureLeakageLedgerEntry, DisclosureProfileLeakageBudget,
        DisclosureSensitivityClass, DisclosureSignedLineageEdge, DisclosureSignedLineageNode,
        DisclosureSignedLineageRedaction, DisclosureVerifierPrivacyProfile, SignedLineageSubgraph,
        TransparencyState, DISCLOSURE_CAPSULE_SCHEMA_V1,
        DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1, DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1,
        DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1, LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1,
    };

    /// The test lineage-signer keypair (seed `[29u8; 32]`), pinned into the
    /// verifier trust by [`lineage_trust`].
    fn lineage_signer() -> Keypair {
        Keypair::from_seed(&[29u8; 32])
    }

    fn lineage_trust() -> DisclosureLineageVerifierTrust {
        let key = lineage_signer().public_key();
        DisclosureLineageVerifierTrust::new()
            .with_trusted_lineage_signer_keys(vec![key.clone()])
            .with_trusted_crypto_context_report_signer_keys(vec![key])
    }

    fn digest(value: &str) -> String {
        sha256_hex(value.as_bytes())
    }

    fn lineage_frontier_digest(node_id: &str, artifact_sha256: &str, depth: u32) -> String {
        digest(&format!("{node_id}:{artifact_sha256}:{depth}"))
    }

    fn leakage_entry(
        entry_id: &str,
        field: &str,
        leakage_kind: &str,
        sensitivity_class: &str,
        score: u32,
        residual_inference_note: Option<&str>,
    ) -> DisclosureLeakageLedgerEntry {
        DisclosureLeakageLedgerEntry {
            entry_id: entry_id.to_string(),
            source: "disclosure-capsule".to_string(),
            field: field.to_string(),
            leakage_kind: leakage_kind.to_string(),
            disclosure_kind: leakage_kind.to_string(),
            sensitivity_class: sensitivity_class.to_string(),
            value_class: "identifier_or_predicate".to_string(),
            reason: "required by disclosure profile".to_string(),
            policy_rule: "profile.allowed_disclosure".to_string(),
            derived_inferences: Vec::new(),
            cross_tenant_risk: false,
            mitigation: None,
            score,
            allowed_by_profile: true,
            residual_inference_note: residual_inference_note.map(str::to_string),
        }
    }

    fn amount_cap_hidden_predicate() -> DisclosureHiddenPredicate {
        DisclosureHiddenPredicate {
            predicate_id: "amount_lte_100".to_string(),
            kind: "amount_cap".to_string(),
            field: "amount".to_string(),
            operator: "<=".to_string(),
            operand: "100".to_string(),
            unit: "USD".to_string(),
            result: true,
            proof_ref: "selective-disclosure-proof".to_string(),
            projection_slot: 2,
        }
    }

    /// The three runtime-assurance leakage entries every own-data ledger accounts.
    fn runtime_assurance_entries() -> Vec<DisclosureLeakageLedgerEntry> {
        vec![
            leakage_entry(
                "leakage-derived-issuer-status",
                "derived.crypto.issuer_status",
                "derived_fact",
                "runtime_assurance",
                1,
                None,
            ),
            leakage_entry(
                "leakage-derived-revocation-freshness",
                "derived.crypto.revocation_freshness",
                "derived_fact",
                "runtime_assurance",
                1,
                None,
            ),
            leakage_entry(
                "leakage-derived-presentation-timing",
                "derived.crypto.presentation_timing",
                "derived_fact",
                "timing",
                1,
                None,
            ),
        ]
    }

    /// A fully-valid own-data [`DisclosureLineageBundle`] whose lineage nodes are
    /// bound to `tenant` by its sha256 `tenant_hash` (never the plaintext tenant).
    /// Modeled on the shipped disclosure-lineage fixture and signed with the
    /// pinned trusted lineage signer.
    fn own_data_bundle(tenant: &str) -> DisclosureLineageBundle {
        let tenant_hash = sha256_hex(tenant.as_bytes());
        let capsule = DisclosureCapsule {
            schema: DISCLOSURE_CAPSULE_SCHEMA_V1.to_string(),
            id: "disclosure-capsule-own".to_string(),
            transaction_passport_ref: "passport-own-data".to_string(),
            crypto_context_report_ref: "crypto-context-report-own".to_string(),
            projection_manifest_ref: "bbs-projection-manifest-own".to_string(),
            privacy_profile_ref: "privacy-profile-own".to_string(),
            lineage_subgraph_ref: "lineage-subgraph-own".to_string(),
            leakage_ledger_ref: "leakage-ledger-own".to_string(),
            disclosed_fields: vec!["capability_id".to_string(), "tool_name".to_string()],
            hidden_predicates: vec![amount_cap_hidden_predicate()],
        };
        let privacy_profile = DisclosureVerifierPrivacyProfile {
            schema: DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1.to_string(),
            profile_id: "privacy-profile-own".to_string(),
            allowed_proof_mechanisms: vec!["bbs".to_string()],
            required_holder_binding: Some("holder:own-data-agent".to_string()),
            transaction_passport_ref: "passport-own-data".to_string(),
            leakage_budget: DisclosureProfileLeakageBudget {
                max_disclosed_fields: 2,
                max_hidden_predicates: 1,
            },
            sensitivity_classes: vec![
                DisclosureSensitivityClass {
                    class_id: "capability_identifier".to_string(),
                    fields: vec!["capability_id".to_string()],
                },
                DisclosureSensitivityClass {
                    class_id: "tool_identity".to_string(),
                    fields: vec!["tool_name".to_string()],
                },
                DisclosureSensitivityClass {
                    class_id: "amount_or_budget".to_string(),
                    fields: vec!["amount_lte_100".to_string()],
                },
                DisclosureSensitivityClass {
                    class_id: "runtime_assurance".to_string(),
                    fields: vec![
                        "derived.crypto.issuer_status".to_string(),
                        "derived.crypto.revocation_freshness".to_string(),
                    ],
                },
                DisclosureSensitivityClass {
                    class_id: "timing".to_string(),
                    fields: vec!["derived.crypto.presentation_timing".to_string()],
                },
            ],
            allowed_issuer_keys: vec![
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            ],
            required_key_epoch_min: 7,
            forbidden_key_epochs: vec![9],
            required_status_freshness_seconds: 300,
            required_audience: "https://auditor.example/chio".to_string(),
            nonce_policy: "no_replay".to_string(),
            allowed_algorithms: vec!["bbs-bls12381-sha256".to_string()],
            forbidden_algorithms: vec!["rsa-pkcs1v15-sha1".to_string()],
            required_transparency_state: TransparencyState::Anchored,
            max_presentation_age_seconds: 600,
            allowed_disclosed_fields: vec!["capability_id".to_string(), "tool_name".to_string()],
            forbidden_disclosed_fields: vec!["customer_email".to_string()],
            allowed_hidden_predicates: vec!["amount_lte_100".to_string()],
            forbidden_hidden_predicates: vec!["raw_amount".to_string()],
        };
        let frontier_sha256 = lineage_frontier_digest("receipt-child", &digest("receipt-child"), 1);
        let checkpoint_ref = "checkpoint-own-data".to_string();
        let mut lineage = SignedLineageSubgraph {
            schema: LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1.to_string(),
            id: "lineage-subgraph-own".to_string(),
            transaction_passport_ref: "passport-own-data".to_string(),
            policy_profile_id: "privacy-profile-own".to_string(),
            generated_at: "2026-06-10T00:00:00Z".to_string(),
            audience: "https://auditor.example/chio".to_string(),
            challenge_nonce: "own-data-fixture-nonce".to_string(),
            frontier_sha256: frontier_sha256.clone(),
            checkpoint_ref: checkpoint_ref.clone(),
            checkpoint_inclusion_sha256: digest(&format!("{checkpoint_ref}|{frontier_sha256}")),
            max_depth: 1,
            required_evidence_class: "observed".to_string(),
            lineage_anchor_ref: "lineage-anchor-own-fixture".to_string(),
            redaction_map_sha256: digest("receipt-child|privacy_profile"),
            leakage_ledger_sha256: digest("leakage-ledger-own"),
            projection_manifest_sha256: digest("bbs-projection-manifest-own"),
            root_receipt_ids: vec!["receipt-root".to_string()],
            nodes: vec![
                DisclosureSignedLineageNode {
                    id: "receipt-root".to_string(),
                    kind: "receipt".to_string(),
                    receipt_ref: "receipt-root".to_string(),
                    artifact_sha256: digest("receipt-root"),
                    artifact_schema: "chio.receipt.v1".to_string(),
                    evidence_class: "observed".to_string(),
                    tenant_hash: tenant_hash.clone(),
                    source_table: "receipts".to_string(),
                    source_id_hash: digest("receipt-root"),
                    depth: 0,
                    parent_ids: Vec::new(),
                    disclosure_state: "disclosed".to_string(),
                },
                DisclosureSignedLineageNode {
                    id: "receipt-child".to_string(),
                    kind: "receipt_lineage_statement".to_string(),
                    receipt_ref: "receipt-child".to_string(),
                    artifact_sha256: digest("receipt-child"),
                    artifact_schema: "chio.receipt-lineage-statement.v1".to_string(),
                    evidence_class: "derived".to_string(),
                    tenant_hash: tenant_hash.clone(),
                    source_table: "receipt_lineage_statements".to_string(),
                    source_id_hash: digest("receipt-child"),
                    depth: 1,
                    parent_ids: vec!["receipt-root".to_string()],
                    disclosure_state: "redacted".to_string(),
                },
            ],
            edges: vec![DisclosureSignedLineageEdge {
                edge_id: "edge-receipt-root-receipt-child".to_string(),
                from: "receipt-root".to_string(),
                to: "receipt-child".to_string(),
                relation: "continued".to_string(),
                kind: "continued_by".to_string(),
                evidence_class: "observed".to_string(),
                source_artifact_sha256: digest("edge-receipt-root-receipt-child"),
                statement_sha256: digest("receipt-root|receipt-child|continued_by"),
                disclosure_state: "disclosed".to_string(),
            }],
            redactions: vec![DisclosureSignedLineageRedaction {
                node_id: "receipt-child".to_string(),
                reason: "privacy_profile".to_string(),
            }],
            subgraph_sha256: String::new(),
            signature: String::new(),
        };
        lineage.subgraph_sha256 =
            compute_signed_lineage_subgraph_digest(&lineage).expect("subgraph digest");
        lineage.signature =
            sign_lineage_subgraph(&lineage, &lineage_signer()).expect("lineage signature");
        let mut entries = vec![
            leakage_entry(
                "leakage-capability-id",
                "capability_id",
                "disclosed_field",
                "capability_identifier",
                1,
                None,
            ),
            leakage_entry(
                "leakage-tool-name",
                "tool_name",
                "disclosed_field",
                "tool_identity",
                1,
                None,
            ),
            leakage_entry(
                "leakage-amount-cap",
                "amount_lte_100",
                "hidden_predicate",
                "amount_or_budget",
                2,
                Some("predicate reveals capped amount band"),
            ),
        ];
        entries.extend(runtime_assurance_entries());
        let leakage_ledger = DisclosureLeakageLedger {
            schema: DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1.to_string(),
            id: "leakage-ledger-own".to_string(),
            transaction_passport_ref: "passport-own-data".to_string(),
            privacy_profile_ref: "privacy-profile-own".to_string(),
            policy_profile_id: "privacy-profile-own".to_string(),
            subject_artifact_sha256: digest("disclosure-capsule-own"),
            generated_at: "2026-06-10T00:00:00Z".to_string(),
            audience: "https://auditor.example/chio".to_string(),
            total_leakage_score: 7,
            max_allowed_leakage_score: 7,
            tenant_leakage_notice_ref: "tenant-leakage-notice-none".to_string(),
            accepted: true,
            entries,
        };
        let mut crypto_context_report = DisclosureCryptoContextReport {
            schema: DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1.to_string(),
            id: "crypto-context-report-own".to_string(),
            context_id: "crypto-context-own".to_string(),
            artifact_ref: "disclosure-capsule-own".to_string(),
            projection_manifest_ref: "bbs-projection-manifest-own".to_string(),
            verdict: DisclosureContextVerdict::Verified,
            evidence_class: "verifier_context".to_string(),
            cryptographic_proof_verified: true,
            verified_claims: vec![
                "claim.disclosure.crypto_context_bound".to_string(),
                "claim.disclosure.profile_context_policy_enforced".to_string(),
            ],
            rejected_checks: Vec::new(),
            disclosed_fields: vec!["capability_id".to_string(), "tool_name".to_string()],
            signature: None,
        };
        crypto_context_report.signature = Some(
            sign_crypto_context_report(&crypto_context_report, &lineage_signer()).expect("sig"),
        );
        DisclosureLineageBundle {
            capsule,
            privacy_profile,
            lineage,
            leakage_ledger,
            crypto_context_report: Some(crypto_context_report),
        }
    }

    #[test]
    fn own_data_gift_emits_verified_bundle_for_both_own_streams() {
        let bundle = own_data_bundle(TENANT);
        for stream in [ChioPassStream::OwnReceipts, ChioPassStream::OwnLineage] {
            let report = emit_own_data_gift_bundle(stream, TENANT, &bundle, &lineage_trust())
                .expect("own-data gift verifies");
            assert_eq!(report.verdict, "verified");
            assert_eq!(report.transaction_passport_ref, "passport-own-data");

            // Routed through the per-stream dispatcher it yields the bundle gift:
            // the VERIFIED bundle (the emittable own data) AND its report.
            let gift = emit_pass_stream_gift(
                stream,
                TENANT,
                PassStreamSelection::OwnDataBundle(&bundle),
                &lineage_trust(),
            )
            .expect("dispatcher emits bundle");
            let PassStreamGift::OwnDataBundle {
                bundle: emitted_bundle,
                report: emitted_report,
            } = gift
            else {
                panic!("own streams must emit the verified bundle gift");
            };
            // The gift carries the full verified bundle (lineage nodes included),
            // not only the refs-and-counts report.
            assert_eq!(*emitted_bundle, bundle);
            assert_eq!(emitted_report.verdict, "verified");
        }
    }

    #[test]
    fn own_data_raw_stream_or_three_key_strip_emission_fails() {
        // The raw SiemEvent receipt body and the 3-key strip view are INTERNAL
        // selection steps only: feeding either as the emission for an own stream
        // must fail fail-closed.
        let raw_receipt = serde_json::json!({
            "capability_id": "chiopass:test",
            "metadata": { "financial": { "cost_charged": 42 } }
        });
        for stream in [ChioPassStream::OwnReceipts, ChioPassStream::OwnLineage] {
            assert!(matches!(
                emit_pass_stream_gift(
                    stream,
                    TENANT,
                    PassStreamSelection::AggregateBody(&raw_receipt),
                    &lineage_trust(),
                ),
                Err(KernelError::PassOwnDataGiftInvalid(_))
            ));
            // The weaker 3-key strip is not the own-stream gift boundary either.
            let stripped = project_pass_stream_view(&raw_receipt).expect("strip view");
            assert!(matches!(
                emit_pass_stream_gift(
                    stream,
                    TENANT,
                    PassStreamSelection::AggregateBody(&stripped),
                    &lineage_trust(),
                ),
                Err(KernelError::PassOwnDataGiftInvalid(_))
            ));
        }
    }

    #[test]
    fn aggregate_streams_keep_redacted_view_emission_unchanged() {
        let body = serde_json::json!({
            "capability_id": "chiopass:test",
            "metadata": { "cost": { "dimensions": [] }, "trust_level": "mediated" }
        });
        for stream in [
            ChioPassStream::ReputationTier,
            ChioPassStream::MarketplaceListings,
            ChioPassStream::PheromoneConcentration,
        ] {
            let gift = emit_pass_stream_gift(
                stream,
                TENANT,
                PassStreamSelection::AggregateBody(&body),
                &lineage_trust(),
            )
            .expect("aggregate view");
            let PassStreamGift::AggregateView(view) = gift else {
                panic!("aggregate stream must emit a redacted view");
            };
            assert_eq!(
                view.get("redaction").and_then(|v| v.as_str()),
                Some("summary")
            );
            // A disclosure bundle is never an aggregate-stream emission.
            let bundle = own_data_bundle(TENANT);
            assert!(matches!(
                emit_pass_stream_gift(
                    stream,
                    TENANT,
                    PassStreamSelection::OwnDataBundle(&bundle),
                    &lineage_trust(),
                ),
                Err(KernelError::PassRedactionFailed(_))
            ));
        }
    }

    #[test]
    fn own_data_gift_rejects_wrong_tenant_hash_binding() {
        // A bundle whose lineage nodes are bound to a different tenant must not be
        // served as this holder's own-data gift.
        let bundle = own_data_bundle("did:chioother");
        assert!(matches!(
            emit_own_data_gift_bundle(
                ChioPassStream::OwnReceipts,
                TENANT,
                &bundle,
                &lineage_trust()
            ),
            Err(KernelError::PassOwnDataGiftInvalid(_))
        ));
    }

    #[test]
    fn own_data_gift_rejects_plaintext_tenant_leak() {
        // The verifier still accepts the bundle (required_holder_binding is not
        // digest-bound), but the kernel denies because the plaintext tenant leaks
        // into the emitted artifact: only the sha256 tenant hash may appear.
        let mut bundle = own_data_bundle(TENANT);
        bundle.privacy_profile.required_holder_binding = Some(format!("holder:{TENANT}"));
        assert!(verify_disclosure_lineage_bundle_with_trust(&bundle, &lineage_trust()).is_ok());
        assert!(matches!(
            emit_own_data_gift_bundle(
                ChioPassStream::OwnReceipts,
                TENANT,
                &bundle,
                &lineage_trust()
            ),
            Err(KernelError::PassOwnDataGiftInvalid(_))
        ));
    }

    #[test]
    fn own_data_gift_rejects_non_own_stream() {
        let bundle = own_data_bundle(TENANT);
        for stream in [
            ChioPassStream::ReputationTier,
            ChioPassStream::MarketplaceListings,
            ChioPassStream::PheromoneConcentration,
        ] {
            assert!(matches!(
                emit_own_data_gift_bundle(stream, TENANT, &bundle, &lineage_trust()),
                Err(KernelError::PassOwnDataGiftInvalid(_))
            ));
        }
    }

    fn own_data_ledger(
        entries: Vec<DisclosureLeakageLedgerEntry>,
        accepted: bool,
    ) -> DisclosureLeakageLedger {
        let total = entries.iter().map(|entry| entry.score).sum();
        DisclosureLeakageLedger {
            schema: DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1.to_string(),
            id: "leakage-ledger-own".to_string(),
            transaction_passport_ref: "passport-own-data".to_string(),
            privacy_profile_ref: "privacy-profile-own".to_string(),
            policy_profile_id: "privacy-profile-own".to_string(),
            subject_artifact_sha256: digest("disclosure-capsule-own"),
            generated_at: "2026-06-10T00:00:00Z".to_string(),
            audience: "https://auditor.example/chio".to_string(),
            total_leakage_score: total,
            max_allowed_leakage_score: total,
            tenant_leakage_notice_ref: "tenant-leakage-notice-none".to_string(),
            accepted,
            entries,
        }
    }

    #[test]
    fn own_data_leakage_ledger_requires_accounted_runtime_assurance_even_when_empty() {
        // A ledger with no disclosed-field entries (the "empty" gift) still MUST
        // account the three runtime-assurance derived facts; the upstream verifier
        // does not require them when nothing is disclosed, so this is the kernel's
        // own strengthening.
        let empty = own_data_ledger(Vec::new(), true);
        assert!(matches!(
            require_own_data_leakage_ledger(&empty),
            Err(KernelError::PassOwnDataGiftInvalid(_))
        ));
        // Present even when empty of disclosed fields: just the three derived facts.
        let runtime_only = own_data_ledger(runtime_assurance_entries(), true);
        assert!(require_own_data_leakage_ledger(&runtime_only).is_ok());
        // Not accepted by policy denies.
        let rejected = own_data_ledger(runtime_assurance_entries(), false);
        assert!(matches!(
            require_own_data_leakage_ledger(&rejected),
            Err(KernelError::PassOwnDataGiftInvalid(_))
        ));
    }

    // -- Five-stream day-zero gift parity + cross-tenant hardening --------------

    #[test]
    fn day_zero_tier0_gifts_all_five_streams_at_pinned_indices() {
        // Day-zero (tier_0) gifting: the five streams are minted at their pinned
        // 0..=4 indices with the canonical URIs, each Read+Subscribe only. The
        // builder takes no tier input, so a tier_0 newcomer is gifted exactly this
        // set on day zero.
        let grants = pass_baseline_resource_grants(TENANT).expect("grants");
        let expected: [(usize, &str); 5] = [
            (0, "chio://trust/reputation/tier/*"),
            (1, "chio://marketplace/listings*"),
            (2, "chio://trust/pheromone/concentration/*"),
            (3, "chio://receipts/tenant/did:chioabcd/*"),
            (4, "chio://lineage/tenant/did:chioabcd/*"),
        ];
        assert_eq!(grants.len(), 5);
        for (index, uri) in expected {
            assert_eq!(
                grants[index].uri_pattern, uri,
                "stream {index} URI is pinned"
            );
            assert_eq!(
                grants[index].operations,
                vec![Operation::Read, Operation::Subscribe],
                "stream {index} is Read+Subscribe only",
            );
        }
        // Streams 3/4 are the OWN tenant-bound rights; 0/1/2 are aggregate feeds.
        assert!(
            ChioPassStream::ALL[3].is_own_tenant() && ChioPassStream::ALL[4].is_own_tenant(),
            "streams 3 and 4 are the own-data baseline rights",
        );
        assert!(
            !ChioPassStream::ALL[0].is_own_tenant()
                && !ChioPassStream::ALL[1].is_own_tenant()
                && !ChioPassStream::ALL[2].is_own_tenant(),
            "streams 0..=2 are tenant-independent aggregates",
        );
    }

    #[test]
    fn gifted_resource_grants_are_byte_identical_across_tiers() {
        // pass_baseline_resource_grants takes NO TrustTier: the own-data gift is a
        // permanent baseline RIGHT, never tier-gated. Building the set the way a
        // tier_0 mint and a Premier mint both do (same tenant, same builder) yields
        // a byte-identical ResourceGrant set. The end-to-end cross-tier proof
        // through build_pass_scope lives in chio-control-plane.
        let as_tier0 = pass_baseline_resource_grants(TENANT).expect("tier0 grants");
        let as_premier = pass_baseline_resource_grants(TENANT).expect("premier grants");
        assert_eq!(as_tier0, as_premier);
        assert_eq!(
            serde_json::to_vec(&as_tier0).expect("ser tier0"),
            serde_json::to_vec(&as_premier).expect("ser premier"),
            "the gifted grant set must be byte-identical regardless of tier",
        );
    }

    #[test]
    fn pheromone_stream_serves_aggregate_concentration_not_raw_deposits() {
        // Stream 2 is the collapsed-origin aggregate concentration view, never the
        // origin-identifying raw deposits (query_deposits) surface.
        let concentration =
            pass_stream_uri(ChioPassStream::PheromoneConcentration, TENANT).expect("uri");
        assert_eq!(concentration, "chio://trust/pheromone/concentration/*");
        // The concentration aggregate is gifted (not deny-listed).
        assert!(!uri_is_pass_denied(
            "chio://trust/pheromone/concentration/ns"
        ));
        // The raw deposits surface is deny-listed and appears in NO baseline grant.
        assert!(uri_is_pass_denied(PASS_DENY_PHEROMONE_DEPOSITS));
        let grants = pass_baseline_resource_grants(TENANT).expect("grants");
        assert!(
            grants
                .iter()
                .all(|g| !g.uri_pattern.starts_with(PASS_DENY_PHEROMONE_DEPOSITS)),
            "no gifted grant may reach the raw query_deposits surface",
        );
        // The serving gate authorizes concentration but denies raw deposits.
        let cap = pass_capability(baseline_scope(TENANT));
        assert!(
            pass_authorizes_read(&cap, "chio://trust/pheromone/concentration/ns").expect("read")
        );
        assert!(
            !pass_authorizes_read(&cap, "chio://trust/pheromone/deposits/origin/abc")
                .expect("deny raw deposits read")
        );
        assert!(
            !pass_authorizes_subscription(&cap, "chio://trust/pheromone/deposits")
                .expect("deny raw deposits subscribe")
        );
    }

    #[test]
    fn pass_for_short_tenant_cannot_read_longer_sibling_via_mandatory_delimiter() {
        // Prefix-collision: did:chioabcd (short) vs did:chioabcde (longer sibling).
        // The mandatory `/` delimiter before the trailing `*` means the short
        // tenant's Pass never prefix-matches the longer tenant's stream.
        const SHORT: &str = "did:chioabcd";
        const LONG: &str = "did:chioabcde";
        let cap = pass_capability(baseline_scope(SHORT));
        // The short tenant reads its OWN receipts/lineage.
        assert!(
            pass_authorizes_read(&cap, &format!("chio://receipts/tenant/{SHORT}/r1"))
                .expect("own receipts")
        );
        assert!(
            pass_authorizes_read(&cap, &format!("chio://lineage/tenant/{SHORT}/n1"))
                .expect("own lineage")
        );
        // It MUST NOT read the longer sibling tenant's receipts or lineage.
        assert!(
            !pass_authorizes_read(&cap, &format!("chio://receipts/tenant/{LONG}/r1"))
                .expect("deny sibling receipts")
        );
        assert!(
            !pass_authorizes_read(&cap, &format!("chio://lineage/tenant/{LONG}/n1"))
                .expect("deny sibling lineage")
        );
        assert!(
            !pass_authorizes_subscription(&cap, &format!("chio://receipts/tenant/{LONG}/r1"))
                .expect("deny sibling subscribe")
        );
    }
}
