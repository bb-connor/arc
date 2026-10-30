use super::*;

#[derive(Debug, Clone)]
pub(crate) struct TrustHttpError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl TrustHttpError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    pub(crate) fn into_response(self) -> Response {
        plain_http_error(self.status, &self.message)
    }
}

impl From<TrustHttpError> for CliError {
    fn from(error: TrustHttpError) -> Self {
        CliError::cli_other_error(error.message)
    }
}

impl From<ReceiptStoreError> for TrustHttpError {
    fn from(error: ReceiptStoreError) -> Self {
        trust_http_error_from_receipt_store(error)
    }
}

impl From<CliError> for TrustHttpError {
    fn from(error: CliError) -> Self {
        TrustHttpError::internal(error.to_string())
    }
}

pub(crate) fn liability_market_http_error(message: &str) -> Response {
    let status = if message.contains("not found") {
        StatusCode::NOT_FOUND
    } else if message.contains("outside the trusted capital authority set") {
        StatusCode::FORBIDDEN
    } else if message.contains("already")
        || message.contains("stale")
        || message.contains("unsupported")
        || message.contains("not active")
        || message.contains("superseded")
        || message.contains("expires")
        || message.contains("mismatch")
        || message.contains("must match")
        || message.contains("cannot be issued")
    {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    };
    plain_http_error(status, message)
}

#[derive(Debug, Clone)]
pub(crate) enum UnderwritingQuotedExposure {
    None,
    Single(MonetaryAmount),
    MixedCurrencies(BTreeSet<String>),
}

impl UnderwritingQuotedExposure {
    pub(crate) fn amount_for_pricing(&self) -> Option<MonetaryAmount> {
        match self {
            Self::Single(amount) => Some(amount.clone()),
            Self::None | Self::MixedCurrencies(_) => None,
        }
    }

    pub(crate) fn apply_to_artifact(
        &self,
        artifact: &mut chio_kernel::UnderwritingDecisionArtifact,
    ) {
        let Self::MixedCurrencies(currencies) = self else {
            return;
        };
        if artifact.premium.state != chio_kernel::UnderwritingPremiumState::Quoted {
            return;
        }

        artifact.premium.state = chio_kernel::UnderwritingPremiumState::Withheld;
        artifact.premium.basis_points = None;
        artifact.premium.quoted_amount = None;
        artifact.premium.rationale = format!(
            "premium is withheld because governed exposure spans multiple currencies: {}",
            currencies.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct CombinedDelegationChainEntry {
    capability_id: String,
    subject_key: String,
    issuer_key: String,
    issued_at: u64,
    expires_at: u64,
    grants_json: String,
    delegation_depth: u64,
    parent_capability_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    federated_parent_capability_id: Option<String>,
    provenance: chio_core::receipt::evidence::CapabilitySnapshotProvenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_capability: Option<chio_core::capability::token::CapabilityToken>,
    snapshot_delegation_depth: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_parent_capability_id: Option<String>,
}

pub(crate) fn project_combined_delegation_chain(
    chain: Vec<CapabilitySnapshot>,
) -> Vec<CombinedDelegationChainEntry> {
    let mut effective_parent = None;
    chain
        .into_iter()
        .zip(0_u64..)
        .map(|(snapshot, delegation_depth)| {
            let CapabilitySnapshot {
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth: snapshot_delegation_depth,
                parent_capability_id: snapshot_parent_capability_id,
                federated_parent_capability_id,
                provenance,
                signed_capability,
            } = snapshot;
            let entry = CombinedDelegationChainEntry {
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id: effective_parent.take(),
                federated_parent_capability_id,
                provenance,
                signed_capability,
                snapshot_delegation_depth,
                snapshot_parent_capability_id,
            };
            effective_parent = Some(entry.capability_id.clone());
            entry
        })
        .collect()
}

#[cfg(test)]
mod combined_delegation_chain_tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn snapshot(
        capability_id: &str,
        snapshot_parent: Option<&str>,
        federated_parent: Option<&str>,
        snapshot_depth: u64,
    ) -> CapabilitySnapshot {
        CapabilitySnapshot {
            capability_id: capability_id.to_string(),
            subject_key: "subject".to_string(),
            issuer_key: "issuer".to_string(),
            issued_at: 1,
            expires_at: 2,
            grants_json: "{}".to_string(),
            delegation_depth: snapshot_depth,
            parent_capability_id: snapshot_parent.map(ToString::to_string),
            federated_parent_capability_id: federated_parent.map(ToString::to_string),
            provenance: chio_core::receipt::evidence::CapabilitySnapshotProvenance::SyntheticAnchor,
            signed_capability: None,
        }
    }

    #[test]
    fn projection_exposes_effective_chain_without_erasing_snapshot_lineage() {
        let value = serde_json::to_value(project_combined_delegation_chain(vec![
            snapshot("root", None, None, 0),
            snapshot("federated", None, Some("root"), 0),
            snapshot("signed-child", Some("federated"), None, 1),
        ]))
        .test_expect("serialize combined delegation chain");
        let entries = value
            .as_array()
            .test_expect("combined delegation chain array");

        assert_eq!(entries[1]["parent_capability_id"], "root");
        assert_eq!(entries[1]["delegation_depth"], 1);
        assert!(entries[1].get("snapshot_parent_capability_id").is_none());
        assert_eq!(entries[1]["snapshot_delegation_depth"], 0);
        assert_eq!(entries[2]["parent_capability_id"], "federated");
        assert_eq!(entries[2]["delegation_depth"], 2);
        assert_eq!(entries[2]["snapshot_parent_capability_id"], "federated");
        assert_eq!(entries[2]["snapshot_delegation_depth"], 1);
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChildReceiptQuery {
    /// Point-load a single child receipt by its `receipt_id`. When set, the
    /// handler resolves exactly this receipt from the durable store (bounded to
    /// one row), so a store-authoritative `--control-url` deployment can resolve
    /// a child receipt that the kernel's bounded mirror has evicted.
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub parent_request_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub terminal_state: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RevocationQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<chio_core_types::root_authority::RevocationTargetKind>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRecordView {
    pub capability_id: String,
    pub revoked_at: i64,
}

/// Whether one capability is revoked, and by which entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationStatusResponse {
    pub capability_id: String,
    pub revoked: bool,
    pub entry_id: Option<chio_core_types::root_authority::RevocationEntryId>,
}

/// One page of revocation entries after a cursor, in `entry_seq` order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntryPage {
    pub entries: Vec<RevocationEntryPageItem>,
    /// The cursor for the next page: the last `entry_seq` returned, or the
    /// requested cursor when the page is empty.
    pub next_after: u64,
    /// The highest stored `entry_seq`.
    pub head: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntryPageItem {
    pub entry_seq: u64,
    pub entry: chio_core_types::root_authority::RevocationEntry,
}

/// The status and fixed body for a revocation store error. An unknown commit
/// outcome poisons the serving owner until the process restarts; every other
/// error left nothing committed. No store text reaches the caller.
#[must_use]
pub fn revocation_store_failure(
    error: &chio_kernel::RevocationStoreError,
) -> (axum::http::StatusCode, &'static str) {
    let body = match error {
        chio_kernel::RevocationStoreError::OutcomeUnknown(_) => {
            "revocation outcome unknown; restart the provider, then retry the same request"
        }
        _ => "revocation store unavailable",
    };
    (axum::http::StatusCode::SERVICE_UNAVAILABLE, body)
}

/// The fixed refusal for a malformed revocation request or query.
pub const INVALID_REVOCATION_REQUEST: &str = "invalid revocation request";
pub const DEFAULT_REVOCATION_PAGE: usize = 100;
pub const MAX_REVOCATION_PAGE: usize = 500;

/// A revocation query, parsed: the check of one capability or a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationListing {
    Status(String),
    Page {
        after: u64,
        limit: usize,
        kind: Option<chio_core_types::root_authority::RevocationTargetKind>,
    },
}

impl RevocationQuery {
    /// `None` for a query this endpoint refuses: a capability check that also
    /// names a page member, an invalid capability id, or a limit outside
    /// 1 to `MAX_REVOCATION_PAGE`.
    #[must_use]
    pub fn listing(&self) -> Option<RevocationListing> {
        if let Some(capability_id) = &self.capability_id {
            if self.after.is_some() || self.limit.is_some() || self.kind.is_some() {
                return None;
            }
            chio_core_types::root_authority::RevocationTarget::capability(capability_id).ok()?;
            return Some(RevocationListing::Status(capability_id.clone()));
        }
        let limit = self.limit.unwrap_or(DEFAULT_REVOCATION_PAGE);
        if !(1..=MAX_REVOCATION_PAGE).contains(&limit) {
            return None;
        }
        Some(RevocationListing::Page {
            after: self.after.unwrap_or(0),
            limit,
            kind: self.kind,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptListResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<chio_kernel::receipt_query::ReceiptSnapshotWatermark>,
    pub configured: bool,
    pub backend: String,
    pub kind: String,
    pub count: usize,
    pub filters: Value,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BudgetQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug)]
pub struct BudgetUsageView {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub total_cost_exposed: u64,
    pub total_cost_realized_spend: u64,
    pub updated_at: i64,
    pub seq: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BudgetUsageViewWire<'a> {
    capability_id: &'a str,
    grant_index: u32,
    invocation_count: u32,
    total_exposure_charged: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_realized_spend: Option<u64>,
    updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BudgetUsageViewWireInput {
    capability_id: String,
    grant_index: u32,
    invocation_count: u32,
    #[serde(default)]
    total_exposure_charged: Option<u64>,
    #[serde(default)]
    total_realized_spend: Option<u64>,
    updated_at: i64,
    #[serde(default)]
    seq: Option<u64>,
}

impl Serialize for BudgetUsageView {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BudgetUsageViewWire {
            capability_id: &self.capability_id,
            grant_index: self.grant_index,
            invocation_count: self.invocation_count,
            total_exposure_charged: self.total_cost_exposed,
            total_realized_spend: Some(self.total_cost_realized_spend),
            updated_at: self.updated_at,
            seq: self.seq,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BudgetUsageView {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = BudgetUsageViewWireInput::deserialize(deserializer)?;
        Ok(Self {
            capability_id: wire.capability_id,
            grant_index: wire.grant_index,
            invocation_count: wire.invocation_count,
            total_cost_exposed: require_budget_amount(
                wire.total_exposure_charged,
                "`totalExposureCharged`",
            )?,
            total_cost_realized_spend: wire.total_realized_spend.unwrap_or(0),
            updated_at: wire.updated_at,
            seq: wire.seq,
        })
    }
}

pub(super) fn require_budget_amount<E>(
    amount: Option<u64>,
    missing_field_name: &str,
) -> Result<u64, E>
where
    E: serde::de::Error,
{
    amount.ok_or_else(|| E::custom(format!("missing required field {missing_field_name}")))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetListResponse {
    pub configured: bool,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    pub count: usize,
    pub usages: Vec<BudgetUsageView>,
}

impl From<chio_security_types::clock::ClockError> for TrustHttpError {
    fn from(error: chio_security_types::clock::ClockError) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, error.code())
    }
}
