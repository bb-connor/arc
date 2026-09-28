use crate::receipt_store::StoredToolReceipt;

/// Maximum number of receipts returnable in a single query page.
pub const MAX_QUERY_LIMIT: usize = 200;

/// Explicit receipt read boundary for query, export, and report surfaces.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ReceiptReadBoundary {
    /// Caller has explicit administrative access to all receipt rows.
    AdminAll,
    /// Caller is scoped to a single authenticated tenant.
    TenantScoped { tenant: String },
}

impl ReceiptReadBoundary {
    #[must_use]
    pub fn tenant_scoped(tenant: impl Into<String>) -> Self {
        Self::TenantScoped {
            tenant: tenant.into(),
        }
    }
}

/// Provenance for a resolved read boundary.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptReadContextSource {
    LocalOperator,
    AdminService,
    AuthenticatedTenant,
}

/// Receipt read authority resolved by a trusted local or service adapter.
/// Never deserialize this from a request. Remote callers supply credentials;
/// the adapter authenticates those credentials before selecting a constructor.
///
/// ```compile_fail
/// use chio_kernel::ReceiptReadContext;
/// let context: ReceiptReadContext = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptReadContext {
    boundary: ReceiptReadBoundary,
    source: ReceiptReadContextSource,
}

impl ReceiptReadContext {
    #[must_use]
    pub fn local_operator_admin_all() -> Self {
        Self {
            boundary: ReceiptReadBoundary::AdminAll,
            source: ReceiptReadContextSource::LocalOperator,
        }
    }
    #[must_use]
    pub fn admin_service() -> Self {
        Self {
            boundary: ReceiptReadBoundary::AdminAll,
            source: ReceiptReadContextSource::AdminService,
        }
    }
    #[must_use]
    pub fn authenticated_tenant(tenant: impl Into<String>) -> Self {
        Self {
            boundary: ReceiptReadBoundary::tenant_scoped(tenant),
            source: ReceiptReadContextSource::AuthenticatedTenant,
        }
    }
    #[must_use]
    pub fn local_operator_tenant(tenant: impl Into<String>) -> Self {
        Self {
            boundary: ReceiptReadBoundary::tenant_scoped(tenant),
            source: ReceiptReadContextSource::LocalOperator,
        }
    }
    #[must_use]
    pub const fn boundary(&self) -> &ReceiptReadBoundary {
        &self.boundary
    }
    #[must_use]
    pub const fn source(&self) -> ReceiptReadContextSource {
        self.source
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptReadError {
    #[error("receipt query requires an explicit read context")]
    MissingContext,
    #[error("receipt query requires a non-empty tenant without surrounding whitespace")]
    InvalidTenant,
    #[error("receipt query tenant filter cannot widen authenticated tenant scope")]
    TenantScopeMismatch,
    #[error("receipt query is invalid: {0}")]
    InvalidQuery(String),
    #[error("stored receipt tenant projection differs from its signed body")]
    TenantProjectionMismatch,
}

impl ReceiptReadError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingContext => "urn:chio:error:kernel:receipt-read-context-missing",
            Self::InvalidTenant => "urn:chio:error:kernel:receipt-read-tenant-invalid",
            Self::TenantScopeMismatch => "urn:chio:error:kernel:receipt-read-scope-mismatch",
            Self::InvalidQuery(_) => "urn:chio:error:kernel:receipt-read-query-invalid",
            Self::TenantProjectionMismatch => {
                "urn:chio:error:kernel:receipt-read-projection-mismatch"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveReceiptReadScope {
    pub tenant: Option<String>,
    pub is_admin_all: bool,
}

/// Query parameters for filtering and paginating tool receipts.
#[derive(Debug, Default, Clone)]
pub struct ReceiptQuery {
    /// Filter by capability ID (exact match).
    pub capability_id: Option<String>,
    /// Filter by tool server name (exact match).
    pub tool_server: Option<String>,
    /// Filter by tool name (exact match).
    pub tool_name: Option<String>,
    /// Filter by decision outcome (maps to decision_kind column:
    /// "allow", "deny", "cancelled", "incomplete").
    pub outcome: Option<String>,
    /// Include only receipts with timestamp >= since (Unix seconds, inclusive).
    pub since: Option<u64>,
    /// Include only receipts with timestamp <= until (Unix seconds, inclusive).
    pub until: Option<u64>,
    /// Include only receipts with financial cost_charged >= min_cost (minor units).
    /// Receipts without financial metadata are excluded when this filter is set.
    pub min_cost: Option<u64>,
    /// Include only receipts with financial cost_charged <= max_cost (minor units).
    /// Receipts without financial metadata are excluded when this filter is set.
    pub max_cost: Option<u64>,
    /// Currency for cost filters. Required when either cost bound is present.
    pub cost_currency: Option<String>,
    /// Cursor for forward pagination: return only receipts with seq > cursor (exclusive).
    pub cursor: Option<u64>,
    /// Maximum number of receipts to return per page (capped at MAX_QUERY_LIMIT).
    pub limit: usize,
    /// Filter by agent subject public key (hex-encoded Ed25519). Resolved through
    /// capability_lineage JOIN -- does not replay issuance logs.
    pub agent_subject: Option<String>,
    /// Optional tenant narrowing filter. This is never authority by itself:
    /// callers must also provide a matching explicit `read_context`.
    pub tenant_filter: Option<String>,
    /// Explicit read context resolved from authenticated authority.
    pub read_context: Option<ReceiptReadContext>,
}

impl ReceiptQuery {
    pub fn validated_cost_currency(&self) -> Result<Option<&str>, String> {
        if self
            .min_cost
            .zip(self.max_cost)
            .is_some_and(|(minimum, maximum)| minimum > maximum)
        {
            return Err("receipt query minimum cost exceeds maximum cost".to_string());
        }
        let has_cost_bound = self.min_cost.is_some() || self.max_cost.is_some();
        let Some(currency) = self.cost_currency.as_deref() else {
            if has_cost_bound {
                return Err("receipt query cost bounds require a currency".to_string());
            }
            return Ok(None);
        };
        if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err("receipt query currency must be a three-letter uppercase code".to_string());
        }
        Ok(Some(currency))
    }

    #[must_use]
    pub fn with_read_context(mut self, read_context: ReceiptReadContext) -> Self {
        self.read_context = Some(read_context);
        self
    }

    #[must_use]
    pub fn local_operator_admin(mut self) -> Self {
        self.read_context = Some(ReceiptReadContext::local_operator_admin_all());
        self
    }

    #[must_use]
    pub fn authenticated_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.read_context = Some(ReceiptReadContext::authenticated_tenant(tenant));
        self
    }

    pub fn effective_read_scope(&self) -> Result<EffectiveReceiptReadScope, ReceiptReadError> {
        self.validated_cost_currency()
            .map_err(ReceiptReadError::InvalidQuery)?;
        let context = self
            .read_context
            .as_ref()
            .ok_or(ReceiptReadError::MissingContext)?;
        let valid_tenant = |tenant: &str| !tenant.is_empty() && tenant.trim() == tenant;
        if self
            .tenant_filter
            .as_deref()
            .is_some_and(|tenant| !valid_tenant(tenant))
        {
            return Err(ReceiptReadError::InvalidTenant);
        }
        match context.boundary() {
            ReceiptReadBoundary::AdminAll => Ok(EffectiveReceiptReadScope {
                tenant: self.tenant_filter.clone(),
                is_admin_all: true,
            }),
            ReceiptReadBoundary::TenantScoped { tenant } => {
                if !valid_tenant(tenant) {
                    return Err(ReceiptReadError::InvalidTenant);
                }
                if self
                    .tenant_filter
                    .as_ref()
                    .is_some_and(|filter| filter != tenant)
                {
                    return Err(ReceiptReadError::TenantScopeMismatch);
                }
                Ok(EffectiveReceiptReadScope {
                    tenant: Some(tenant.clone()),
                    is_admin_all: false,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReceiptQuery, ReceiptReadContext, ReceiptReadError};

    #[test]
    fn tenant_filter_without_read_context_is_not_authority() {
        let query = ReceiptQuery {
            tenant_filter: Some("tenant-a".to_string()),
            ..ReceiptQuery::default()
        };

        let err = query
            .effective_read_scope()
            .expect_err("tenant_filter must not authorize a receipt read by itself");

        assert_eq!(err, ReceiptReadError::MissingContext);
    }

    #[test]
    fn authenticated_tenant_context_must_match_query_filter() {
        let query = ReceiptQuery {
            tenant_filter: Some("tenant-b".to_string()),
            read_context: Some(ReceiptReadContext::authenticated_tenant("tenant-a")),
            ..ReceiptQuery::default()
        };

        let err = query
            .effective_read_scope()
            .expect_err("query filter must not widen authenticated tenant scope");

        assert_eq!(err, ReceiptReadError::TenantScopeMismatch);
    }

    #[test]
    fn admin_context_tenant_filter_narrows_effective_scope() {
        let query = ReceiptQuery {
            tenant_filter: Some("tenant-a".to_string()),
            read_context: Some(ReceiptReadContext::admin_service()),
            ..ReceiptQuery::default()
        };

        let scope = query
            .effective_read_scope()
            .expect("admin tenant filter should narrow the query");

        assert_eq!(scope.tenant.as_deref(), Some("tenant-a"));
        assert!(scope.is_admin_all);
    }

    #[test]
    fn admin_context_rejects_blank_tenant_filter() {
        let query = ReceiptQuery {
            tenant_filter: Some("   ".to_string()),
            read_context: Some(ReceiptReadContext::admin_service()),
            ..ReceiptQuery::default()
        };

        let err = query
            .effective_read_scope()
            .expect_err("blank tenant filter must fail closed");

        assert_eq!(err, ReceiptReadError::InvalidTenant);
    }

    #[test]
    fn tenant_scoped_context_rejects_blank_boundary_tenant() {
        let query = ReceiptQuery {
            read_context: Some(ReceiptReadContext::authenticated_tenant("   ")),
            ..ReceiptQuery::default()
        };

        let err = query
            .effective_read_scope()
            .expect_err("blank tenant boundary must fail closed");

        assert_eq!(err, ReceiptReadError::InvalidTenant);
    }
}

/// Result of a receipt query, including pagination state.
#[derive(Debug)]
pub struct ReceiptQueryResult {
    /// Receipts matching the query filters, ordered by seq ASC.
    pub receipts: Vec<StoredToolReceipt>,
    /// Total number of receipts matching the filters (independent of limit/cursor).
    pub total_count: u64,
    /// Cursor for the next page: Some(last_seq) when more results exist, None on last page.
    pub next_cursor: Option<u64>,
}
