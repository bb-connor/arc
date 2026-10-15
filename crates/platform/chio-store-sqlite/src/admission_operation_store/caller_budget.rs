#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
//! Read a complete delegated caller-share view through the parent index.

use super::*;
use chio_kernel::admission_operation::{
    AdmissionCallerBudgetShare, RetainedToolAdmissionRequestV1,
};

pub(super) const SCHEMA: &str = include_str!("caller_budget/schema.sql");

/// Operations indexed under the parent, plus every unresolved funded
/// operation, which must keep denying each snapshot. The left table drives
/// both arms, so neither reads operations outside the index.
pub(super) const CANDIDATES_SQL: &str = r#"
    SELECT share.operation_id, share.parent_kind, share.parent_capability_id
    FROM admission_operation_caller_shares AS share
    CROSS JOIN admission_operations AS operation
        ON operation.operation_id = share.operation_id
    WHERE share.parent_kind = 'delegated' AND share.parent_capability_id = ?1
      AND (operation.terminal = 0 OR operation.state = 'outcome_unknown_after_dispatch')
    UNION ALL
    SELECT share.operation_id, share.parent_kind, share.parent_capability_id
    FROM admission_operation_caller_shares AS share
    CROSS JOIN admission_operations AS operation
        ON operation.operation_id = share.operation_id
    WHERE share.parent_kind = 'unresolved'
      AND (operation.terminal = 0 OR operation.state = 'outcome_unknown_after_dispatch')
    ORDER BY 1
"#;

const INDEX_MISMATCH: &str = "caller share parent index disagrees with its retained request";

/// Where a funded operation's share is accounted. It is derived only from the
/// immutable retained request, so an indexed row never needs to change.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShareParent {
    Delegated(AdmissionIdentifier),
    Root,
    /// No retained request, or a parent that is not a valid identifier. Such
    /// an operation cannot be attributed, so it denies every parent's snapshot.
    Unresolved,
}

impl ShareParent {
    fn of(retained: Option<&RetainedToolAdmissionRequestV1>) -> Self {
        let Some(retained) = retained else {
            return Self::Unresolved;
        };
        match retained
            .request_for_revalidation()
            .capability
            .delegation_chain
            .last()
        {
            None => Self::Root,
            Some(parent) => AdmissionIdentifier::try_new("parent_id", parent.capability_id.clone())
                .map_or(Self::Unresolved, Self::Delegated),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Delegated(_) => "delegated",
            Self::Root => "root",
            Self::Unresolved => "unresolved",
        }
    }

    fn capability_id(&self) -> Option<&str> {
        match self {
            Self::Delegated(parent) => Some(parent.as_str()),
            Self::Root | Self::Unresolved => None,
        }
    }

    fn decode(kind: &str, parent: Option<String>) -> Result<Self, AdmissionOperationStoreError> {
        match (kind, parent) {
            ("delegated", Some(parent)) => AdmissionIdentifier::try_new("parent_id", parent)
                .map(Self::Delegated)
                .map_err(|_| invariant("caller share parent index is malformed")),
            ("root", None) => Ok(Self::Root),
            ("unresolved", None) => Ok(Self::Unresolved),
            _ => Err(invariant("caller share parent index is malformed")),
        }
    }

    fn load(
        connection: &Connection,
        operation_id: &str,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        connection
            .query_row(
                "SELECT parent_kind, parent_capability_id
                 FROM admission_operation_caller_shares WHERE operation_id = ?1",
                [operation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?
            .map(|(kind, parent)| Self::decode(&kind, parent))
            .transpose()
    }
}

/// Index the parent in the transaction that first persists an operation
/// funding a caller share. Later commits of the same operation find the row.
pub(super) fn index_funded_share(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    if !AdmissionCallerBudgetShare::is_owned_by(operation) {
        return Ok(());
    }
    let operation_id = operation.binding().operation_id().as_str();
    if ShareParent::load(connection, operation_id)?.is_some() {
        return Ok(());
    }
    let retained = retained_request::load_retained_request_tx(connection, operation)?;
    let parent = ShareParent::of(retained.as_ref());
    connection
        .execute(
            "INSERT INTO admission_operation_caller_shares
                 (operation_id, parent_kind, parent_capability_id)
             VALUES (?1, ?2, ?3)",
            params![operation_id, parent.kind(), parent.capability_id()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

/// An indexed parent must match the retained request, and every operation
/// that currently funds a share must be indexed.
pub(super) fn verify_indexed(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    retained: Option<&RetainedToolAdmissionRequestV1>,
) -> Result<(), AdmissionOperationStoreError> {
    match ShareParent::load(connection, operation.binding().operation_id().as_str())? {
        Some(indexed) if indexed == ShareParent::of(retained) => Ok(()),
        Some(_) => Err(invariant(INDEX_MISMATCH)),
        None if AdmissionCallerBudgetShare::is_owned_by(operation) => {
            Err(invariant("funded caller share has no parent index"))
        }
        None => Ok(()),
    }
}

pub(super) fn verify_ownership(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM admission_operation_caller_shares AS share
                WHERE NOT EXISTS (
                    SELECT 1 FROM admission_operations AS operation
                    WHERE operation.operation_id = share.operation_id
                )
            )",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if orphan {
        return Err(invariant(
            "caller share parent index has no owning admission operation",
        ));
    }
    Ok(())
}

impl SqliteAdmissionOperationStore {
    pub(super) fn caller_budget_shares(
        &self,
        parent_id: &AdmissionIdentifier,
        limit: usize,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Vec<AdmissionCallerBudgetShare>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        verify_trusted_time(&transaction, now, &self.serving_owner)?;
        let shares = read_indexed(&transaction, parent_id, limit, now)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(shares)
    }
}

/// Every candidate is loaded and verified exactly as a full scan would verify
/// it. A candidate whose retained request disagrees with its index row denies.
fn read_indexed(
    transaction: &Transaction<'_>,
    parent_id: &AdmissionIdentifier,
    limit: usize,
    now: u64,
) -> Result<Vec<AdmissionCallerBudgetShare>, AdmissionOperationStoreError> {
    let history = CheckedHistoryScope::new(transaction);
    let mut statement = transaction.prepare(CANDIDATES_SQL).map_err(sqlite_error)?;
    let mut rows = statement
        .query([parent_id.as_str()])
        .map_err(sqlite_error)?;
    let mut shares = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let id =
            AdmissionOperationId::from_persisted(row.get::<_, String>(0).map_err(sqlite_error)?)?;
        let indexed = ShareParent::decode(
            &row.get::<_, String>(1).map_err(sqlite_error)?,
            row.get::<_, Option<String>>(2).map_err(sqlite_error)?,
        )?;
        let stored = load_by_operation_id_tx_with_history(transaction, &id, &history)?
            .ok_or_else(|| invariant("caller share operation disappeared in its snapshot"))?;
        stored.verify_decision_time(now)?;
        if !AdmissionCallerBudgetShare::is_owned_by(&stored.operation) {
            continue;
        }
        let retained = retained_request::load_retained_request_tx(transaction, &stored.operation)?
            .ok_or_else(|| invariant("funded caller share lost its retained request"))?;
        if ShareParent::of(Some(&retained)) != indexed {
            return Err(invariant(INDEX_MISMATCH));
        }
        match AdmissionCallerBudgetShare::from_retained_operation(&stored.operation, &retained)? {
            Some(share) if share.parent_id() == parent_id => {
                if shares.len() == limit {
                    return Err(invariant("caller sibling-share snapshot exceeds its bound"));
                }
                shares.push(share);
            }
            _ => return Err(invariant(INDEX_MISMATCH)),
        }
    }
    Ok(shares)
}

/// The pre-index snapshot: verify every live or outcome-unknown operation,
/// then filter by parent. Tests compare it with the indexed read.
#[cfg(test)]
pub(super) fn read_by_full_scan(
    transaction: &Transaction<'_>,
    parent_id: &AdmissionIdentifier,
    now: u64,
) -> Result<Vec<AdmissionCallerBudgetShare>, AdmissionOperationStoreError> {
    let history = CheckedHistoryScope::new(transaction);
    let mut statement = transaction
        .prepare(
            "SELECT operation_id FROM admission_operations
             WHERE terminal = 0 OR state = 'outcome_unknown_after_dispatch'
             ORDER BY operation_id",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut shares = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let id =
            AdmissionOperationId::from_persisted(row.get::<_, String>(0).map_err(sqlite_error)?)?;
        let stored = load_by_operation_id_tx_with_history(transaction, &id, &history)?
            .ok_or_else(|| invariant("caller share operation disappeared in its snapshot"))?;
        stored.verify_decision_time(now)?;
        if !AdmissionCallerBudgetShare::is_owned_by(&stored.operation) {
            continue;
        }
        let retained = retained_request::load_retained_request_tx(transaction, &stored.operation)?
            .ok_or_else(|| invariant("funded caller share lost its retained request"))?;
        if let Some(share) =
            AdmissionCallerBudgetShare::from_retained_operation(&stored.operation, &retained)?
        {
            if share.parent_id() == parent_id {
                shares.push(share);
            }
        }
    }
    Ok(shares)
}
