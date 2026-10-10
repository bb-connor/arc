// Cost attribution report query.
use super::analytics::{selected_query, AnalyticsScope};
use super::read_boundary::{ReportReadLimits, ReportSnapshot};
use super::*;

impl SqliteReceiptStore {
    /// Complete totals for the selected stored rows, with embedded-signature
    /// consistency only. This does not authenticate exclusion or corpus trust.
    pub fn query_cost_attribution_report(
        &self,
        query: &CostAttributionQuery,
    ) -> Result<CostAttributionReport, ReceiptStoreError> {
        self.cost_attribution_with_limits(query, ReportReadLimits::default(), || Ok(()))
    }

    pub(super) fn cost_attribution_with_limits(
        &self,
        query: &CostAttributionQuery,
        limits: ReportReadLimits,
        after_snapshot: impl FnOnce() -> Result<(), ReceiptStoreError>,
    ) -> Result<CostAttributionReport, ReceiptStoreError> {
        require_admin_receipt_read_context(query.read_context.as_ref(), "cost attribution report")?;
        let limit = query
            .limit
            .unwrap_or(100)
            .clamp(1, MAX_COST_ATTRIBUTION_LIMIT);
        let scope = AnalyticsScope::from_cost_query(query)?;
        let connection = self.connection()?;
        let mut owner = ReportSnapshot::new(&connection, "cost attribution report", limits)?;
        after_snapshot()?;
        let (snapshot, budget) = owner.split();
        let result = (|| {
            let row_bytes = sqlite_i64(budget.metadata_byte_limit()?, "report encoded row limit")?;
            let ceiling = sqlite_i64(
                limits.rows.checked_add(1).ok_or_else(|| {
                    ReceiptStoreError::ReadBoundary("invalid report row limit".into())
                })?,
                "report row limit",
            )?;
            let (sql, scan) = selected_query(&scope, &row_bytes, &ceiling, true);
            let mut statement = snapshot.prepare(&sql)?;
            let mut rows = statement.query(scan.params())?;
            let mut matching_receipts = 0_u64;
            let mut receipts = Vec::with_capacity(limit);
            let mut by_root = BTreeMap::<String, RootAggregate>::new();
            let mut by_leaf = BTreeMap::<(String, String), LeafAggregate>::new();
            let mut distinct_roots = BTreeSet::new();
            let mut distinct_leaves = BTreeSet::new();
            let mut total_cost_charged = 0_u64;
            let mut total_attempted_cost = 0_u64;
            let mut max_delegation_depth = 0_u64;
            let mut lineage_gap_count = 0_u64;

            // The complete selected set is streamed. The output limit never trims
            // financial input or suppresses a later integrity/capacity failure.
            while let Some(row) = rows.next()? {
                let (seq, receipt) = budget.receipt(snapshot, row)?;
                let Some(financial) = extract_financial_metadata(&receipt) else {
                    continue;
                };
                let attribution = extract_receipt_attribution(&receipt);
                matching_receipts = matching_receipts.checked_add(1).ok_or_else(|| {
                    ReceiptStoreError::ReadBoundary(
                        "cost attribution receipt count overflow".into(),
                    )
                })?;
                let chain_snapshots = budget.delegation_chain(snapshot, &receipt.capability_id)?;
                let lineage_complete = chain_is_complete(&receipt.capability_id, &chain_snapshots);
                if !lineage_complete {
                    lineage_gap_count = lineage_gap_count.saturating_add(1);
                }

                let chain = chain_snapshots
                    .iter()
                    .map(|snapshot| CostAttributionChainHop {
                        capability_id: snapshot.capability_id.clone(),
                        subject_key: snapshot.subject_key.clone(),
                        issuer_key: snapshot.issuer_key.clone(),
                        delegation_depth: snapshot.delegation_depth,
                        parent_capability_id: snapshot.parent_capability_id.clone(),
                    })
                    .collect::<Vec<_>>();

                let root_subject_key = chain_snapshots
                    .first()
                    .map(|snapshot| snapshot.subject_key.clone())
                    .or_else(|| Some(financial.root_budget_holder.clone()));
                let leaf_subject_key = attribution.subject_key.clone().or_else(|| {
                    chain_snapshots
                        .last()
                        .map(|snapshot| snapshot.subject_key.clone())
                });
                let attempted_cost = financial.attempted_cost.unwrap_or(0);
                let decision = receipt_decision_kind(&receipt).to_string();

                total_cost_charged = checked_report_sum(
                    total_cost_charged,
                    financial.cost_charged,
                    "cost attribution charged-cost total",
                )?;
                total_attempted_cost = checked_report_sum(
                    total_attempted_cost,
                    attempted_cost,
                    "cost attribution attempted-cost total",
                )?;
                max_delegation_depth =
                    max_delegation_depth.max(u64::from(financial.delegation_depth));

                if let Some(root_key) = root_subject_key.clone() {
                    distinct_roots.insert(root_key.clone());
                    budget.groups(distinct_roots.len())?;
                    let root_entry = by_root.entry(root_key.clone()).or_default();
                    root_entry.receipt_count = root_entry.receipt_count.saturating_add(1);
                    root_entry.total_cost_charged = checked_report_sum(
                        root_entry.total_cost_charged,
                        financial.cost_charged,
                        "root charged-cost total",
                    )?;
                    root_entry.total_attempted_cost = checked_report_sum(
                        root_entry.total_attempted_cost,
                        attempted_cost,
                        "root attempted-cost total",
                    )?;
                    root_entry.max_delegation_depth = root_entry
                        .max_delegation_depth
                        .max(u64::from(financial.delegation_depth));

                    if let Some(leaf_key) = leaf_subject_key.clone() {
                        root_entry.leaf_subjects.insert(leaf_key.clone());
                        if !by_leaf.contains_key(&(root_key.clone(), leaf_key.clone())) {
                            budget.groups(by_leaf.len().checked_add(1).ok_or_else(|| {
                                ReceiptStoreError::ReadBoundary(
                                    "cost attribution group count overflow".into(),
                                )
                            })?)?;
                        }
                        let leaf_entry = by_leaf.entry((root_key, leaf_key)).or_default();
                        leaf_entry.receipt_count = leaf_entry.receipt_count.saturating_add(1);
                        leaf_entry.total_cost_charged = checked_report_sum(
                            leaf_entry.total_cost_charged,
                            financial.cost_charged,
                            "leaf charged-cost total",
                        )?;
                        leaf_entry.total_attempted_cost = checked_report_sum(
                            leaf_entry.total_attempted_cost,
                            attempted_cost,
                            "leaf attempted-cost total",
                        )?;
                        leaf_entry.max_delegation_depth = leaf_entry
                            .max_delegation_depth
                            .max(u64::from(financial.delegation_depth));
                    }
                }

                if let Some(leaf_key) = leaf_subject_key.clone() {
                    distinct_leaves.insert(leaf_key);
                    budget.groups(distinct_leaves.len())?;
                }

                if receipts.len() < limit {
                    receipts.push(CostAttributionReceiptRow {
                        seq,
                        receipt_id: receipt.id.clone(),
                        timestamp: receipt.timestamp,
                        capability_id: receipt.capability_id.clone(),
                        tool_server: receipt.tool_server.clone(),
                        tool_name: receipt.tool_name.clone(),
                        decision_kind: decision,
                        root_subject_key,
                        leaf_subject_key,
                        grant_index: Some(financial.grant_index),
                        delegation_depth: u64::from(financial.delegation_depth),
                        cost_charged: financial.cost_charged,
                        attempted_cost: financial.attempted_cost,
                        currency: financial.currency.clone(),
                        budget_total: financial.budget_total,
                        budget_remaining: financial.budget_remaining,
                        settlement_status: Some(financial.settlement_status),
                        payment_reference: financial.payment_reference.clone(),
                        budget_authority: receipt.financial_budget_authority_metadata(),
                        lineage_complete,
                        chain,
                    });
                }
            }

            let mut by_root = by_root
                .into_iter()
                .map(|(root_subject_key, aggregate)| RootCostAttributionRow {
                    root_subject_key,
                    receipt_count: aggregate.receipt_count,
                    total_cost_charged: aggregate.total_cost_charged,
                    total_attempted_cost: aggregate.total_attempted_cost,
                    distinct_leaf_subjects: crate::integer::count(aggregate.leaf_subjects.len()),
                    max_delegation_depth: aggregate.max_delegation_depth,
                })
                .collect::<Vec<_>>();
            by_root.sort_by(|left, right| {
                right
                    .total_cost_charged
                    .cmp(&left.total_cost_charged)
                    .then_with(|| right.receipt_count.cmp(&left.receipt_count))
                    .then_with(|| left.root_subject_key.cmp(&right.root_subject_key))
            });

            let mut by_leaf = by_leaf
                .into_iter()
                .map(
                    |((root_subject_key, leaf_subject_key), aggregate)| LeafCostAttributionRow {
                        root_subject_key,
                        leaf_subject_key,
                        receipt_count: aggregate.receipt_count,
                        total_cost_charged: aggregate.total_cost_charged,
                        total_attempted_cost: aggregate.total_attempted_cost,
                        max_delegation_depth: aggregate.max_delegation_depth,
                    },
                )
                .collect::<Vec<_>>();
            by_leaf.sort_by(|left, right| {
                right
                    .total_cost_charged
                    .cmp(&left.total_cost_charged)
                    .then_with(|| right.receipt_count.cmp(&left.receipt_count))
                    .then_with(|| left.root_subject_key.cmp(&right.root_subject_key))
                    .then_with(|| left.leaf_subject_key.cmp(&right.leaf_subject_key))
            });

            Ok(CostAttributionReport {
                summary: CostAttributionSummary {
                    matching_receipts,
                    returned_receipts: crate::integer::count(receipts.len()),
                    total_cost_charged,
                    total_attempted_cost,
                    max_delegation_depth,
                    distinct_root_subjects: crate::integer::count(distinct_roots.len()),
                    distinct_leaf_subjects: crate::integer::count(distinct_leaves.len()),
                    lineage_gap_count,
                    truncated: matching_receipts > crate::integer::count(receipts.len()),
                },
                by_root,
                by_leaf,
                receipts,
            })
        })();
        owner.finish(result)
    }
}
