//! Bound lineage metadata before existing validated point readers allocate it.
use super::*;

fn preflight(
    connection: &Connection,
    capability_id: &str,
    budget: &mut ReportReadBudget,
    federated: bool,
) -> Result<bool, ReceiptStoreError> {
    budget.lineage_lookup()?;
    let (from, order, fields) = if federated {
        ("federated_share_capability_lineage l JOIN federated_evidence_shares s ON s.share_id = l.share_id",
         "ORDER BY s.imported_at DESC, s.share_id DESC LIMIT 1",
         "l.capability_id,l.subject_key,l.issuer_key,l.grants_json,l.parent_capability_id,l.federated_parent_capability_id,l.provenance,l.signed_capability_json,s.share_id,s.manifest_hash,s.issuer,s.partner,s.signer_public_key")
    } else {
        ("capability_lineage l", "LIMIT 2", "l.capability_id,l.subject_key,l.issuer_key,l.grants_json,l.parent_capability_id,l.federated_parent_capability_id,l.provenance,l.signed_capability_json")
    };
    let bytes = fields
        .split(',')
        .map(|field| format!("COALESCE(octet_length({field}), 0)"))
        .collect::<Vec<_>>()
        .join(" + ");
    let columns = fields
        .split(',')
        .map(|field| format!("CASE WHEN ({bytes}) <= ?2 THEN {field} END"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT {bytes}, {columns} FROM {from} WHERE l.capability_id = ?1 {order}");
    let mut statement = connection.prepare(&sql)?;
    let metadata_limit = budget.metadata_byte_limit()?;
    let mut rows = statement.query(params![
        capability_id,
        sqlite_i64(metadata_limit, "report encoded lineage byte limit")?
    ])?;
    let Some(row) = rows.next()? else {
        return Ok(false);
    };
    if sqlite_u64(row.get(0)?, "report encoded lineage bytes")? > metadata_limit {
        return Err(budget.refusal(ReportReadExhaustion::RowBytes));
    }
    let mut actual = 0_u64;
    for column in 1..=fields.split(',').count() {
        let size = match row.get_ref(column)? {
            ValueRef::Text(bytes) => crate::integer::count(bytes.len()),
            ValueRef::Null => 0,
            _ => {
                return Err(ReceiptStoreError::Conflict(
                    "report lineage tuple has invalid storage types".into(),
                ))
            }
        };
        actual = actual
            .checked_add(size)
            .filter(|size| *size <= budget.limits.row_bytes)
            .ok_or_else(|| budget.refusal(ReportReadExhaustion::RowBytes))?;
    }
    budget.source_bytes(actual)?;
    for column in [4, 8] {
        if let ValueRef::Text(bytes) = row.get_ref(column)? {
            let raw = std::str::from_utf8(bytes).map_err(|_| {
                ReceiptStoreError::Conflict("report lineage text is not UTF-8".into())
            })?;
            budget.decoded_text(raw)?;
        }
    }
    if !federated && rows.next()?.is_some() {
        return Err(ReceiptStoreError::Conflict(
            "report lineage contains duplicate capability identities".into(),
        ));
    }
    Ok(true)
}

pub(super) fn local(
    connection: &Connection,
    capability_id: &str,
    budget: &mut ReportReadBudget,
) -> Result<Option<CapabilitySnapshot>, ReceiptStoreError> {
    if !preflight(connection, capability_id, budget, false)? {
        return Ok(None);
    }
    SqliteReceiptStore::get_lineage_on_connection(connection, capability_id)
        .map_err(crate::receipt_store::support::capability_lineage_store_error)
}

pub(super) fn chain(
    connection: &Connection,
    capability_id: &str,
    budget: &mut ReportReadBudget,
) -> Result<Vec<CapabilitySnapshot>, ReceiptStoreError> {
    let mut current = Some(capability_id.to_owned());
    let mut seen = BTreeSet::new();
    let mut chain = Vec::new();
    while let Some(id) = current.take() {
        if !seen.insert(id.clone()) {
            return Err(ReceiptStoreError::Conflict(
                "report delegation chain contains a cycle".into(),
            ));
        }
        if chain.len() >= 32 {
            return Err(ReceiptStoreError::Conflict(
                "report delegation chain exceeds 32 capabilities".into(),
            ));
        }
        let snapshot = match local(connection, &id, budget)? {
            Some(snapshot) => Some(snapshot),
            None if preflight(connection, &id, budget, true)? => {
                SqliteReceiptStore::get_federated_share_for_capability_on_connection(
                    connection, &id,
                )?
                .map(|(_, snapshot)| snapshot)
            }
            None => None,
        };
        let Some(snapshot) = snapshot else {
            if chain.is_empty() {
                return Ok(chain);
            }
            return Err(ReceiptStoreError::Conflict(
                "report delegation chain references a missing parent".into(),
            ));
        };
        current = snapshot
            .parent_capability_id
            .clone()
            .or_else(|| snapshot.federated_parent_capability_id.clone());
        chain.push(snapshot);
    }
    chain.reverse();
    Ok(chain)
}
