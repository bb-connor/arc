//! Original contractual authority plus receiver-verified refund, never RPC consent.
use super::{
    native::Native,
    settlement::{self, Action, Prepared},
    waiver_terms,
};
use crate::common::{self, digest, Result};
use chio_kernel::{payment::*, ToolCallRequest};
use serde_json::{json, Value};
use std::path::Path;

pub(super) fn resolve(
    state: &Path,
    native: &Native,
    request: &ToolCallRequest,
    checkpoint: &super::Checkpoint,
) -> Result<Value> {
    let entry = native
        .journal
        .by_request(&request.request_id)?
        .ok_or("original refund entry missing")?;
    entry.agreement.validate(&native.policy, request)?;
    let terms = entry
        .agreement
        .body
        .capture_waiver_terms
        .as_ref()
        .ok_or("original agreement did not authorize capture waiver")?;
    let prepared: Prepared = native
        .journal
        .retained(&entry.allocation, "refund")?
        .ok_or("refund intent absent")?;
    let action = settlement::request(&entry, Action::Refund, &native.policy, &native.journal)?;
    let refund = settlement::observe(&prepared, &action, &native.policy, native.source.as_ref())?;
    settlement::retain_observation(&native.journal, &entry.allocation, &refund)?;
    let operation_id = entry
        .operation
        .as_deref()
        .ok_or("refund original operation missing")?;
    let store = native.authority.admission_operation_store();
    let fence = native.authority.mutation_fence();
    let policy = waiver_terms::policy(&native.policy);
    let resolution: ContractualCaptureWaiverRequestV1 = match native
        .journal
        .retained(&entry.allocation, "capture-waiver")?
    {
        Some(retained) => retained,
        None => {
            let source = store.capture_waiver_source(operation_id, &fence)?;
            let observer = common::key(&state.join("verifier"))?;
            if observer.public_key() != policy.observation_key {
                return Err("refund observation key differs from original policy".into());
            }
            let observation = SignedCaptureWaiverObservationV1::sign(
                CaptureWaiverObservationV1 {
                    terms_digest: digest(terms)?,
                    operation_id: operation_id.into(),
                    journal_digest: digest(&source.journal)?,
                    raw_output_digest: source.raw_output_digest,
                    contract_context_digest: waiver_terms::context(
                        &native.policy,
                        &entry.agreement.body.work,
                    )?,
                    agreement_digest: digest(&entry.agreement.body)?,
                    allocation_id: entry.allocation.clone(),
                    refund_reference: refund.transaction_hash.clone(),
                    evidence_digest: refund.observation_sha256,
                    observed_at_unix_ms: super::now_ms()?,
                },
                &observer,
            )?;
            let resolution = ContractualCaptureWaiverRequestV1 {
                terms: terms.clone(),
                observation,
            };
            native
                .journal
                .retain(&entry.allocation, "capture-waiver", &resolution)?;
            resolution
        }
    };
    let observed = &resolution.observation.body;
    if digest(&resolution.terms)? != digest(terms)?
        || observed.operation_id != operation_id
        || observed.agreement_digest != digest(&entry.agreement.body)?
        || observed.allocation_id != entry.allocation
        || observed.refund_reference != refund.transaction_hash
        || observed.contract_context_digest
            != waiver_terms::context(&native.policy, &entry.agreement.body.work)?
    {
        return Err("retained waiver changed original funding or refund authority".into());
    }
    checkpoint("after-resolution-retained")?;
    let accepted = store.begin_capture_waiver(&policy, &resolution, &fence, super::now_ms()?)?;
    checkpoint("after-resolution-accepted")?;
    let completed = if accepted.is_complete() {
        accepted
    } else {
        store.complete_capture_waiver(
            operation_id,
            &digest(&resolution)?,
            &fence,
            super::now_ms()?,
        )?
    };
    checkpoint("after-resolution-completed")?;
    Ok(
        json!({"resolutionSha256":digest(&resolution)?,"recordSha256":digest(&completed)?,
        "refundTransaction":observed.refund_reference,"resolved":completed.is_complete()}),
    )
}

pub(super) fn original_sources(
    state: &Path,
    native: &Native,
    request: &ToolCallRequest,
) -> Result<Value> {
    use chio_kernel::tool_outcome::ToolOutcomeStore;
    use rusqlite::{types::ValueRef, Connection, OpenFlags};
    let connection = Connection::open_with_flags(
        state.join("authority.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut hashes = serde_json::Map::new();
    for table in [
        "payment_journal",
        "budget_mutation_events",
        "budget_authorization_holds",
    ] {
        let mut statement = connection.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| {
                        Ok(match row.get_ref(index)? {
                            ValueRef::Null => Value::Null,
                            ValueRef::Integer(value) => json!(value),
                            ValueRef::Real(value) => json!(value),
                            ValueRef::Text(value) => json!(String::from_utf8_lossy(value)),
                            ValueRef::Blob(value) => json!(chio_core_types::sha256_hex(value)),
                        })
                    })
                    .collect::<rusqlite::Result<Vec<Value>>>()
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        hashes.insert(table.into(), json!(digest(&rows)?));
    }
    // Auditing source identity must not export a receipt or claim a finalizer
    // lease on the exclusive financial-resolution handle.
    let operation = native
        .operation(request)?
        .ok_or("original operation missing")?;
    let raw = native
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .ok_or("original native return missing")?;
    hashes.insert("rawOutcome".into(), json!(digest(&raw.to_persisted())?));
    Ok(Value::Object(hashes))
}

pub(super) fn financial(state: &Path, native: &Native, request: &ToolCallRequest) -> Result<Value> {
    use chio_kernel::{admission_operation::AdmissionTerminalReplay, ReceiptStore};
    let operation = native
        .operation(request)?
        .ok_or("resolved operation missing")?;
    let Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) = operation.terminal_replay()
    else {
        return Err("resolved operation has no terminal receipt".into());
    };
    let receipt = chio_store_sqlite::SqliteReceiptStore::open(state.join("receipts.sqlite"))?
        .load_retained_chio_receipt(receipt_id.as_str())?
        .ok_or("resolved receipt missing")?;
    if receipt.kernel_key != native.policy.provider_key || !receipt.verify_signature()? {
        return Err("resolved receipt signature invalid".into());
    }
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .cloned()
        .ok_or_else(|| "resolved financial metadata absent".into())
}
