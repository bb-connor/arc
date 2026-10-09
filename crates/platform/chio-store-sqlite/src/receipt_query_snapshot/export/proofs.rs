//! Proof trees materialize authenticated hashes of selected checkpoint batches,
//! with a total leaf allowance checked before reading a batch.
use chio_core::{hashing::Hash, merkle::MerkleTree};
use chio_kernel::checkpoint::{build_inclusion_proof, KernelCheckpoint, ReceiptInclusionProof};
use chio_kernel::evidence_export::{EvidenceToolReceiptRecord, EvidenceUncheckpointedReceipt};
use chio_kernel::ReceiptStoreError;
use rusqlite::params;
use std::collections::{BTreeMap, BTreeSet};

use super::Lease;
use crate::evidence_export::http_budget::{refuse, ByteBudget};
use crate::receipt_query_snapshot::db::blob32;

pub(super) fn collect(
    lease: &Lease<'_>,
    tools: &[EvidenceToolReceiptRecord],
    checkpoints: &[KernelCheckpoint],
    limit: u64,
    bytes: &mut ByteBudget,
) -> Result<
    (
        Vec<ReceiptInclusionProof>,
        Vec<EvidenceUncheckpointedReceipt>,
    ),
    ReceiptStoreError,
> {
    let exported = tools
        .iter()
        .map(|tool| (tool.seq, &tool.receipt.id))
        .collect::<BTreeMap<_, _>>();
    let mut used = 0_u64;
    let mut proofs = Vec::new();
    let mut covered = BTreeSet::new();
    for checkpoint in checkpoints {
        let start = checkpoint.body.batch_start_seq;
        let end = checkpoint.body.batch_end_seq;
        let selected = exported
            .range(start..=end)
            .map(|(seq, _)| *seq)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        let leaves_count = end
            .checked_sub(start)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| super::invalid("checkpoint export range is invalid"))?;
        if leaves_count > limit.saturating_sub(used) {
            return Err(refuse("HTTP evidence export proof-leaf allowance; narrow the selected checkpoint batches or use local operator export"));
        }
        used += leaves_count;
        let mut leaves = Vec::new();
        let mut after = start;
        while after <= end {
            let high = after.saturating_add(255).min(end);
            let rows = lease.read(|db| {
                let mut statement = db.connection()?.prepare_cached("SELECT entry_seq, leaf_hash FROM snapshot_tool_receipt INDEXED BY sq_entry WHERE entry_seq >= ?1 AND entry_seq <= ?2 UNION ALL SELECT entry_seq, leaf_hash FROM snapshot_child_cursor WHERE entry_seq >= ?1 AND entry_seq <= ?2 ORDER BY entry_seq")?;
                let rows = statement.query_map(params![crate::integer::checked::<_, i64>(after)?, crate::integer::checked::<_, i64>(high)?], |row| Ok((row.get::<_, i64>(0)?, blob32(row.get::<_, Vec<u8>>(1)?)?)))?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })?;
            if crate::integer::count(rows.len()) != high - after + 1 {
                return lease.invalid("authenticated checkpoint proof range is incomplete");
            }
            for (offset, (seq, hash)) in rows.into_iter().enumerate() {
                if crate::receipt_store::sqlite_u64(seq, "proof claim sequence")?
                    != after + crate::integer::count(offset)
                {
                    return lease.invalid(
                        "authenticated checkpoint proof range repeats or omits a claim entry",
                    );
                }
                leaves.push(Hash::from_bytes(hash));
            }
            after = high + 1;
        }
        let tree =
            MerkleTree::from_hashes(leaves).map_err(|error| super::invalid(error.to_string()))?;
        if tree.root() != checkpoint.body.merkle_root {
            return lease
                .invalid("authenticated checkpoint proof hashes do not reproduce the signed root");
        }
        for seq in selected {
            let proof = build_inclusion_proof(
                &tree,
                crate::integer::checked::<_, usize>(seq - start)?,
                checkpoint.body.checkpoint_seq,
                seq,
            )
            .map_err(|error| super::invalid(error.to_string()))?;
            bytes.charge(&proof)?;
            proofs.push(proof);
            covered.insert(seq);
        }
    }
    let mut uncheckpointed = Vec::new();
    for tool in tools {
        if !covered.contains(&tool.seq) {
            let record = EvidenceUncheckpointedReceipt {
                seq: tool.seq,
                receipt_id: tool.receipt.id.clone(),
            };
            bytes.charge(&record)?;
            uncheckpointed.push(record);
        }
    }
    Ok((proofs, uncheckpointed))
}
