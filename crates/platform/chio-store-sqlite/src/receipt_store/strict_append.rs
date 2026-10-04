use super::*;

impl SqliteReceiptStore {
    /// Append new evidence atomically, refusing even an identical duplicate.
    /// Kernel replay uses the separate idempotent ReceiptStore trait method.
    /// A caller deadline does not cancel a transaction the writer already owns.
    pub fn append_new_chio_receipt(
        &self,
        receipt: &ChioReceipt,
        budget: std::time::Duration,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        let receipt = receipt.clone();
        let raw_json = serde_json::to_string(&receipt)?;
        self.writer_handle().run_write_receipt_with_timeout(
            move |tx| {
                ensure_checkpoint_transparency_guards(tx)?;
                let (seq, inserted) =
                    super::append_chio_receipt_tx_with_insert_status(tx, &receipt, &raw_json)?;
                if !inserted {
                    return Err(ReceiptStoreError::Conflict("duplicate receipt id".into()));
                }
                ensure_receipt_lineage_statement_for_receipt_id_tx(tx, &receipt.id)?;
                Ok(seq)
            },
            budget,
        )
    }
}
