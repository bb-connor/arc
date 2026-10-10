//! The base receipt-store contract accepts backends borrowing caller state.
use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
use chio_kernel::{ReceiptStore, ReceiptStoreError};

struct BorrowedReceiptStore<'a> {
    sink_id: &'a str,
}

impl ReceiptStore for BorrowedReceiptStore<'_> {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn durable_sink_id(&self) -> Option<&str> {
        Some(self.sink_id)
    }
}

#[test]
fn receipt_store_accepts_a_backend_borrowing_caller_state() {
    let sink_id = String::from("borrowed-receipt-sink");
    let backend = BorrowedReceiptStore { sink_id: &sink_id };
    let configured: &dyn ReceiptStore = &backend;

    assert_eq!(configured.durable_sink_id(), Some(sink_id.as_str()));
    assert!(configured.native_finishing_owner().is_none());
}
