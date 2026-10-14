use std::any::Any;
use std::sync::Arc;

use super::ReceiptStore;

/// Owned receipt sink with its independently captured concrete identity.
///
/// Both private views originate from the same concrete `Arc`. A wrapper retains
/// its own concrete type even if it forwards another store's owner discovery.
/// This registration conveys identity only, never a source, account or loan.
/// Install it through [`crate::ChioKernel::set_native_receipt_store`]. Ordinary
/// receipt-store setters remain available and leave Native owner identity
/// unregistered. Unsupported concrete backends are still refused by the Native
/// adapter even if explicitly registered.
pub struct NativeReceiptStoreRegistration {
    receipt_store: Arc<dyn ReceiptStore>,
    concrete: Arc<dyn Any + Send + Sync>,
}

impl NativeReceiptStoreRegistration {
    pub fn new<T: ReceiptStore + Any>(store: Arc<T>) -> Self {
        Self {
            receipt_store: store.clone(),
            concrete: store,
        }
    }

    /// The receipt sink captured by this registration's single constructor.
    pub fn receipt_store(&self) -> &dyn ReceiptStore {
        self.receipt_store.as_ref()
    }

    /// Downcast the actual registered object, without invoking backend hooks.
    pub fn downcast_ref<T: ReceiptStore + Any>(&self) -> Option<&T> {
        self.concrete.as_ref().downcast_ref()
    }

    pub(crate) fn receipt_store_handle(&self) -> Arc<dyn ReceiptStore> {
        Arc::clone(&self.receipt_store)
    }
}
