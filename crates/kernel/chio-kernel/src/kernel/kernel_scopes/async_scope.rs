//! Receipt context owned by one evaluation across polls and cancellation.

use std::future::Future;
use std::sync::Arc;

use arc_swap::ArcSwapOption;

use super::{ReceiptFederationAdmission, RECEIPT_EVALUATION_SCOPE_KEY};

pub(super) struct EvaluationReceiptContext {
    pub(super) tenant_id: ArcSwapOption<String>,
    pub(super) federation_admission: ArcSwapOption<ReceiptFederationAdmission>,
}

tokio::task_local! {
    static EVALUATION_RECEIPT_CONTEXT: Arc<EvaluationReceiptContext>;
}

pub(crate) fn scope_async_receipt_context<F: Future>(future: F) -> impl Future<Output = F::Output> {
    let context = Arc::new(EvaluationReceiptContext {
        tenant_id: ArcSwapOption::empty(),
        federation_admission: ArcSwapOption::empty(),
    });
    RECEIPT_EVALUATION_SCOPE_KEY.scope(
        uuid::Uuid::now_v7().to_string(),
        EVALUATION_RECEIPT_CONTEXT.scope(context, future),
    )
}

pub(super) fn current() -> Option<Arc<EvaluationReceiptContext>> {
    EVALUATION_RECEIPT_CONTEXT.try_with(Arc::clone).ok()
}
