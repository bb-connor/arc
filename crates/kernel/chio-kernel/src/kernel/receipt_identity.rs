//! Signed request identity state, selected by the transition producing a receipt.

use serde_json::{Map, Value};

use crate::admission_operation::RequestNamespaceDigest;
use crate::receipt_support::merge_metadata_objects;

use super::{ChioKernel, KernelError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityDisposition {
    /// No persisted operation, retained custody or executed effect binds the id.
    Reusable,
    /// A submitted durable commit has not yielded an authoritative outcome.
    Retained,
    /// A terminal operation or an executed effect binds the id.
    Terminal,
}

pub(super) fn with_identity_disposition(
    metadata: Option<Value>,
    disposition: IdentityDisposition,
) -> Option<Value> {
    let mut metadata = match metadata {
        Some(Value::Object(object)) => object,
        _ => Map::new(),
    };
    let mut runtime = match metadata.remove("chio_runtime") {
        Some(Value::Object(object)) => object,
        _ => Map::new(),
    };
    let disposition = match disposition {
        IdentityDisposition::Reusable => "reusable",
        IdentityDisposition::Retained => "retained",
        IdentityDisposition::Terminal => "terminal",
    };
    runtime.insert(
        crate::kernel::runtime_field::IDENTITY_DISPOSITION.into(),
        Value::String(disposition.into()),
    );
    metadata.insert("chio_runtime".into(), Value::Object(runtime));
    Some(Value::Object(metadata))
}

/// A refusal's metadata and the identity state selected by its producing row.
#[derive(Debug, Clone)]
pub(crate) struct RefusalReceiptMetadata {
    metadata: Option<Value>,
    disposition: IdentityDisposition,
}

impl RefusalReceiptMetadata {
    pub(in crate::kernel) fn new(
        metadata: Option<Value>,
        disposition: IdentityDisposition,
    ) -> Self {
        Self {
            metadata,
            disposition,
        }
    }

    pub(in crate::kernel) fn into_signed_metadata(
        self,
        namespace: &RequestNamespaceDigest,
    ) -> Option<Value> {
        let mut context = self
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("receipt_context"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        context.insert(
            "request_namespace_digest".into(),
            Value::String(namespace.as_str().into()),
        );
        merge_metadata_objects(
            with_identity_disposition(self.metadata, self.disposition),
            Some(serde_json::json!({ "receipt_context": context })),
        )
    }
}

impl ChioKernel {
    pub(in crate::kernel) fn prepare_refusal_receipt_metadata(
        &self,
        request_id: &str,
        metadata: RefusalReceiptMetadata,
    ) -> Result<Option<Value>, KernelError> {
        let namespace = self.authenticated_receipt_namespace(request_id)?;
        if metadata.disposition == IdentityDisposition::Reusable {
            self.require_unoccupied_receipt_identity(request_id, &namespace)?;
        }
        Ok(metadata.into_signed_metadata(namespace.digest()))
    }
}
