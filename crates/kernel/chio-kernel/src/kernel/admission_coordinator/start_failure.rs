use super::{IdentityDisposition, KernelError};

/// A refused admission and the identity state established at its storage boundary.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub(crate) struct AdmissionStartFailure {
    #[source]
    pub(in crate::kernel) error: Box<KernelError>,
    pub(in crate::kernel) disposition: IdentityDisposition,
}
