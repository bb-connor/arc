use super::ProviderAttemptBindingV1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchTransport {
    /// A tool server registered with this kernel.
    KernelToolServer,
    /// The caller's own report of an execution that happened elsewhere.
    CallerReport,
}

pub(crate) const CALLER_REPORT_TRANSPORT_PREFIX: &str =
    ProviderAttemptBindingV1::CALLER_REPORT_TRANSPORT_PREFIX;

impl DispatchTransport {
    pub(crate) fn transport_id(self, server_id: &str) -> String {
        match self {
            Self::KernelToolServer => format!("kernel-tool-server:{server_id}"),
            Self::CallerReport => format!("{CALLER_REPORT_TRANSPORT_PREFIX}{server_id}"),
        }
    }
}

/// Whether a registered provider attempt binds the caller-report transport.
pub(crate) fn is_caller_report_attempt(attempt: &ProviderAttemptBindingV1) -> bool {
    attempt.is_caller_report()
}
