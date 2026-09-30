//! Protocol and guard errors carry finite reasons rather than peer text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("urn:chio:error:transport:invalid-request-shape")]
pub enum AcpProtocolError {
    MissingParams {
        method: &'static str,
    },
    EmptyField {
        method: &'static str,
        field: &'static str,
    },
    MalformedField {
        method: &'static str,
        field: &'static str,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("urn:chio:error:guard:denied")]
pub enum AcpGuardError {
    EmptyPath,
    RelativePath,
    PathTraversal,
    PathOutsideScope,
    EmptyAllowlist,
    EmptyCommand,
    CommandOutsideScope,
    ShellArgument,
}
