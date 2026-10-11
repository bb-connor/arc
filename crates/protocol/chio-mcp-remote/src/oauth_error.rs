//! OAuth error vocabulary and local rejection context.
/// OAuth protocol error class, selected by the rejecting domain operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthError {
    InvalidGrant,
    InvalidRequest,
    InvalidScope,
    InvalidTarget,
    ServerError,
    TemporarilyUnavailable,
    UnsupportedGrantType,
    UnsupportedResponseType,
    AccessDenied,
}
impl OAuthError {
    /// OAuth wire spelling.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::AccessDenied => "access_denied",
        }
    }
    /// Registered, input-independent rejection code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ServerError | Self::TemporarilyUnavailable => {
                "urn:chio:error:transport:upstream-failure"
            }
            Self::AccessDenied | Self::InvalidScope | Self::InvalidGrant => {
                "urn:chio:error:policy:decision-denied"
            }
            _ => "urn:chio:error:transport:invalid-request-shape",
        }
    }
}

/// Local context retained in an HTTP response extension; never rendered on the wire.
#[derive(thiserror::Error)]
#[error("{}", .kind.code())]
pub struct OAuthRejection {
    /// Domain error class.
    pub kind: OAuthError,
    detail: String,
}
impl OAuthRejection {
    pub(crate) fn new(kind: OAuthError, detail: &str) -> Self {
        Self {
            kind,
            detail: detail.to_owned(),
        }
    }
    /// Operator-local context. May contain input; do not include in a peer response.
    pub fn local_detail(&self) -> &str {
        &self.detail
    }
}
impl std::fmt::Debug for OAuthRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
