// Kernel-backed CapabilityChecker implementation.
//
// Validates capability tokens for file and terminal operations.
// Fail-closed: any error during validation results in deny.

use arc_core::capability::CapabilityToken;
use arc_core::crypto::PublicKey;

/// Kernel-backed capability checker.
///
/// Validates ACP operations against presented capability tokens.
/// Uses the kernel's public key for trusted-issuer verification,
/// verifies the token signature, and checks time bounds and scope.
pub struct KernelCapabilityChecker {
    /// Trusted kernel public key for verifying token signatures.
    kernel_public_key: PublicKey,
    /// Server ID this checker is bound to.
    server_id: String,
}

impl KernelCapabilityChecker {
    /// Create a new kernel-backed checker.
    pub fn new(kernel_public_key: PublicKey, server_id: impl Into<String>) -> Self {
        Self {
            kernel_public_key,
            server_id: server_id.into(),
        }
    }

    /// Validate a capability token's structure, trust binding, signature, and
    /// time bounds.
    fn validate_token(&self, token_json: &str) -> Result<CapabilityToken, CapabilityCheckError> {
        let token: CapabilityToken = serde_json::from_str(token_json).map_err(|e| {
            CapabilityCheckError::InvalidToken(format!("failed to parse token: {e}"))
        })?;

        if token.issuer != self.kernel_public_key {
            return Err(CapabilityCheckError::SignatureVerificationFailed(
                "token issuer does not match the trusted kernel key".to_string(),
            ));
        }

        let signature_valid = token.verify_signature().map_err(|e| {
            CapabilityCheckError::SignatureVerificationFailed(format!(
                "failed to verify token signature: {e}"
            ))
        })?;
        if !signature_valid {
            return Err(CapabilityCheckError::SignatureVerificationFailed(
                "token signature is invalid".to_string(),
            ));
        }

        // Check time bounds.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // `issued_at` serves as the earliest validity time.
        if now < token.issued_at {
            return Err(CapabilityCheckError::InvalidToken(
                "token not yet valid".to_string(),
            ));
        }

        if now > token.expires_at {
            return Err(CapabilityCheckError::Expired);
        }

        Ok(token)
    }

    /// Check whether a token's scope covers the requested operation.
    fn check_scope(&self, token: &CapabilityToken, operation: &str, resource: &str) -> bool {
        // Check each tool grant in the token's scope for a match.
        for grant in &token.scope.grants {
            // Match the tool name against the operation type.
            let tool_matches = match operation {
                "fs_read" => {
                    grant.tool_name == "fs/read_text_file"
                        || grant.tool_name == "fs/*"
                        || grant.tool_name == "*"
                }
                "fs_write" => {
                    grant.tool_name == "fs/write_text_file"
                        || grant.tool_name == "fs/*"
                        || grant.tool_name == "*"
                }
                "terminal" => {
                    grant.tool_name == "terminal/create"
                        || grant.tool_name == "terminal/*"
                        || grant.tool_name == "*"
                }
                _ => grant.tool_name == "*",
            };

            if !tool_matches {
                continue;
            }

            // Check server scope.
            let server_matches = grant.server_id == "*" || grant.server_id == self.server_id;

            if !server_matches {
                continue;
            }

            // Check resource constraints if present.
            // For PathPrefix constraints, the resource path must start
            // with the prefix. For other constraint types, we skip them
            // (fail open on unknown constraint types within the grant,
            // since the grant itself was already matched by tool name).
            let resource_matches = if grant.constraints.is_empty() {
                true
            } else {
                grant.constraints.iter().any(|c| {
                    matches!(
                        c,
                        arc_core::capability::Constraint::PathPrefix(prefix) if resource.starts_with(prefix.as_str())
                    )
                })
            };

            if resource_matches {
                return true;
            }
        }
        false
    }
}

impl CapabilityChecker for KernelCapabilityChecker {
    fn check_access(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError> {
        // No token presented -- fail closed.
        let token_json = match &request.token {
            Some(t) if !t.is_empty() => t,
            _ => {
                return Ok(AcpVerdict {
                    allowed: false,
                    capability_id: None,
                    reason: "no capability token presented".to_string(),
                });
            }
        };

        // Validate token structure and time bounds.
        let token = match self.validate_token(token_json) {
            Ok(t) => t,
            Err(e) => {
                // Fail closed: validation errors deny access.
                return Ok(AcpVerdict {
                    allowed: false,
                    capability_id: None,
                    reason: format!("token validation failed: {e}"),
                });
            }
        };

        // Check scope.
        if self.check_scope(&token, &request.operation, &request.resource) {
            Ok(AcpVerdict {
                allowed: true,
                capability_id: Some(token.id.clone()),
                reason: "capability token authorized access".to_string(),
            })
        } else {
            Ok(AcpVerdict {
                allowed: false,
                capability_id: Some(token.id.clone()),
                reason: format!(
                    "token scope does not cover {} on {}",
                    request.operation, request.resource
                ),
            })
        }
    }
}
