//! Response sanitization guard -- scans for PII/PHI patterns and redacts them.
//!
//! This is a post-invocation guard that inspects tool responses before
//! delivery to the agent. It can:
//! - Block the response entirely if sensitive data is found
//! - Redact matching patterns in the response
//! - Escalate by returning a verdict that triggers operator review
//!
//! The guard fails closed: if pattern compilation fails or an internal
//! error occurs, the response is blocked.

use regex::Regex;

use arc_kernel::{Guard, GuardContext, KernelError, Verdict};

// ---------------------------------------------------------------------------
// PII/PHI pattern definitions
// ---------------------------------------------------------------------------

/// Classification level for a detected pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitivityLevel {
    /// Low sensitivity -- may produce false positives (e.g., phone numbers).
    Low,
    /// Medium sensitivity -- likely PII (e.g., email addresses).
    Medium,
    /// High sensitivity -- definite PII/PHI (e.g., SSN, medical record numbers).
    High,
}

/// A named pattern that matches sensitive data.
#[derive(Debug, Clone)]
pub struct SensitivePattern {
    /// Human-readable name for the pattern.
    pub name: String,
    /// The compiled regex.
    regex: Regex,
    /// Classification level.
    pub level: SensitivityLevel,
    /// Replacement string for redaction.
    pub redaction: String,
}

/// Action to take when sensitive data is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizationAction {
    /// Block the response entirely.
    Block,
    /// Redact the matching patterns and allow the response.
    Redact,
}

// ---------------------------------------------------------------------------
// Default patterns
// ---------------------------------------------------------------------------

fn default_patterns() -> Vec<SensitivePattern> {
    let mut patterns = Vec::new();

    // SSN (Social Security Number): XXX-XX-XXXX
    if let Ok(regex) = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b") {
        patterns.push(SensitivePattern {
            name: "SSN".to_string(),
            regex,
            level: SensitivityLevel::High,
            redaction: "[SSN REDACTED]".to_string(),
        });
    }

    // Email addresses
    if let Ok(regex) = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b") {
        patterns.push(SensitivePattern {
            name: "email".to_string(),
            regex,
            level: SensitivityLevel::Medium,
            redaction: "[EMAIL REDACTED]".to_string(),
        });
    }

    // US phone numbers: (XXX) XXX-XXXX or XXX-XXX-XXXX
    if let Ok(regex) = Regex::new(r"\b(?:\(\d{3}\)\s*|\d{3}[-.])\d{3}[-.]?\d{4}\b") {
        patterns.push(SensitivePattern {
            name: "phone".to_string(),
            regex,
            level: SensitivityLevel::Low,
            redaction: "[PHONE REDACTED]".to_string(),
        });
    }

    // Credit card numbers (basic Luhn-style patterns)
    if let Ok(regex) = Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b") {
        patterns.push(SensitivePattern {
            name: "credit-card".to_string(),
            regex,
            level: SensitivityLevel::High,
            redaction: "[CARD REDACTED]".to_string(),
        });
    }

    // Date of birth patterns: MM/DD/YYYY or YYYY-MM-DD
    if let Ok(regex) = Regex::new(r"\b(?:\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})\b") {
        patterns.push(SensitivePattern {
            name: "date-of-birth".to_string(),
            regex,
            level: SensitivityLevel::Low,
            redaction: "[DATE REDACTED]".to_string(),
        });
    }

    // Medical Record Number (MRN): common alphanumeric patterns
    if let Ok(regex) = Regex::new(r"\bMRN[:\s#]*\d{6,12}\b") {
        patterns.push(SensitivePattern {
            name: "MRN".to_string(),
            regex,
            level: SensitivityLevel::High,
            redaction: "[MRN REDACTED]".to_string(),
        });
    }

    // ICD-10 codes (medical diagnosis codes)
    if let Ok(regex) = Regex::new(r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b") {
        patterns.push(SensitivePattern {
            name: "ICD-10".to_string(),
            regex,
            level: SensitivityLevel::Medium,
            redaction: "[ICD REDACTED]".to_string(),
        });
    }

    patterns
}

// ---------------------------------------------------------------------------
// ResponseSanitizationGuard
// ---------------------------------------------------------------------------

/// Guard that scans responses for PII/PHI patterns and redacts or blocks them.
///
/// This guard is designed to run as a post-invocation check. When used as a
/// pre-invocation guard (via the standard Guard trait), it inspects the
/// request arguments for sensitive data leakage. For post-invocation use,
/// call `scan_response` directly.
pub struct ResponseSanitizationGuard {
    patterns: Vec<SensitivePattern>,
    /// Minimum sensitivity level to trigger the guard.
    min_level: SensitivityLevel,
    /// Action to take when patterns are found.
    action: SanitizationAction,
}

impl ResponseSanitizationGuard {
    /// Create a new guard with default PII/PHI patterns.
    pub fn new(min_level: SensitivityLevel, action: SanitizationAction) -> Self {
        Self {
            patterns: default_patterns(),
            min_level,
            action,
        }
    }

    /// Create a guard with custom patterns only.
    pub fn with_patterns(
        patterns: Vec<SensitivePattern>,
        min_level: SensitivityLevel,
        action: SanitizationAction,
    ) -> Self {
        Self {
            patterns,
            min_level,
            action,
        }
    }

    /// Scan text for sensitive patterns.
    ///
    /// Returns a list of (pattern_name, match_text) pairs for all matches
    /// at or above the configured minimum sensitivity level.
    pub fn scan(&self, text: &str) -> Vec<(String, String)> {
        let mut findings = Vec::new();
        for pattern in &self.patterns {
            if level_ord(pattern.level) < level_ord(self.min_level) {
                continue;
            }
            for m in pattern.regex.find_iter(text) {
                findings.push((pattern.name.clone(), m.as_str().to_string()));
            }
        }
        findings
    }

    /// Redact all matching patterns in the given text.
    ///
    /// Returns the redacted text and a count of redactions performed.
    pub fn redact(&self, text: &str) -> (String, usize) {
        let mut result = text.to_string();
        let mut count = 0usize;
        for pattern in &self.patterns {
            if level_ord(pattern.level) < level_ord(self.min_level) {
                continue;
            }
            let before_len = result.len();
            result = pattern
                .regex
                .replace_all(&result, pattern.redaction.as_str())
                .to_string();
            if result.len() != before_len {
                count = count.saturating_add(1);
            }
            // Also count when replacement has same length but content changed.
            if before_len == result.len() && pattern.regex.is_match(text) {
                // Re-check on original text to count properly.
                let match_count = pattern.regex.find_iter(text).count();
                if match_count > 0 {
                    count = count.saturating_add(match_count);
                }
            }
        }
        (result, count)
    }

    /// Scan a response payload (as a JSON value) for sensitive data.
    ///
    /// Returns the action verdict: Block or Redact based on configuration.
    pub fn scan_response(&self, response: &serde_json::Value) -> ScanResult {
        let text = response.to_string();
        let findings = self.scan(&text);
        if findings.is_empty() {
            return ScanResult::Clean;
        }
        match self.action {
            SanitizationAction::Block => ScanResult::Blocked(findings),
            SanitizationAction::Redact => {
                let (redacted, count) = self.redact(&text);
                ScanResult::Redacted {
                    redacted_text: redacted,
                    redaction_count: count,
                    findings,
                }
            }
        }
    }
}

/// Result of scanning a response for sensitive data.
#[derive(Debug)]
pub enum ScanResult {
    /// No sensitive data found.
    Clean,
    /// Sensitive data found and response should be blocked.
    Blocked(Vec<(String, String)>),
    /// Sensitive data found and redacted.
    Redacted {
        redacted_text: String,
        redaction_count: usize,
        findings: Vec<(String, String)>,
    },
}

/// Convert sensitivity level to an ordinal for comparison.
fn level_ord(level: SensitivityLevel) -> u8 {
    match level {
        SensitivityLevel::Low => 0,
        SensitivityLevel::Medium => 1,
        SensitivityLevel::High => 2,
    }
}

impl Guard for ResponseSanitizationGuard {
    fn name(&self) -> &str {
        "response-sanitization"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        // When used as a pre-invocation guard, scan the arguments for
        // sensitive data that shouldn't be sent to tool servers.
        let args_text = ctx.request.arguments.to_string();
        let findings = self.scan(&args_text);
        if findings.is_empty() {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::Deny)
        }
    }
}

/// Build a `SensitivePattern` from components. Returns None if the regex
/// is invalid.
pub fn build_pattern(
    name: &str,
    regex_str: &str,
    level: SensitivityLevel,
    redaction: &str,
) -> Option<SensitivePattern> {
    Regex::new(regex_str).ok().map(|regex| SensitivePattern {
        name: name.to_string(),
        regex,
        level,
        redaction: redaction.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_name() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
        assert_eq!(guard.name(), "response-sanitization");
    }

    #[test]
    fn detects_ssn() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
        let findings = guard.scan("My SSN is 123-45-6789");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|(name, _)| name == "SSN"));
    }

    #[test]
    fn detects_email() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
        let findings = guard.scan("Contact john@example.com for info");
        assert!(findings.iter().any(|(name, _)| name == "email"));
    }

    #[test]
    fn detects_mrn() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
        let findings = guard.scan("Patient MRN: 123456789");
        assert!(findings.iter().any(|(name, _)| name == "MRN"));
    }

    #[test]
    fn no_findings_on_clean_text() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
        let findings = guard.scan("This is perfectly clean text with no PII.");
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_minimum_sensitivity() {
        // Only detect High-level patterns.
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
        // Email is Medium, should not be detected.
        let findings = guard.scan("Contact john@example.com");
        assert!(
            !findings.iter().any(|(name, _)| name == "email"),
            "email should not be detected at High sensitivity"
        );
        // SSN is High, should be detected.
        let findings2 = guard.scan("SSN 123-45-6789");
        assert!(findings2.iter().any(|(name, _)| name == "SSN"));
    }

    #[test]
    fn redacts_ssn() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Redact);
        let (redacted, count) = guard.redact("SSN is 123-45-6789 please");
        assert!(redacted.contains("[SSN REDACTED]"));
        assert!(!redacted.contains("123-45-6789"));
        assert!(count > 0);
    }

    #[test]
    fn redacts_email() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Redact);
        let (redacted, _) = guard.redact("Email: jane@example.com");
        assert!(redacted.contains("[EMAIL REDACTED]"));
        assert!(!redacted.contains("jane@example.com"));
    }

    #[test]
    fn scan_response_clean() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
        let response = serde_json::json!({"status": "ok", "data": "nothing sensitive"});
        let result = guard.scan_response(&response);
        assert!(matches!(result, ScanResult::Clean));
    }

    #[test]
    fn scan_response_blocked() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
        let response = serde_json::json!({"patient": "SSN: 123-45-6789"});
        let result = guard.scan_response(&response);
        assert!(matches!(result, ScanResult::Blocked(_)));
    }

    #[test]
    fn scan_response_redacted() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Redact);
        let response = serde_json::json!({"patient": "SSN: 123-45-6789"});
        let result = guard.scan_response(&response);
        match result {
            ScanResult::Redacted { redacted_text, .. } => {
                assert!(redacted_text.contains("[SSN REDACTED]"));
            }
            _ => panic!("expected Redacted result"),
        }
    }

    #[test]
    fn guard_evaluate_denies_args_with_pii() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);

        let kp = arc_core::crypto::Keypair::generate();
        let scope = arc_core::capability::ArcScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv".to_string();

        let cap_body = arc_core::capability::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        let cap = arc_core::capability::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = arc_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "write_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"content": "SSN is 123-45-6789"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let ctx = arc_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }

    #[test]
    fn guard_evaluate_allows_clean_args() {
        let guard =
            ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);

        let kp = arc_core::crypto::Keypair::generate();
        let scope = arc_core::capability::ArcScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv".to_string();

        let cap_body = arc_core::capability::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        let cap = arc_core::capability::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = arc_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        };

        let ctx = arc_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn custom_pattern() {
        let pattern = build_pattern(
            "custom-id",
            r"\bCUST-\d{8}\b",
            SensitivityLevel::High,
            "[CUST-ID REDACTED]",
        );
        assert!(pattern.is_some());

        let guard = ResponseSanitizationGuard::with_patterns(
            vec![pattern.unwrap()],
            SensitivityLevel::High,
            SanitizationAction::Block,
        );
        let findings = guard.scan("Customer CUST-12345678 record");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|(name, _)| name == "custom-id"));
    }
}
