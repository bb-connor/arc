//! Secret leak guard -- detects potential secret exposure in file writes.
//!
//! Adapted from ClawdStrike's `guards/secret_leak.rs`. Uses regex patterns
//! to detect common API keys, tokens, passwords, and private keys in file
//! write content. This is a critical security guard.

use regex::Regex;

use pact_kernel::{GuardContext, KernelError, Verdict};

use crate::action::{extract_action, ToolAction};

/// Pattern definition for secret detection.
pub struct SecretPattern {
    /// Pattern name (e.g. "aws_access_key").
    pub name: &'static str,
    /// Regex pattern string.
    pub pattern: &'static str,
}

fn default_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "aws_access_key",
            pattern: r"AKIA[0-9A-Z]{16}",
        },
        SecretPattern {
            name: "aws_secret_key",
            pattern: r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"]?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}"#,
        },
        SecretPattern {
            name: "github_token",
            pattern: r"gh[ps]_[A-Za-z0-9]{36}",
        },
        SecretPattern {
            name: "github_pat",
            pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        },
        SecretPattern {
            name: "openai_key",
            pattern: r"sk-[A-Za-z0-9]{48}",
        },
        SecretPattern {
            name: "openai_project_key",
            pattern: r"sk-proj-[A-Za-z0-9]{48,}",
        },
        SecretPattern {
            name: "anthropic_key",
            pattern: r"sk-ant-[A-Za-z0-9\-]{95}",
        },
        SecretPattern {
            name: "anthropic_api03_key",
            pattern: r"sk-ant-api03-[A-Za-z0-9_\-]{93}",
        },
        SecretPattern {
            name: "private_key",
            pattern: r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        },
        SecretPattern {
            name: "npm_token",
            pattern: r"npm_[A-Za-z0-9]{36}",
        },
        SecretPattern {
            name: "slack_token",
            pattern: r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        },
        SecretPattern {
            name: "stripe_secret_key",
            pattern: r"sk_live_[A-Za-z0-9]{24,}",
        },
        SecretPattern {
            name: "stripe_restricted_key",
            pattern: r"rk_live_[A-Za-z0-9]{24,}",
        },
        SecretPattern {
            name: "gcp_service_account",
            pattern: r#""type"\s*:\s*"service_account""#,
        },
        SecretPattern {
            name: "azure_key_vault_token",
            pattern: r#"(?i)azure[_\-]?(?:key[_\-]?vault|kv)[_\-]?(?:secret|token|key)['"]?\s*[:=]\s*['"]?[A-Za-z0-9+/=_\-]{32,}"#,
        },
        SecretPattern {
            name: "gitlab_pat",
            pattern: r#"glpat-[A-Za-z0-9_\-]{20,}"#,
        },
        SecretPattern {
            name: "generic_api_key",
            pattern: r#"(?i)(api[_\-]?key|apikey)[\x27"]?\s*[:=]\s*[\x27"]?[A-Za-z0-9]{32,}"#,
        },
        SecretPattern {
            name: "generic_secret",
            pattern: r#"(?i)(secret|password|passwd|pwd)['"]?\s*[:=]\s*['"]?[A-Za-z0-9!@#$%^&*]{8,}"#,
        },
    ]
}

/// Compiled pattern for matching.
struct CompiledPattern {
    name: String,
    regex: Regex,
}

/// A detected secret match.
#[derive(Clone, Debug)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub offset: usize,
    pub length: usize,
    pub redacted: String,
}

fn mask_value(s: &str) -> String {
    let len = s.chars().count();
    let first = 4usize;
    let last = 4usize;

    if s.is_empty() {
        return String::new();
    }

    if first + last >= len {
        return "*".repeat(len);
    }

    let first_chars: String = s.chars().take(first).collect();
    let last_chars: String = s
        .chars()
        .rev()
        .take(last)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!(
        "{}{}{}",
        first_chars,
        "*".repeat(len - first - last),
        last_chars
    )
}

/// Guard configuration.
pub struct SecretLeakConfig {
    /// Enable/disable this guard.
    pub enabled: bool,
    /// File path patterns to skip (e.g. test fixtures).
    pub skip_paths: Vec<String>,
}

impl Default for SecretLeakConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            skip_paths: vec![
                "**/test/**".to_string(),
                "**/tests/**".to_string(),
                "**/*_test.*".to_string(),
                "**/*.test.*".to_string(),
            ],
        }
    }
}

/// Guard that detects potential secret exposure in file writes.
pub struct SecretLeakGuard {
    enabled: bool,
    patterns: Vec<CompiledPattern>,
    skip_paths: Vec<glob::Pattern>,
}

impl SecretLeakGuard {
    pub fn new() -> Self {
        Self::with_config(SecretLeakConfig::default())
    }

    pub fn with_config(config: SecretLeakConfig) -> Self {
        let patterns = default_patterns()
            .into_iter()
            .filter_map(|p| {
                Regex::new(p.pattern).ok().map(|regex| CompiledPattern {
                    name: p.name.to_string(),
                    regex,
                })
            })
            .collect();

        let skip_paths = config
            .skip_paths
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        Self {
            enabled: config.enabled,
            patterns,
            skip_paths,
        }
    }

    /// Scan content for secrets. Returns a list of matches.
    pub fn scan(&self, content: &[u8]) -> Vec<SecretMatch> {
        let content = match std::str::from_utf8(content) {
            Ok(s) => s,
            Err(_) => return vec![], // Skip binary content.
        };

        let mut matches = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(content) {
                let matched = m.as_str();
                let redacted = mask_value(matched);

                matches.push(SecretMatch {
                    pattern_name: pattern.name.clone(),
                    offset: m.start(),
                    length: m.len(),
                    redacted,
                });
            }
        }
        matches
    }

    /// Check if a path should be skipped (e.g. test fixtures).
    pub fn should_skip_path(&self, path: &str) -> bool {
        for pattern in &self.skip_paths {
            if pattern.matches(path) {
                return true;
            }
        }
        false
    }
}

impl Default for SecretLeakGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl pact_kernel::Guard for SecretLeakGuard {
    fn name(&self) -> &str {
        "secret-leak"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        if !self.enabled {
            return Ok(Verdict::Allow);
        }

        let action = extract_action(&ctx.request.tool_name, &ctx.request.arguments);

        let (path, content) = match &action {
            ToolAction::FileWrite(p, c) => (p.as_str(), c.as_slice()),
            ToolAction::Patch(p, diff) => (p.as_str(), diff.as_bytes()),
            _ => return Ok(Verdict::Allow),
        };

        if self.should_skip_path(path) {
            return Ok(Verdict::Allow);
        }

        let matches = self.scan(content);

        if matches.is_empty() {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::Deny)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pact_kernel::Guard;

    #[test]
    fn detects_aws_access_key() {
        let guard = SecretLeakGuard::new();
        let content = b"aws_key = AKIAIOSFODNN7EXAMPLE";
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "aws_access_key");
    }

    #[test]
    fn detects_github_token() {
        let guard = SecretLeakGuard::new();
        let content = b"token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "github_token");
    }

    #[test]
    fn detects_private_key() {
        let guard = SecretLeakGuard::new();
        let content = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "private_key");
    }

    #[test]
    fn detects_openai_project_key() {
        let guard = SecretLeakGuard::new();
        let content = format!("key = sk-proj-{}", "a".repeat(48));
        let matches = guard.scan(content.as_bytes());
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.pattern_name == "openai_project_key"));
    }

    #[test]
    fn detects_anthropic_api03_key() {
        let guard = SecretLeakGuard::new();
        let content = format!("key = sk-ant-api03-{}", "a".repeat(93));
        let matches = guard.scan(content.as_bytes());
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.pattern_name == "anthropic_api03_key"));
    }

    #[test]
    fn detects_stripe_secret_key() {
        let guard = SecretLeakGuard::new();
        let content = format!("key = sk_live_{}", "a".repeat(24));
        let matches = guard.scan(content.as_bytes());
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.pattern_name == "stripe_secret_key"));
    }

    #[test]
    fn detects_gcp_service_account() {
        let guard = SecretLeakGuard::new();
        let content = br#"{"type": "service_account", "project_id": "test"}"#;
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.pattern_name == "gcp_service_account"));
    }

    #[test]
    fn detects_gitlab_pat() {
        let guard = SecretLeakGuard::new();
        let content = format!("token = glpat-{}", "a".repeat(20));
        let matches = guard.scan(content.as_bytes());
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.pattern_name == "gitlab_pat"));
    }

    #[test]
    fn no_false_positive_on_normal_code() {
        let guard = SecretLeakGuard::new();
        let content = b"This is just normal code\nfn main() { }";
        let matches = guard.scan(content);
        assert!(matches.is_empty());
    }

    #[test]
    fn redaction() {
        assert_eq!(mask_value("short"), "*****");
        assert_eq!(mask_value("AKIAIOSFODNN7EXAMPLE"), "AKIA************MPLE");
    }

    #[test]
    fn skip_paths() {
        let guard = SecretLeakGuard::new();
        assert!(guard.should_skip_path("/app/tests/fixtures/sample.json"));
        assert!(guard.should_skip_path("/app/src/main_test.rs"));
        assert!(!guard.should_skip_path("/app/src/main.rs"));
    }

    #[test]
    fn evaluate_blocks_file_write_with_secret() {
        let guard = SecretLeakGuard::new();

        let kp = pact_core::crypto::Keypair::generate();
        let scope = pact_core::capability::PactScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = pact_core::capability::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        let cap = pact_core::capability::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        // File write containing an OpenAI key.
        let secret_content = format!("api_key = sk-{}", "x".repeat(48));
        let request = pact_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap.clone(),
            tool_name: "write_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "path": "/app/config.py",
                "content": secret_content,
            }),
            dpop_proof: None,
        };

        let ctx = pact_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Deny);

        // Normal file write should be allowed.
        let request2 = pact_kernel::ToolCallRequest {
            request_id: "req-test-2".to_string(),
            capability: cap,
            tool_name: "write_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "path": "/app/main.rs",
                "content": "fn main() { println!(\"Hello\"); }",
            }),
            dpop_proof: None,
        };

        let ctx2 = pact_kernel::GuardContext {
            request: &request2,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result2 = guard.evaluate(&ctx2).expect("evaluate should not error");
        assert_eq!(result2, Verdict::Allow);
    }

    #[test]
    fn evaluate_allows_write_to_test_path() {
        let guard = SecretLeakGuard::new();

        let kp = pact_core::crypto::Keypair::generate();
        let scope = pact_core::capability::PactScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = pact_core::capability::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        let cap = pact_core::capability::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        // Even though content contains a secret, test paths are skipped.
        let secret_content = format!("api_key = sk-{}", "x".repeat(48));
        let request = pact_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "write_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({
                "path": "/app/tests/fixtures/sample.json",
                "content": secret_content,
            }),
            dpop_proof: None,
        };

        let ctx = pact_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Allow);
    }
}
