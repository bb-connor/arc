use crate::capability::AccessMode;
use std::path::PathBuf;

/// Why a path access was denied during a supervised session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// Path is blocked by sandbox policy before approval is consulted
    PolicyBlocked,
    /// Path matches a capability but the requested access mode is not granted
    InsufficientAccess,
    /// User declined the interactive approval prompt
    UserDenied,
    /// Request was rate limited (too many requests)
    RateLimited,
    /// Approval backend returned an error
    BackendError,
}

/// Record of a denied access attempt during a supervised session.
#[derive(Debug, Clone)]
pub struct DenialRecord {
    /// The path that was denied
    pub path: PathBuf,
    /// Access mode requested
    pub access: AccessMode,
    /// Why it was denied
    pub reason: DenialReason,
}

/// Best-effort sandbox violation recovered from OS-native logging.
///
/// On macOS, Seatbelt does not stream deny events back to the supervisor like
/// Linux seccomp-notify does, so diagnostics can supplement denials with
/// unified-log records recovered from sandboxd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxViolation {
    /// Denied operation, such as `file-read-data` or `mach-lookup`.
    pub operation: String,
    /// Optional path or resource associated with the violation.
    pub target: Option<String>,
}

/// Policy explanation for a denied path, resolved from `nono why` logic.
///
/// This carries the enriched query result so the diagnostic can show
/// group names, policy details, and suggested fixes inline rather than
/// asking the user to run `nono why` separately.
#[derive(Debug, Clone)]
pub struct PolicyExplanation {
    /// The denied path.
    pub path: PathBuf,
    /// Access mode that was denied.
    pub access: AccessMode,
    /// Why it was denied: "sensitive_path", "insufficient_access", or "path_not_granted".
    pub reason: String,
    /// Human-readable explanation (e.g. "blocked by group 'ssh' (SSH keys and config)").
    pub details: Option<String>,
    /// Policy source identifier (e.g. "group:ssh").
    pub policy_source: Option<String>,
    /// Suggested CLI flag to fix (e.g. "--read ~/.ssh/id_rsa").
    pub suggested_flag: Option<String>,
}

/// Path-level hint extracted from a command's own error output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPathHint {
    /// The path mentioned in the error output.
    pub path: PathBuf,
    /// Best-effort access mode inferred from the error text.
    pub access: AccessMode,
}

/// Primary classification derived from a command's own error output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorVerdict {
    /// The command likely hit a sandbox-relevant path access issue.
    LikelySandbox(ObservedPathHint),
    /// The command reported a missing path, which is not itself a sandbox denial.
    MissingPath(PathBuf),
    /// The command reported an application-level failure unrelated to permissions.
    NonSandboxFailure(String),
}

/// Best-effort observations extracted from a command's stderr output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorObservation {
    /// Primary diagnosis extracted from the command output.
    pub primary_verdict: Option<ErrorVerdict>,
    /// Name of a protected file referenced in the error output, if any.
    pub blocked_protected_file: Option<String>,
    /// Paths that look like sandbox-denied accesses from stderr.
    pub path_hints: Vec<ObservedPathHint>,
    /// Paths that look missing according to stderr output.
    pub missing_paths: Vec<PathBuf>,
    /// Error text that strongly suggests a non-sandbox application failure.
    pub non_sandbox_failure: Option<String>,
}

impl ErrorObservation {
    #[must_use]
    pub fn has_findings(&self) -> bool {
        self.primary_verdict.is_some()
            || self.blocked_protected_file.is_some()
            || !self.path_hints.is_empty()
            || !self.missing_paths.is_empty()
            || self.non_sandbox_failure.is_some()
    }
}

/// Execution mode for diagnostic context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticMode {
    /// Standard mode: suggest --allow flags for re-run
    Standard,
    /// Supervised mode: interactive expansion available, show denials
    Supervised,
}

/// Context about the command that was executed.
///
/// Used to generate more specific diagnostic messages when a
/// sandboxed command fails.
#[derive(Debug, Clone)]
pub struct CommandContext {
    /// The program name as the user typed it (e.g. "ps", "./script.sh")
    pub program: String,
    /// The resolved absolute path to the binary
    pub resolved_path: PathBuf,
    /// Original argv passed to the top-level command
    pub args: Vec<String>,
}

/// Strip control characters and ANSI escape sequences from a string.
///
/// Prevents terminal injection from attacker-controlled program names
/// or paths appearing in diagnostic output.
pub(super) fn sanitize_for_diagnostic(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip ESC and the entire escape sequence
            if let Some(next) = chars.next() {
                if next == '[' {
                    for seq_char in chars.by_ref() {
                        if seq_char.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            }
        } else if c.is_control() {
            // Strip all control characters
        } else {
            result.push(c);
        }
    }
    result
}
