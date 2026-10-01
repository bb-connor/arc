//! Diagnostic output formatter for sandbox policy.
//!
//! This module provides human and agent-readable diagnostic output
//! when sandboxed commands fail. The output helps identify whether
//! the failure was due to sandbox restrictions.
//!
//! # Design Principles
//!
//! - **Unmistakable boundary**: Diagnostics render as a dedicated `nono diagnostic`
//!   block so they remain easy to distinguish from command output
//! - **May vs was**: Phrased as "may be due to" not "was caused by"
//!   because the non-zero exit could be unrelated to the sandbox
//! - **Actionable**: Provides specific flags to grant additional access
//! - **Mode-aware**: Different guidance for supervised vs standard mode
//! - **Library code**: No process management, no CLI assumptions

use crate::capability::{AccessMode, CapabilitySet, CapabilitySource};
use crate::path::try_canonicalize;
use std::path::{Path, PathBuf};

mod context;
pub use context::{CommandContext, DenialReason, DenialRecord, DiagnosticMode, ErrorObservation,
    ErrorVerdict, ObservedPathHint, PolicyExplanation, SandboxViolation};
use context::sanitize_for_diagnostic;

/// Parse best-effort denial hints from a command's stderr output.
#[must_use]
pub fn analyze_error_output(
    error_output: &str,
    protected_paths: &[PathBuf],
    current_dir: Option<&Path>,
) -> ErrorObservation {
    let mut blocked_protected_file = None;
    let mut observed = std::collections::BTreeMap::<PathBuf, AccessMode>::new();
    let mut missing = std::collections::BTreeSet::<PathBuf>::new();
    let mut pending_relative_write: Option<PathBuf> = None;
    let mut pending_structured_access_denial = false;
    let mut pending_structured_access: Option<AccessMode> = None;
    let mut non_sandbox_failure = None;

    for line in error_output.lines() {
        if blocked_protected_file.is_none() {
            blocked_protected_file = detect_protected_file_in_error_line(protected_paths, line);
        }

        if non_sandbox_failure.is_none() {
            non_sandbox_failure = detect_non_sandbox_failure_line(line);
        }

        if let Some(path) =
            current_dir.and_then(|cwd| extract_relative_write_path_from_line(line, cwd))
        {
            pending_relative_write = Some(path);
        }

        if looks_like_structured_access_denial_code(line) {
            pending_structured_access_denial = true;
        }

        if pending_structured_access_denial {
            if let Some(access) = infer_access_from_structured_syscall_line(line) {
                pending_structured_access = Some(access);
            }

            if let (Some(path), Some(access)) = (
                extract_structured_path_property(line),
                pending_structured_access,
            ) {
                observed
                    .entry(path)
                    .and_modify(|existing| *existing = merge_access_modes(*existing, access))
                    .or_insert(access);
                pending_structured_access_denial = false;
                pending_structured_access = None;
                continue;
            }
        }

        if looks_like_missing_path(line) {
            if let Some(path) = extract_denied_path_from_error_line(line) {
                missing.insert(path);
            }
            continue;
        }

        if !looks_like_access_denial(line) {
            continue;
        }

        let Some(path) =
            extract_denied_path_from_error_line(line).or_else(|| pending_relative_write.clone())
        else {
            continue;
        };
        let access = if extract_denied_path_from_error_line(line).is_some() {
            infer_access_from_error_line(line, &path)
        } else {
            AccessMode::Write
        };

        observed
            .entry(path)
            .and_modify(|existing| *existing = merge_access_modes(*existing, access))
            .or_insert(access);
        pending_relative_write = None;
    }

    let path_hints = observed
        .into_iter()
        .map(|(path, access)| ObservedPathHint { path, access })
        .collect::<Vec<_>>();
    let primary_verdict = missing
        .iter()
        .next()
        .cloned()
        .map(ErrorVerdict::MissingPath)
        .or_else(|| {
            non_sandbox_failure
                .clone()
                .map(ErrorVerdict::NonSandboxFailure)
        })
        .or_else(|| path_hints.first().cloned().map(ErrorVerdict::LikelySandbox));

    ErrorObservation {
        primary_verdict,
        blocked_protected_file,
        path_hints,
        missing_paths: missing.into_iter().collect(),
        non_sandbox_failure,
    }
}

fn detect_non_sandbox_failure_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("eexist")
        || lower.contains("file already exists")
        || lower.contains("already exists")
    {
        return Some(trimmed.to_string());
    }

    // Version requirement errors are never sandbox-related
    if lower.contains("version must be at least")
        || lower.contains("requires version")
        || lower.contains("minimum version")
        || lower.contains("upgrade your")
    {
        return Some(trimmed.to_string());
    }

    None
}

fn detect_protected_file_in_error_line(
    protected_paths: &[PathBuf],
    error_line: &str,
) -> Option<String> {
    for path in protected_paths {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if error_line.contains(name) {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn looks_like_access_denial(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("read-only file system")
}

fn looks_like_structured_access_denial_code(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    (lower.contains("eperm") || lower.contains("eacces")) && looks_like_access_denial(line)
}

fn looks_like_missing_path(line: &str) -> bool {
    line.to_ascii_lowercase()
        .contains("no such file or directory")
}

fn render_diagnostic_block(body: &str) -> String {
    let mut lines = Vec::new();

    for line in body.lines() {
        if line == "[nono]" {
            lines.push(String::new());
        } else if let Some(stripped) = line.strip_prefix("[nono] ") {
            lines.push(stripped.to_string());
        } else if let Some(stripped) = line.strip_prefix("[nono]") {
            lines.push(stripped.to_string());
        } else {
            lines.push(line.to_string());
        }
    }

    lines.join("\n")
}

fn format_command_failed_line(exit_code: i32) -> String {
    format!("[nono] Command exited with code {}.", exit_code)
}

fn format_command_failed_not_sandbox_line(exit_code: i32) -> String {
    format!(
        "[nono] The command failed, but this does not look like a sandbox denial. (exit code {})",
        exit_code
    )
}

fn format_command_succeeded_with_stderr_line() -> String {
    "[nono] The command succeeded, but stderr showed a likely sandbox-related access issue."
        .to_string()
}

fn extract_denied_path_from_error_line(line: &str) -> Option<PathBuf> {
    if let Some(path) = extract_path_after_syscall_word(line) {
        return Some(path);
    }

    let denial_markers = [
        "Operation not permitted",
        "Permission denied",
        "Read-only file system",
    ];

    let prefix = denial_markers
        .iter()
        .find_map(|marker| line.find(marker).map(|idx| &line[..idx]))
        .unwrap_or(line);

    for segment in prefix.rsplit(':') {
        if let Some(path) = extract_path_from_segment(segment) {
            return Some(path);
        }
    }

    extract_path_from_segment(prefix).or_else(|| extract_path_from_segment(line))
}

fn extract_path_after_syscall_word(line: &str) -> Option<PathBuf> {
    const MARKERS: &[&str] = &["mkdir", "mkdtemp", "open", "copyfile", "rename", "unlink"];

    let lower = line.to_ascii_lowercase();
    for marker in MARKERS {
        let needle = format!("{marker} ");
        let Some(idx) = lower.find(&needle) else {
            continue;
        };
        let segment = line.get(idx + needle.len()..)?;
        if let Some(path) = extract_path_from_segment(segment) {
            return Some(path);
        }
    }

    None
}

fn infer_access_from_structured_syscall_line(line: &str) -> Option<AccessMode> {
    let syscall = extract_structured_string_property(line, "syscall")?;
    Some(match syscall.to_ascii_lowercase().as_str() {
        "mkdir" | "mkdtemp" | "rmdir" | "unlink" | "rename" | "write" | "copyfile" | "chmod"
        | "chown" | "utimes" => AccessMode::Write,
        _ => AccessMode::ReadWrite,
    })
}

fn extract_structured_path_property(line: &str) -> Option<PathBuf> {
    extract_structured_string_property(line, "path").map(PathBuf::from)
}

fn extract_structured_string_property(line: &str, key: &str) -> Option<String> {
    let trimmed = line.trim();
    let after_key = trimmed
        .strip_prefix(key)
        .or_else(|| trimmed.strip_prefix(&format!("\"{key}\"")))
        .or_else(|| trimmed.strip_prefix(&format!("'{key}'")))?;
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    let quote = after_colon.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after_quote = after_colon.get(quote.len_utf8()..)?;
    let mut value = String::new();
    let mut escaped = false;
    let mut found_end = false;

    for ch in after_quote.chars() {
        if escaped {
            if ch == quote || ch == '\\' {
                value.push(ch);
            } else {
                value.push('\\');
                value.push(ch);
            }
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == quote {
            found_end = true;
            break;
        }

        value.push(ch);
    }

    if !found_end {
        return None;
    }

    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_string())
}

fn extract_relative_write_path_from_line(line: &str, current_dir: &Path) -> Option<PathBuf> {
    let lower = line.to_ascii_lowercase();
    let markers = ["creating empty ", "creating ", "create ", "writing "];

    let marker = markers.iter().find(|marker| lower.contains(**marker))?;
    let start = lower.find(marker)? + marker.len();
    let candidate = line.get(start..)?.split_whitespace().next()?;
    let candidate = candidate
        .trim_matches(|c: char| {
            matches!(
                c,
                '\'' | '"' | '`' | ',' | ':' | ';' | '(' | ')' | '[' | ']'
            )
        })
        .trim_end_matches('.')
        .trim();

    if candidate.is_empty()
        || candidate.starts_with('/')
        || candidate.starts_with('~')
        || candidate.starts_with('-')
        || candidate.chars().any(char::is_control)
    {
        return None;
    }

    Some(current_dir.join(candidate))
}

fn extract_path_from_segment(segment: &str) -> Option<PathBuf> {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Strip a leading quote if the path is quoted (e.g. '/bin/ls' or "/bin/ls")
    let (unquoted, closing_quote) = if trimmed.starts_with('\'') || trimmed.starts_with('"') {
        let quote = trimmed.as_bytes()[0] as char;
        (&trimmed[1..], Some(quote))
    } else {
        (trimmed, None)
    };

    let tilde_idx = unquoted.find("~/");
    let slash_idx = unquoted.find('/');
    let start = match (tilde_idx, slash_idx) {
        (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }?;

    let after_start = &unquoted[start..];

    // Terminate the path at the closing quote (if we stripped an opening one)
    // or at any character that cannot appear in a filesystem path.
    let end = if let Some(q) = closing_quote {
        after_start.find(q).unwrap_or(after_start.len())
    } else {
        after_start
            .find(['\'', '"', '`', ')', '(', '<', '>'])
            .unwrap_or(after_start.len())
    };

    let candidate = after_start[..end].trim();
    if candidate.is_empty() || candidate.chars().any(char::is_control) {
        return None;
    }

    Some(PathBuf::from(candidate))
}

fn infer_access_from_error_line(line: &str, path: &Path) -> AccessMode {
    let lower = line.to_ascii_lowercase();

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if matches!(
            name,
            ".profile" | ".bash_profile" | ".bashrc" | ".zprofile" | ".zshrc" | ".zlogin"
        ) {
            return AccessMode::Read;
        }
    }

    if lower.contains("cannot create")
        || lower.contains("can't create")
        || lower.contains("write error")
        || lower.contains("read-only file system")
        || lower.contains("operation not permitted, mkdir ")
        || lower.contains("permission denied, mkdir ")
        || lower.contains("eperm") && lower.contains("mkdir ")
        || lower.contains("eacces") && lower.contains("mkdir ")
        || lower.starts_with("tee:")
        || lower.starts_with("touch:")
        || lower.starts_with("mkdir:")
        || lower.starts_with("mktemp:")
        || lower.starts_with("install:")
        || lower.starts_with("cp:")
        || lower.starts_with("mv:")
        || lower.starts_with("rm:")
        || lower.starts_with("ln:")
        || lower.starts_with("chmod:")
        || lower.starts_with("chown:")
        || lower.starts_with("truncate:")
    {
        return AccessMode::Write;
    }

    if lower.contains("cannot open")
        || lower.contains("can't open")
        || lower.starts_with("cat:")
        || lower.starts_with("grep:")
        || lower.starts_with("sed:")
        || lower.starts_with("awk:")
        || lower.starts_with("head:")
        || lower.starts_with("tail:")
        || lower.starts_with("less:")
        || lower.starts_with("more:")
        || lower.starts_with("find:")
        || lower.starts_with("ls:")
    {
        return AccessMode::Read;
    }

    AccessMode::ReadWrite
}

/// Formats diagnostic information about sandbox policy.
///
/// This is library code that can be used by any parent process
/// that wants to explain sandbox denials to users or AI agents.
pub struct DiagnosticFormatter<'a> {
    caps: &'a CapabilitySet,
    mode: DiagnosticMode,
    denials: &'a [DenialRecord],
    sandbox_violations: &'a [SandboxViolation],
    /// Paths that are write-protected due to trust verification
    protected_paths: &'a [PathBuf],
    /// Primary verdict extracted from the command output.
    primary_verdict: Option<ErrorVerdict>,
    /// Name of a protected file that was detected in the error output
    blocked_protected_file: Option<String>,
    /// Best-effort path hints extracted from the command's own error output.
    observed_path_hints: Vec<ObservedPathHint>,
    /// Best-effort missing path hints extracted from the command's own error output.
    missing_path_hints: Vec<PathBuf>,
    /// Error text that strongly suggests a non-sandbox application failure.
    non_sandbox_failure: Option<String>,
    /// Command that was executed (for context-aware diagnostics)
    command: Option<CommandContext>,
    /// Directory the child process started in.
    current_dir: Option<&'a Path>,
    /// Session ID for `nono grant` suggestions in supervised mode.
    session_id: Option<String>,
    /// Policy explanations for denied paths, resolved from `query_path`.
    policy_explanations: Vec<PolicyExplanation>,
}

impl<'a> DiagnosticFormatter<'a> {
    /// Create a new formatter for the given capability set.
    #[must_use]
    pub fn new(caps: &'a CapabilitySet) -> Self {
        Self {
            caps,
            mode: DiagnosticMode::Standard,
            denials: &[],
            sandbox_violations: &[],
            protected_paths: &[],
            primary_verdict: None,
            blocked_protected_file: None,
            observed_path_hints: Vec::new(),
            missing_path_hints: Vec::new(),
            non_sandbox_failure: None,
            command: None,
            current_dir: None,
            session_id: None,
            policy_explanations: Vec::new(),
        }
    }

    /// Set the diagnostic mode (standard or supervised).
    #[must_use]
    pub fn with_mode(mut self, mode: DiagnosticMode) -> Self {
        self.mode = mode;
        self
    }

    /// Add denial records from a supervised session.
    #[must_use]
    pub fn with_denials(mut self, denials: &'a [DenialRecord]) -> Self {
        self.denials = denials;
        self
    }

    /// Add OS-native sandbox violation records.
    #[must_use]
    pub fn with_sandbox_violations(mut self, violations: &'a [SandboxViolation]) -> Self {
        self.sandbox_violations = violations;
        self
    }

    /// Add paths that are write-protected due to trust verification.
    ///
    /// These are signed instruction files that the sandbox protects from
    /// modification even when the parent directory has write access.
    #[must_use]
    pub fn with_protected_paths(mut self, paths: &'a [PathBuf]) -> Self {
        self.protected_paths = paths;
        self
    }

    /// Set the name of a protected file that was detected in the error output.
    ///
    /// When set, the diagnostic will highlight that a write to a signed
    /// instruction file was blocked.
    #[must_use]
    pub fn with_blocked_protected_file(mut self, name: Option<String>) -> Self {
        self.blocked_protected_file = name;
        self
    }

    /// Set best-effort observations extracted from the command's stderr output.
    #[must_use]
    pub fn with_error_observation(mut self, observation: ErrorObservation) -> Self {
        self.primary_verdict = observation.primary_verdict;
        self.blocked_protected_file = observation.blocked_protected_file;
        self.observed_path_hints = observation.path_hints;
        self.missing_path_hints = observation.missing_paths;
        self.non_sandbox_failure = observation.non_sandbox_failure;
        self
    }

    /// Set command context for more specific diagnostics.
    #[must_use]
    pub fn with_command(mut self, command: CommandContext) -> Self {
        self.command = Some(command);
        self
    }

    /// Set the child process working directory for cwd-relative diagnostics.
    #[must_use]
    pub fn with_current_dir(mut self, current_dir: &'a Path) -> Self {
        self.current_dir = Some(current_dir);
        self
    }

    /// Set the session ID for `nono grant` suggestions in supervised mode.
    #[must_use]
    pub fn with_session_id(mut self, session_id: Option<String>) -> Self {
        self.session_id = session_id;
        self
    }

    /// Add policy explanations for denied paths.
    ///
    /// These are resolved from `query_path` in the CLI layer and provide
    /// group names, policy details, and suggested fixes so the diagnostic
    /// can show them inline.
    #[must_use]
    pub fn with_policy_explanations(mut self, explanations: Vec<PolicyExplanation>) -> Self {
        self.policy_explanations = explanations;
        self
    }

    /// Check if an error line mentions any protected file and return the filename.
    ///
    /// This is used by the output processor to detect when a permission error
    /// is specifically due to a signed instruction file being write-protected.
    #[must_use]
    pub fn detect_protected_file_in_error(&self, error_line: &str) -> Option<String> {
        detect_protected_file_in_error_line(self.protected_paths, error_line)
    }

    /// Format the diagnostic footer for a failed command.
    ///
    /// Returns a multi-line string formatted as a dedicated diagnostic block.
    /// The output is designed to be printed to stderr.
    #[must_use]
    pub fn format_footer(&self, exit_code: i32) -> String {
        let body = match self.mode {
            DiagnosticMode::Standard => self.format_standard_footer(exit_code),
            DiagnosticMode::Supervised => self.format_supervised_footer(exit_code),
        };
        render_diagnostic_block(&body)
    }

    /// Check whether the resolved binary path falls under any allowed read path.
    fn is_binary_path_readable(&self) -> bool {
        let cmd = match &self.command {
            Some(c) => c,
            None => return true, // no context, assume readable
        };
        let binary_path = &cmd.resolved_path;
        for cap in self.caps.fs_capabilities() {
            if cap.access == AccessMode::Read || cap.access == AccessMode::ReadWrite {
                if cap.is_file {
                    if *binary_path == cap.resolved {
                        return true;
                    }
                } else if binary_path.starts_with(&cap.resolved) {
                    return true;
                }
            }
        }
        false
    }

    /// Check whether the binary's parent directory is readable in the sandbox.
    fn is_binary_dir_readable(&self) -> bool {
        let cmd = match &self.command {
            Some(c) => c,
            None => return true,
        };
        let binary_dir = match cmd.resolved_path.parent() {
            Some(d) => d,
            None => return false,
        };
        for cap in self.caps.fs_capabilities() {
            if !cap.is_file
                && (cap.access == AccessMode::Read || cap.access == AccessMode::ReadWrite)
                && binary_dir.starts_with(&cap.resolved)
            {
                return true;
            }
        }
        false
    }

    /// Format context-aware explanation for the exit code.
    ///
    /// Returns a vec of diagnostic lines explaining what likely
    /// happened and what the user can do about it.
    fn format_exit_explanation(&self, exit_code: i32) -> Vec<String> {
        let mut lines = Vec::new();

        match exit_code {
            127 => {
                // 127 = command not found (shell convention) or execve failed.
                // When we resolved the program path, prefer the broader wording.
                let headline = if self.command.is_some() {
                    "[nono] Failed to execute command (exit code 127)."
                } else {
                    "[nono] Command not found (exit code 127)."
                };
                lines.push(headline.to_string());
                lines.push("[nono]".to_string());

                if let Some(ref cmd) = self.command {
                    let program = sanitize_for_diagnostic(&cmd.program);
                    let path = sanitize_for_diagnostic(&cmd.resolved_path.display().to_string());
                    if !self.is_binary_path_readable() {
                        // The binary exists (we resolved it) but the sandbox
                        // can't read it.
                        lines.push(format!(
                            "[nono] The executable '{}' was resolved at:",
                            program,
                        ));
                        lines.push(format!("[nono]   {}", path));
                        lines.push(
                            "[nono] but its directory is not readable inside the sandbox."
                                .to_string(),
                        );
                        lines.push("[nono]".to_string());

                        if let Some(parent) = cmd.resolved_path.parent() {
                            let parent_path =
                                sanitize_for_diagnostic(&parent.display().to_string());
                            lines.push(
                                "[nono] Fix: grant read access to the binary's directory:"
                                    .to_string(),
                            );
                            lines.push(format!("[nono]   nono run --read {} ...", parent_path,));
                        }
                    } else if !self.is_binary_dir_readable() {
                        // Binary itself is allowed but its directory isn't
                        // (unlikely but possible with file-level grants)
                        lines.push(format!(
                            "[nono] '{}' resolved to {} but the directory",
                            program, path,
                        ));
                        lines.push(
                            "[nono] may not be accessible. The sandbox needs read access to"
                                .to_string(),
                        );
                        lines.push("[nono] the directory containing the binary.".to_string());
                    } else {
                        // Binary path is readable — the command may depend on
                        // a dynamic linker, shared libraries, or shell that
                        // isn't accessible.
                        lines.push(format!(
                            "[nono] '{}' resolved to {} and is readable,",
                            program, path,
                        ));
                        lines.push("[nono] but execution still failed. Common causes:".to_string());
                        lines.push(
                            "[nono]   - A shared library or dynamic linker path is not accessible"
                                .to_string(),
                        );
                        lines.push(
                            "[nono]   - The binary is a script whose interpreter is not accessible"
                                .to_string(),
                        );
                        lines.push(
                            "[nono]   - The binary depends on a path not in the sandbox"
                                .to_string(),
                        );
                        lines.push("[nono]".to_string());
                        lines.push(
                            "[nono] Run with -v to see all allowed paths and check if".to_string(),
                        );
                        lines.push("[nono] required system directories are included.".to_string());
                    }
                } else {
                    lines.push(
                        "[nono] The command binary could not be found or executed inside"
                            .to_string(),
                    );
                    lines.push(
                        "[nono] the sandbox. Ensure the binary's directory is readable."
                            .to_string(),
                    );
                }
            }
            126 => {
                // 126 = command found but not executable
                lines.push("[nono] Permission denied (exit code 126).".to_string());
                lines.push("[nono]".to_string());

                if let Some(ref cmd) = self.command {
                    let program = sanitize_for_diagnostic(&cmd.program);
                    let path = sanitize_for_diagnostic(&cmd.resolved_path.display().to_string());
                    lines.push(format!(
                        "[nono] '{}' was found at {} but could not be executed.",
                        program, path,
                    ));
                    lines.push(
                        "[nono] The file may not have execute permission, or the sandbox"
                            .to_string(),
                    );
                    lines.push(
                        "[nono] may be blocking execution of binaries in that directory."
                            .to_string(),
                    );
                } else {
                    lines.push(
                        "[nono] The command was found but could not be executed.".to_string(),
                    );
                    lines.push(
                        "[nono] Check file permissions and sandbox access to the binary's directory."
                            .to_string(),
                    );
                }
            }
            code if (129..=192).contains(&code) => {
                // Signal-based exit: 128 + signal number
                let sig = code - 128;
                // SIGSYS is platform-dependent: 31 on Linux, 12 on macOS
                let sigsys: i32 = libc::SIGSYS;
                let sig_name = match sig {
                    1 => "SIGHUP",
                    2 => "SIGINT",
                    4 => "SIGILL",
                    6 => "SIGABRT",
                    9 => "SIGKILL",
                    11 => "SIGSEGV",
                    13 => "SIGPIPE",
                    15 => "SIGTERM",
                    s if s == sigsys => "SIGSYS",
                    _ => "",
                };

                if sig == sigsys {
                    // SIGSYS = seccomp/sandbox killed it
                    lines.push(format!(
                        "[nono] Command killed by {} (exit code {}).",
                        sig_name, code,
                    ));
                    lines.push("[nono]".to_string());
                    lines.push(
                        "[nono] SIGSYS typically means a blocked system call. The command tried"
                            .to_string(),
                    );
                    lines.push("[nono] an operation that the sandbox does not permit.".to_string());
                } else if sig == 9 {
                    lines.push(format!(
                        "[nono] Command killed by {} (exit code {}).",
                        sig_name, code,
                    ));
                    lines.push("[nono]".to_string());
                    lines.push(
                        "[nono] The process was forcefully terminated. This is usually not"
                            .to_string(),
                    );
                    lines.push("[nono] caused by sandbox restrictions.".to_string());
                } else if !sig_name.is_empty() {
                    lines.push(format!(
                        "[nono] Command killed by signal {} / {} (exit code {}).",
                        sig, sig_name, code,
                    ));
                } else {
                    lines.push(format!(
                        "[nono] Command killed by signal {} (exit code {}).",
                        sig, code,
                    ));
                }
            }
            code => {
                lines.push(format_command_failed_line(code));
            }
        }

        lines
    }

    /// Standard mode footer: concise policy summary with --allow suggestions.
    fn format_standard_footer(&self, exit_code: i32) -> String {
        let mut lines = Vec::new();
        let observed_hints = self.actionable_observed_path_hints();
        let primary_verdict = self.primary_observation_verdict();
        let has_observation = self.has_error_observation();

        // Check if this was a protected file write attempt
        if let Some(ref blocked_file) = self.blocked_protected_file {
            lines.push(format!(
                "[nono] Write to '{}' blocked: file is a signed instruction file.",
                blocked_file
            ));
            lines.push(
                "[nono] Signed instruction files are write-protected to prevent tampering."
                    .to_string(),
            );
            lines.push("[nono]".to_string());
            lines.push(format!(
                "[nono] The command failed. (exit code {})",
                exit_code
            ));
        } else if matches!(
            primary_verdict.as_ref(),
            Some(ErrorVerdict::MissingPath(_)) | Some(ErrorVerdict::NonSandboxFailure(_))
        ) {
            lines.push(format_command_failed_not_sandbox_line(exit_code));
        } else if exit_code == 0 && has_observation {
            lines.push(format_command_succeeded_with_stderr_line());
        } else {
            lines.extend(self.format_exit_explanation(exit_code));
        }
        lines.push("[nono]".to_string());

        if self.blocked_protected_file.is_none() {
            if let Some(verdict) = primary_verdict.as_ref() {
                self.format_primary_verdict_guidance(&mut lines, verdict);
                lines.push("[nono]".to_string());
            }
        }

        // Concise policy summary: show user paths, summarize system/group paths
        lines.push("[nono] Sandbox policy:".to_string());

        self.format_allowed_paths_concise(&mut lines);
        self.format_network_status(&mut lines);
        self.format_protected_paths(&mut lines);
        let additional_hints = if observed_hints.len() > 1 {
            &observed_hints[1..]
        } else {
            &[]
        };
        self.format_observed_path_hints(&mut lines, additional_hints);

        // Help section (skip if the failure was specifically due to protected file)
        if self.blocked_protected_file.is_none()
            && observed_hints.is_empty()
            && primary_verdict.is_none()
        {
            lines.push("[nono]".to_string());
            self.format_grant_help(&mut lines);
            lines.push("[nono]".to_string());
            self.format_follow_up_guidance(&mut lines, None);
        }

        lines.join("\n")
    }

    /// Supervised mode footer: show denials and mode-specific guidance.
    fn format_supervised_footer(&self, exit_code: i32) -> String {
        let mut lines = Vec::new();
        let primary_verdict = self.primary_observation_verdict();
        let has_observation = self.has_error_observation();

        if self.denials.is_empty()
            && matches!(
                primary_verdict.as_ref(),
                Some(ErrorVerdict::MissingPath(_)) | Some(ErrorVerdict::NonSandboxFailure(_))
            )
        {
            lines.push(format_command_failed_not_sandbox_line(exit_code));
        } else if exit_code == 0 && has_observation && self.denials.is_empty() {
            lines.push(format_command_succeeded_with_stderr_line());
        } else {
            lines.extend(self.format_exit_explanation(exit_code));
        }
        lines.push("[nono]".to_string());

        // Convert macOS Seatbelt violations (operation + target) into
        // DenialRecords so the same rendering logic handles both platforms.
        let (violation_denials, non_fs_violations) = violations_to_denials(self.sandbox_violations);

        // Merge supervisor denials (Linux seccomp) with violation-derived
        // denials (macOS Seatbelt) into a single unified list.
        let mut all_denials: Vec<DenialRecord> = self
            .denials
            .iter()
            .cloned()
            .chain(violation_denials)
            .collect();
        all_denials.extend(self.observed_denials_matching_logged_paths(&all_denials));

        if all_denials.is_empty() {
            // No denials from either source.
            if !non_fs_violations.is_empty() {
                // Non-filesystem violations (mach-lookup, signal, etc.) —
                // show them with human-readable descriptions.
                lines.push("[nono] Sandbox blocked system services:".to_string());
                format_non_fs_violations(&mut lines, &non_fs_violations);
                lines.push("[nono]".to_string());
                format_non_fs_guidance(&mut lines, &non_fs_violations);
            } else {
                // Genuinely no denials observed.
                if let Some(verdict) = primary_verdict.as_ref() {
                    self.format_primary_verdict_guidance(&mut lines, verdict);
                    lines.push("[nono]".to_string());
                }
                lines.push("[nono] No path denials were observed during this session.".to_string());
                lines.push(
                    "[nono] The failure may be unrelated to sandbox restrictions.".to_string(),
                );
            }
            lines.push("[nono]".to_string());
            self.format_grant_help(&mut lines);
            lines.push("[nono]".to_string());
            self.format_follow_up_guidance(&mut lines, None);
        } else {
            // Deduplicate by path, merging access modes. Classification into
            // actionable vs. policy-blocked is done by the consolidated
            // formatter using policy_explanations when available.
            let deduped = dedupe_denials(&all_denials);
            self.format_consolidated_denial_guidance(&mut lines, &deduped);

            // Show non-filesystem violations (mach-lookup, etc.) if any
            if !non_fs_violations.is_empty() {
                lines.push("[nono]".to_string());
                lines.push("[nono] Also blocked (system services):".to_string());
                format_non_fs_violations(&mut lines, &non_fs_violations);
                lines.push("[nono]".to_string());
                format_non_fs_guidance(&mut lines, &non_fs_violations);
            }

            // Note: `nono grant` suggestions are shown via desktop
            // notifications during the session, not in the post-exit footer.
        }

        lines.join("\n")
    }

    fn actionable_observed_path_hints(&self) -> Vec<ObservedPathHint> {
        self.observed_path_hints
            .iter()
            .filter_map(|hint| {
                self.actionable_observed_access(&hint.path, hint.access)
                    .map(|access| ObservedPathHint {
                        path: hint.path.clone(),
                        access,
                    })
            })
            .collect()
    }

    fn observed_denials_matching_logged_paths(
        &self,
        denials: &[DenialRecord],
    ) -> Vec<DenialRecord> {
        if denials.is_empty() {
            return Vec::new();
        }

        let logged_paths = denials
            .iter()
            .map(|denial| denial.path.clone())
            .collect::<std::collections::BTreeSet<_>>();

        self.actionable_observed_path_hints()
            .into_iter()
            .filter(|hint| logged_paths.contains(&hint.path))
            .map(|hint| DenialRecord {
                path: hint.path,
                access: hint.access,
                reason: DenialReason::InsufficientAccess,
            })
            .collect()
    }

    fn primary_observation_verdict(&self) -> Option<ErrorVerdict> {
        self.missing_path_hints
            .first()
            .cloned()
            .map(ErrorVerdict::MissingPath)
            .or_else(|| {
                self.non_sandbox_failure
                    .clone()
                    .map(ErrorVerdict::NonSandboxFailure)
            })
            .or_else(|| {
                self.actionable_observed_path_hints()
                    .first()
                    .cloned()
                    .map(ErrorVerdict::LikelySandbox)
            })
    }

    fn has_error_observation(&self) -> bool {
        self.primary_verdict.is_some()
            || self.blocked_protected_file.is_some()
            || !self.observed_path_hints.is_empty()
            || !self.missing_path_hints.is_empty()
            || self.non_sandbox_failure.is_some()
    }

    fn actionable_observed_access(&self, path: &Path, inferred: AccessMode) -> Option<AccessMode> {
        let Some(cap) = self.closest_covering_capability_any(path) else {
            return Some(inferred);
        };

        if cap.access.contains(inferred) {
            return None;
        }

        match (cap.access, inferred) {
            (AccessMode::Read, AccessMode::ReadWrite) => Some(AccessMode::Write),
            (AccessMode::Write, AccessMode::ReadWrite) => Some(AccessMode::Read),
            _ => Some(inferred),
        }
    }

    fn closest_covering_capability_any(
        &self,
        path: &Path,
    ) -> Option<&crate::capability::FsCapability> {
        let canonical = try_canonicalize(path);
        let mut best_covering: Option<&crate::capability::FsCapability> = None;
        let mut best_covering_score = 0usize;

        for cap in self.caps.fs_capabilities() {
            let covers = if cap.is_file {
                cap.resolved == canonical
            } else {
                canonical.starts_with(&cap.resolved)
            };

            if !covers {
                continue;
            }

            let score = cap.resolved.as_os_str().len();
            if score >= best_covering_score {
                best_covering = Some(cap);
                best_covering_score = score;
            }
        }

        best_covering
    }

    fn format_follow_up_guidance(
        &self,
        lines: &mut Vec<String>,
        _hint: Option<(&Path, AccessMode)>,
    ) {
        lines.push("[nono] Next steps:".to_string());
        if let Some(command) = self.format_command_for_learn() {
            lines.push(format!(
                "[nono]   Discover paths: nono learn -- {}",
                command
            ));
        } else {
            lines.push("[nono]   Discover paths: nono learn -- <your command>".to_string());
        }
        lines.push(
            "[nono]   Query policy: nono why --path <path> --op <read|write|readwrite>".to_string(),
        );
    }

    fn format_primary_observed_guidance(&self, lines: &mut Vec<String>, hint: &ObservedPathHint) {
        lines.push("[nono] Sandbox denial:".to_string());
        if self.observed_hint_points_to_read_only_cwd(hint) {
            lines.push(
                "[nono]   The command appears to be writing inside the current working directory,"
                    .to_string(),
            );
            lines.push(
                "[nono]   but the current working directory is read-only in this sandbox."
                    .to_string(),
            );
        }
        lines.push(format!(
            "[nono]   {} ({})",
            hint.path.display(),
            access_str(hint.access),
        ));
        lines.push(format!(
            "[nono]   Try: {}",
            self.suggested_flag_for_hint(&hint.path, hint.access)
        ));
    }

    fn format_primary_verdict_guidance(&self, lines: &mut Vec<String>, verdict: &ErrorVerdict) {
        match verdict {
            ErrorVerdict::LikelySandbox(hint) => {
                self.format_primary_observed_guidance(lines, hint);
            }
            ErrorVerdict::MissingPath(path) => {
                self.format_primary_missing_path_guidance(lines, path);
            }
            ErrorVerdict::NonSandboxFailure(failure) => {
                self.format_non_sandbox_failure_guidance(lines, failure);
            }
        }
    }

    fn format_primary_missing_path_guidance(&self, lines: &mut Vec<String>, path: &Path) {
        lines.push("[nono] Missing path:".to_string());
        lines.push(format!("[nono]   {}", path.display()));
        lines.push("[nono]   The command reported \"No such file or directory\".".to_string());
        lines.push(
            "[nono]   Path flags only apply to paths that already exist when nono starts."
                .to_string(),
        );
        lines.push(
            "[nono]   Create the path first, or grant an existing parent directory if the command needs to create it."
                .to_string(),
        );
    }

    fn format_non_sandbox_failure_guidance(&self, lines: &mut Vec<String>, failure: &str) {
        lines.push("[nono] Application error:".to_string());
        lines.push(format!("[nono]   {}", sanitize_for_diagnostic(failure)));
        lines.push(
            "[nono]   The command's own output suggests this failure is unrelated to sandbox permissions."
                .to_string(),
        );
    }

    /// Render the consolidated denial block.
    ///
    /// Shows every denied path (truncated past `MAX_INLINE_LIST` entries) with
    /// a `[permanently restricted]` marker for paths that are blocked by the
    /// sensitive-path policy, and emits a single `Fix:` line combining the
    /// `--read`/`--write`/`--allow` flags for all actionable denials.
    ///
    /// Classification: if a policy explanation with `reason == "sensitive_path"`
    /// exists for a path, it is treated as policy-blocked and cannot be fixed
    /// via flags. Everything else is actionable, including macOS Seatbelt
    /// denials whose `DenialReason` defaults to `PolicyBlocked` (that reason
    /// is over-broad on macOS — we trust the query_path result instead).
    fn format_consolidated_denial_guidance(
        &self,
        lines: &mut Vec<String>,
        denials: &[DenialRecord],
    ) {
        const MAX_INLINE_LIST: usize = 10;

        let total = denials.len();
        let mut actionable: Vec<&DenialRecord> = Vec::new();
        let mut policy_blocked: Vec<&DenialRecord> = Vec::new();

        for denial in denials {
            if self.is_denial_policy_blocked(denial) {
                policy_blocked.push(denial);
            } else {
                actionable.push(denial);
            }
        }

        let plural_s = if total == 1 { "" } else { "s" };
        lines.push(format!(
            "[nono] Sandbox denial: {} path{} blocked.",
            total, plural_s
        ));

        for (idx, denial) in denials.iter().enumerate() {
            if idx >= MAX_INLINE_LIST {
                lines.push(format!("[nono]   … and {} more", total - idx));
                break;
            }
            let suffix = if self.is_denial_policy_blocked(denial) {
                "  [permanently restricted]"
            } else {
                ""
            };
            lines.push(format!(
                "[nono]   {} ({}){}",
                denial.path.display(),
                access_str(denial.access),
                suffix,
            ));
        }

        if !actionable.is_empty() {
            let flags: Vec<String> = actionable
                .iter()
                .map(|d| self.suggested_flag_for_denial(d))
                .collect();
            lines.push(format!("[nono] Fix: {}", flags.join(" ")));
        }

        if !policy_blocked.is_empty() {
            let n = policy_blocked.len();
            let (subject, verb) = if n == 1 {
                ("1 path is", "")
            } else {
                ("paths are", "")
            };
            let count_prefix = if n == 1 {
                String::from(subject)
            } else {
                format!("{} {}", n, subject)
            };
            lines.push("[nono]".to_string());
            lines.push(format!(
                "[nono] {}{} permanently restricted — override via a user profile with filesystem.bypass_protection.",
                count_prefix, verb,
            ));
        }
    }

    /// Return true when the denial cannot be fixed by a path flag alone —
    /// i.e. the path is blocked by the sensitive-path policy and requires a
    /// profile with `filesystem.bypass_protection`.
    fn is_denial_policy_blocked(&self, denial: &DenialRecord) -> bool {
        if let Some(expl) = self
            .policy_explanations
            .iter()
            .find(|e| e.path == denial.path)
        {
            return expl.reason == "sensitive_path";
        }
        // No explanation (e.g. Linux seccomp path without a matching lookup):
        // trust the DenialRecord reason.
        denial.reason == DenialReason::PolicyBlocked
    }

    /// Build the CLI flag suggestion for a single denial. Prefers the
    /// explanation's `suggested_flag` (which knows about parent-directory
    /// canonicalization) and falls back to a local computation otherwise.
    fn suggested_flag_for_denial(&self, denial: &DenialRecord) -> String {
        if let Some(flag) = self
            .policy_explanations
            .iter()
            .find(|e| e.path == denial.path && e.access == denial.access)
            .and_then(|e| e.suggested_flag.clone())
        {
            // explanations' suggested_flag is of the form "--read /path".
            // Strip any leading "Fix: " that callers may have prepended.
            return flag
                .strip_prefix("Fix: ")
                .map(str::to_string)
                .unwrap_or(flag);
        }
        suggested_flag_for_path(&denial.path, denial.access)
    }

    fn format_grant_help(&self, lines: &mut Vec<String>) {
        lines.push("[nono] To grant additional access, re-run with:".to_string());
        lines.push("[nono]   --allow <path>     read+write access to directory".to_string());
        lines.push("[nono]   --read <path>      read-only access to directory".to_string());
        lines.push("[nono]   --write <path>     write-only access to directory".to_string());

        if self.caps.is_network_blocked() {
            lines.push(
                "[nono]   --allow-net        unrestricted network for this session".to_string(),
            );
        }
    }

    fn format_command_for_learn(&self) -> Option<String> {
        let command = self.command.as_ref()?;
        if command.args.is_empty() {
            return None;
        }

        Some(
            command
                .args
                .iter()
                .map(|arg| shell_quote(arg))
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    fn suggested_flag_for_hint(&self, path: &Path, requested: AccessMode) -> String {
        if let Some(flag) = self.suggested_upgrade_flag_for_existing_capability(path, requested) {
            flag
        } else if self.observed_hint_points_to_ungranted_cwd(path) {
            "--allow-cwd".to_string()
        } else {
            suggested_flag_for_path(path, requested)
        }
    }

    fn observed_hint_points_to_read_only_cwd(&self, hint: &ObservedPathHint) -> bool {
        let Some(current_dir) = self.current_dir else {
            return false;
        };

        hint.path.starts_with(current_dir)
            && self
                .suggested_upgrade_flag_for_existing_capability(&hint.path, hint.access)
                .is_some()
    }

    fn suggested_upgrade_flag_for_existing_capability(
        &self,
        path: &Path,
        requested: AccessMode,
    ) -> Option<String> {
        let cap = self.closest_covering_capability_any(path)?;
        if cap.access.contains(requested) {
            return None;
        }

        let target = cap.resolved.clone();

        let requested = match (cap.access, requested) {
            (AccessMode::Read, AccessMode::ReadWrite) => AccessMode::Write,
            (AccessMode::Write, AccessMode::ReadWrite) => AccessMode::Read,
            _ => requested,
        };

        Some(suggested_flag_for_existing_target(
            &target,
            cap.is_file,
            requested,
        ))
    }

    fn observed_hint_points_to_ungranted_cwd(&self, path: &Path) -> bool {
        let Some(current_dir) = self.current_dir else {
            return false;
        };

        if !path.starts_with(current_dir) {
            return false;
        }

        self.closest_covering_capability_any(current_dir).is_none()
    }

    /// Format allowed paths concisely: show user/profile paths explicitly,
    /// summarize group/system paths with a count.
    fn format_allowed_paths_concise(&self, lines: &mut Vec<String>) {
        let caps = self.caps.fs_capabilities();
        if caps.is_empty() {
            lines.push("[nono]   Allowed paths: (none)".to_string());
            return;
        }

        let mut user_paths = Vec::new();
        let mut group_count: usize = 0;

        for cap in caps {
            match &cap.source {
                CapabilitySource::User | CapabilitySource::Profile => {
                    let kind = if cap.is_file { "file" } else { "dir" };
                    user_paths.push(format!(
                        "[nono]     {} ({}, {})",
                        cap.resolved.display(),
                        access_str(cap.access),
                        kind,
                    ));
                }
                CapabilitySource::Group(_) | CapabilitySource::System => {
                    group_count += 1;
                }
            }
        }

        if user_paths.is_empty() && group_count == 0 {
            lines.push("[nono]   Allowed paths: (none)".to_string());
        } else {
            lines.push("[nono]   Allowed paths:".to_string());
            for p in &user_paths {
                lines.push(p.clone());
            }
            if group_count > 0 {
                lines.push(format!("[nono]     + {} system/group path(s)", group_count));
            }
        }
    }

    fn format_observed_path_hints(&self, lines: &mut Vec<String>, hints: &[ObservedPathHint]) {
        if hints.is_empty() {
            return;
        }

        lines.push("[nono]   Likely blocked paths seen in the command output:".to_string());
        for hint in hints {
            lines.push(format!(
                "[nono]     {} ({})",
                hint.path.display(),
                access_str(hint.access),
            ));
        }
    }

    /// Format the network status.
    fn format_network_status(&self, lines: &mut Vec<String>) {
        use crate::NetworkMode;
        match self.caps.network_mode() {
            NetworkMode::Blocked => {
                lines.push("[nono]   Network: blocked".to_string());
            }
            NetworkMode::ProxyOnly { port, bind_ports } => {
                if bind_ports.is_empty() {
                    lines.push(format!("[nono]   Network: proxy (localhost:{})", port));
                } else {
                    let ports_str: Vec<String> = bind_ports.iter().map(|p| p.to_string()).collect();
                    lines.push(format!(
                        "[nono]   Network: proxy (localhost:{}), bind: {}",
                        port,
                        ports_str.join(", ")
                    ));
                }
            }
            NetworkMode::AllowAll => {
                lines.push("[nono]   Network: allowed".to_string());
            }
        }
    }

    /// Format write-protected paths (signed instruction files).
    fn format_protected_paths(&self, lines: &mut Vec<String>) {
        if self.protected_paths.is_empty() {
            return;
        }

        lines.push("[nono]   Write-protected (signed instruction files):".to_string());
        for path in self.protected_paths {
            // Show just the filename for brevity
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            lines.push(format!("[nono]     {}", name));
        }
    }

    /// Format a concise single-line summary of the policy.
    ///
    /// Useful for logging or brief status messages.
    #[must_use]
    pub fn format_summary(&self) -> String {
        let path_count = self.caps.fs_capabilities().len();
        let network_status = if self.caps.is_network_blocked() {
            "blocked"
        } else {
            "allowed"
        };

        format!(
            "[nono] Policy: {} path(s), network {}",
            path_count, network_status
        )
    }
}

/// Catalog of observed non-filesystem macOS sandbox denials.
///
/// Apple's public documentation covers APIs such as CFPreferences, but not a
/// complete stable taxonomy of Seatbelt operation names. Keep this table
/// evidence-based: add entries only when they are observed in sandbox logs or
/// backed by a known framework/daemon mapping.
#[derive(Debug, Clone, Copy)]
struct SystemServiceDiagnostic {
    operation: &'static str,
    target: SystemServiceTarget,
    description: &'static str,
    guidance: Option<SystemServiceGuidance>,
}

#[derive(Debug, Clone, Copy)]
enum SystemServiceTarget {
    Any,
    Exact(&'static str),
    Prefix(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemServiceGuidance {
    Keychain,
    SetuidExec,
    UserPreferences,
}

const SYSTEM_SERVICE_DIAGNOSTICS: &[SystemServiceDiagnostic] = &[
    SystemServiceDiagnostic::exact(
        "mach-lookup",
        "com.apple.SecurityServer",
        "Keychain / Security framework",
        Some(SystemServiceGuidance::Keychain),
    ),
    SystemServiceDiagnostic::exact(
        "mach-lookup",
        "com.apple.securityd",
        "Keychain / Security framework",
        Some(SystemServiceGuidance::Keychain),
    ),
    SystemServiceDiagnostic::exact(
        "mach-lookup",
        "com.apple.security.keychaind",
        "Keychain / Security framework",
        Some(SystemServiceGuidance::Keychain),
    ),
    SystemServiceDiagnostic::exact(
        "mach-lookup",
        "com.apple.secd",
        "Keychain / Security framework",
        Some(SystemServiceGuidance::Keychain),
    ),
    SystemServiceDiagnostic::exact(
        "mach-lookup",
        "com.apple.security.agent",
        "Keychain authorization agent",
        Some(SystemServiceGuidance::Keychain),
    ),
    SystemServiceDiagnostic::exact("mach-lookup", "com.apple.logd", "System logging", None),
    SystemServiceDiagnostic::exact(
        "mach-lookup",
        "com.apple.system.notification_center",
        "Distributed notifications",
        None,
    ),
    SystemServiceDiagnostic::exact(
        "mach-lookup",
        "com.apple.distributed_notifications",
        "Distributed notifications",
        None,
    ),
    SystemServiceDiagnostic::exact(
        "mach-lookup",
        "com.apple.CoreServices.coreservicesd",
        "Launch Services",
        None,
    ),
    SystemServiceDiagnostic::exact(
        "mach-lookup",
        "com.apple.lsd.mapdb",
        "Launch Services",
        None,
    ),
    SystemServiceDiagnostic::prefix(
        "mach-lookup",
        "com.apple.windowserver",
        "Window Server / GUI",
        None,
    ),
    SystemServiceDiagnostic::prefix(
        "mach-lookup",
        "com.apple.cfprefsd",
        "Preferences (CFPreferences / NSUserDefaults)",
        None,
    ),
    SystemServiceDiagnostic::prefix(
        "mach-lookup",
        "com.apple.pasteboard",
        "Pasteboard / clipboard",
        None,
    ),
    SystemServiceDiagnostic::prefix(
        "mach-lookup",
        "com.apple.coreservices",
        "Core Services",
        None,
    ),
    SystemServiceDiagnostic::exact(
        "user-preference-read",
        "kcfpreferencesanyapplication",
        "Global preferences (CFPreferences any-application domain)",
        Some(SystemServiceGuidance::UserPreferences),
    ),
    SystemServiceDiagnostic::prefix(
        "user-preference-read",
        "kcfpreferences",
        "Preferences (CFPreferences / NSUserDefaults)",
        Some(SystemServiceGuidance::UserPreferences),
    ),
    SystemServiceDiagnostic::any(
        "forbidden-exec-sugid",
        "Setuid/setgid executable blocked",
        Some(SystemServiceGuidance::SetuidExec),
    ),
];

impl SystemServiceDiagnostic {
    const fn any(
        operation: &'static str,
        description: &'static str,
        guidance: Option<SystemServiceGuidance>,
    ) -> Self {
        Self {
            operation,
            target: SystemServiceTarget::Any,
            description,
            guidance,
        }
    }

    const fn exact(
        operation: &'static str,
        target: &'static str,
        description: &'static str,
        guidance: Option<SystemServiceGuidance>,
    ) -> Self {
        Self {
            operation,
            target: SystemServiceTarget::Exact(target),
            description,
            guidance,
        }
    }

    const fn prefix(
        operation: &'static str,
        target_prefix: &'static str,
        description: &'static str,
        guidance: Option<SystemServiceGuidance>,
    ) -> Self {
        Self {
            operation,
            target: SystemServiceTarget::Prefix(target_prefix),
            description,
            guidance,
        }
    }

    fn matches(&self, violation: &SandboxViolation) -> bool {
        if violation.operation != self.operation {
            return false;
        }
        match self.target {
            SystemServiceTarget::Any => true,
            _ => violation
                .target
                .as_deref()
                .is_some_and(|target| self.target.matches(target)),
        }
    }
}

impl SystemServiceTarget {
    fn matches(self, target: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => target.eq_ignore_ascii_case(expected),
            Self::Prefix(prefix) => target
                .get(..prefix.len())
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix)),
        }
    }
}

fn system_service_diagnostic_for(
    violation: &SandboxViolation,
) -> Option<&'static SystemServiceDiagnostic> {
    SYSTEM_SERVICE_DIAGNOSTICS
        .iter()
        .find(|diagnostic| diagnostic.matches(violation))
}

/// Format non-filesystem violations with human-readable service descriptions.
fn format_non_fs_violations(lines: &mut Vec<String>, violations: &[&SandboxViolation]) {
    for v in violations {
        let desc = system_service_diagnostic_for(v).map(|diagnostic| diagnostic.description);
        match (&v.target, desc) {
            (Some(target), Some(description)) => {
                lines.push(format!(
                    "[nono]   {} ({}) — {}",
                    v.operation, target, description
                ));
            }
            (Some(target), None) => {
                lines.push(format!("[nono]   {} ({})", v.operation, target));
            }
            (None, Some(description)) => {
                lines.push(format!("[nono]   {} — {}", v.operation, description));
            }
            (None, None) => {
                lines.push(format!("[nono]   {}", v.operation));
            }
        }
    }
}

/// Generate actionable guidance for non-filesystem violations.
fn format_non_fs_guidance(lines: &mut Vec<String>, violations: &[&SandboxViolation]) {
    let has_guidance = |guidance| {
        violations.iter().any(|violation| {
            system_service_diagnostic_for(violation).and_then(|diagnostic| diagnostic.guidance)
                == Some(guidance)
        })
    };

    if has_guidance(SystemServiceGuidance::Keychain) {
        lines.push("[nono] Keychain access requires granting the login keychain path:".to_string());
        lines.push(keychain_login_grant_guidance());
    }

    if has_guidance(SystemServiceGuidance::UserPreferences) {
        lines.push("[nono] Preference reads use macOS CFPreferences / NSUserDefaults.".to_string());
        lines.push(
            "[nono] They are platform operations, not filesystem paths; saving them writes a raw macOS Seatbelt rule.".to_string(),
        );
        lines.push(
            "[nono] If the tool requires this, accept the profile prompt or add a reviewed user profile rule:".to_string(),
        );
        lines.push(
            "[nono]   \"unsafe_macos_seatbelt_rules\": [\"(allow user-preference-read)\"]"
                .to_string(),
        );
    }

    if has_guidance(SystemServiceGuidance::SetuidExec) {
        lines.push(
            "[nono] A sandboxed process tried to execute a setuid/setgid binary.".to_string(),
        );
        lines.push(
            "[nono] macOS blocks privilege-changing execs inside this sandbox; this is not a path grant.".to_string(),
        );
        lines.push(
            "[nono] nono does not save this automatically. Prefer a non-setuid helper, or run the privileged helper outside nono after review.".to_string(),
        );
    }
}

fn keychain_login_grant_guidance() -> String {
    const DISPLAY_PATH: &str = "~/Library/Keychains/login.keychain-db";
    let Some(home) = std::env::var_os("HOME") else {
        return format!("[nono]   --read-file {DISPLAY_PATH}");
    };
    let path = PathBuf::from(home).join("Library/Keychains/login.keychain-db");
    keychain_grant_guidance_for_path(&path, DISPLAY_PATH)
}

fn keychain_grant_guidance_for_path(path: &Path, display_path: &str) -> String {
    let flag = match std::fs::metadata(path).map(|metadata| metadata.file_type()) {
        Ok(file_type) if file_type.is_dir() => "--read",
        _ => "--read-file",
    };
    format!("[nono]   {flag} {display_path}")
}

/// Deduplicate denials by path, merging access modes. When the same path
/// appears with multiple reasons, the most restrictive reason wins
/// (`PolicyBlocked` > `InsufficientAccess` > `UserDenied` > `RateLimited` >
/// `BackendError`). Output is sorted by path for stable rendering.
fn dedupe_denials(denials: &[DenialRecord]) -> Vec<DenialRecord> {
    let mut by_path = std::collections::BTreeMap::<PathBuf, (AccessMode, DenialReason)>::new();

    for denial in denials {
        by_path
            .entry(denial.path.clone())
            .and_modify(|(access, reason)| {
                *access = merge_access_modes(*access, denial.access);
                *reason = stricter_reason(reason.clone(), denial.reason.clone());
            })
            .or_insert_with(|| (denial.access, denial.reason.clone()));
    }

    by_path
        .into_iter()
        .map(|(path, (access, reason))| DenialRecord {
            path,
            access,
            reason,
        })
        .collect()
}

fn stricter_reason(a: DenialReason, b: DenialReason) -> DenialReason {
    fn rank(r: &DenialReason) -> u8 {
        match r {
            DenialReason::PolicyBlocked => 5,
            DenialReason::InsufficientAccess => 4,
            DenialReason::UserDenied => 3,
            DenialReason::RateLimited => 2,
            DenialReason::BackendError => 1,
        }
    }
    if rank(&a) >= rank(&b) {
        a
    } else {
        b
    }
}

/// Map a Seatbelt operation name to an `AccessMode`.
///
/// Returns `None` for non-filesystem operations (e.g. `mach-lookup`,
/// `signal`, `process-exec`) that cannot be expressed as path grants.
pub fn seatbelt_operation_to_access(operation: &str) -> Option<AccessMode> {
    match operation {
        "file-read-data" | "file-read-metadata" | "file-read-xattr" => Some(AccessMode::Read),
        "file-write-data" | "file-write-create" | "file-write-unlink" | "file-write-flags"
        | "file-write-mode" | "file-write-owner" | "file-write-times" | "file-write-xattr" => {
            Some(AccessMode::Write)
        }
        _ => None,
    }
}

/// Convert `SandboxViolation`s with filesystem targets into `DenialRecord`s.
///
/// Non-filesystem violations (mach-lookup, signal, etc.) are returned
/// separately since they can't be expressed as path grants.
fn violations_to_denials(
    violations: &[SandboxViolation],
) -> (Vec<DenialRecord>, Vec<&SandboxViolation>) {
    let mut denials = Vec::new();
    let mut non_fs = Vec::new();
    // Deduplicate: multiple operations on the same path merge into one denial
    let mut seen = std::collections::BTreeMap::<PathBuf, AccessMode>::new();

    for v in violations {
        if let (Some(access), Some(target)) =
            (seatbelt_operation_to_access(&v.operation), &v.target)
        {
            let path = PathBuf::from(target);
            seen.entry(path)
                .and_modify(|existing| *existing = merge_access_modes(*existing, access))
                .or_insert(access);
        } else {
            non_fs.push(v);
        }
    }

    for (path, access) in seen {
        denials.push(DenialRecord {
            path,
            access,
            reason: DenialReason::PolicyBlocked,
        });
    }

    (denials, non_fs)
}

fn access_str(access: AccessMode) -> &'static str {
    match access {
        AccessMode::Read => "read",
        AccessMode::Write => "write",
        AccessMode::ReadWrite => "read+write",
    }
}

fn merge_access_modes(existing: AccessMode, new: AccessMode) -> AccessMode {
    if existing == new {
        existing
    } else {
        AccessMode::ReadWrite
    }
}

fn suggested_flag_for_path(path: &Path, requested: AccessMode) -> String {
    let (flag, target) = suggested_flag_parts(path, requested);
    format!("{flag} {}", target.display())
}

fn suggested_flag_for_existing_target(
    target: &Path,
    is_file: bool,
    requested: AccessMode,
) -> String {
    let flag = if is_file {
        match requested {
            AccessMode::Read => "--read-file",
            AccessMode::Write => "--write-file",
            AccessMode::ReadWrite => "--allow-file",
        }
    } else {
        match requested {
            AccessMode::Read => "--read",
            AccessMode::Write => "--write",
            AccessMode::ReadWrite => "--allow",
        }
    };

    format!("{flag} {}", target.display())
}

fn suggested_flag_parts(path: &Path, requested: AccessMode) -> (&'static str, PathBuf) {
    let flag = if path.is_file() {
        match requested {
            AccessMode::Read => "--read-file",
            AccessMode::Write => "--write-file",
            AccessMode::ReadWrite => "--allow-file",
        }
    } else {
        match requested {
            AccessMode::Read => "--read",
            AccessMode::Write => "--write",
            AccessMode::ReadWrite => "--allow",
        }
    };

    let target = if path.exists() || path.is_dir() || path.parent().is_none() {
        path.to_path_buf()
    } else if let Some(parent) = path.parent() {
        parent.to_path_buf()
    } else {
        path.to_path_buf()
    };

    (flag, target)
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
    {
        return s.to_string();
    }

    let mut quoted = String::with_capacity(s.len() + 2);
    quoted.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests;
