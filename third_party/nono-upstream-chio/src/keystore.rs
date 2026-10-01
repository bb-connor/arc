//! Secure credential loading from system keystore, 1Password, Apple Passwords, and environment
//!
//! This module provides functionality to load secrets from the system keystore
//! (macOS Keychain / Linux Secret Service), 1Password (via the `op` CLI),
//! Apple Passwords (via macOS `security`), custom keyring entries (via the
//! `keyring` crate), or environment variables (via the `env://` scheme) and
//! return them as zeroized strings.
//!
//! Credential references are dispatched by URI scheme:
//! - `env://VAR_NAME` — reads from the current process environment
//! - `file:///path/to/secret` — reads from a local file (before sandbox activation)
//! - `op://vault/item/field` — loaded via the 1Password CLI
//! - `apple-password://server/account` — loaded via macOS `security`
//! - `keyring://service/account` — loaded from the system keyring with a custom service name
//! - Everything else — loaded from the system keyring (service name `nono`)
//!
//! All secrets are wrapped in `Zeroizing<String>` to ensure they are securely
//! cleared from memory after use.

use crate::error::{NonoError, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

/// Timeout for secret-manager subprocesses.
///
/// Generous enough to allow biometric prompts in password manager CLIs.
const SECRET_MANAGER_TIMEOUT: Duration = Duration::from_secs(30);

/// A credential loaded from the keystore
pub struct LoadedSecret {
    /// The environment variable name to set
    pub env_var: String,
    /// The secret value (automatically zeroized when dropped)
    pub value: Zeroizing<String>,
}

/// The default service name for secrets in the keystore
pub const DEFAULT_SERVICE: &str = "nono";

/// The `op://` URI scheme prefix, indicating 1Password CLI backend.
const OP_URI_PREFIX: &str = "op://";

/// The `apple-password://` URI scheme prefix, indicating Apple Passwords backend.
const APPLE_PASSWORD_URI_PREFIX: &str = "apple-password://";

/// Alias prefix for Apple Passwords backend.
const APPLE_PASSWORDS_URI_PREFIX: &str = "apple-passwords://";

/// The `keyring://` URI scheme prefix, indicating a custom-service keyring lookup.
const KEYRING_URI_PREFIX: &str = "keyring://";

/// The `env://` URI scheme prefix, indicating environment variable backend.
const ENV_URI_PREFIX: &str = "env://";

/// The `file://` URI scheme prefix, indicating a local file credential source.
/// Read once at startup before sandbox activation; contents zeroed on drop.
const FILE_URI_PREFIX: &str = "file://";

/// Environment variable names that must never be loaded via `env://`.
///
/// These control linker, interpreter, or shell behavior. Allowing them as
/// credential sources would let an `env://` URI act as an injection vector.
const DANGEROUS_ENV_VAR_NAMES: &[&str] = &[
    // Linker injection
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    // Shell injection
    "BASH_ENV",
    "ENV",
    "IFS",
    "CDPATH",
    "PROMPT_COMMAND",
    // Interpreter injection
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
    "GOFLAGS",
    // Process-critical
    "PATH",
    "HOME",
    "SHELL",
];

/// Characters forbidden in `op://` URIs to prevent argument/shell injection.
const FORBIDDEN_URI_CHARS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '!', '\\', '"', '\'', '\n', '\r', '\0',
];

/// Load secrets from the system keystore, 1Password, Apple Passwords, or keyring
///
/// Credential references with URI schemes are dispatched to their backend:
/// - `op://` -> 1Password CLI
/// - `apple-password://` -> macOS security CLI
/// - `keyring://` -> system keyring with custom service name
/// - `env://` -> parent process environment
/// - everything else -> system keyring (service name `nono`)
///
/// # Arguments
/// * `service` - The service name in the keystore (e.g., "nono")
/// * `mappings` - Map of credential reference -> env var name
///
/// # Returns
/// Vector of loaded secrets ready to be set as env vars
///
/// # Example
///
/// ```no_run
/// use nono::keystore::{load_secrets, DEFAULT_SERVICE};
/// use std::collections::HashMap;
///
/// let mut mappings = HashMap::new();
/// mappings.insert("api_key".to_string(), "API_KEY".to_string());
///
/// let secrets = load_secrets(DEFAULT_SERVICE, &mappings)?;
/// for secret in secrets {
///     std::env::set_var(&secret.env_var, secret.value.as_str());
/// }
/// # Ok::<(), nono::NonoError>(())
/// ```
#[must_use = "loaded secrets should be used to set environment variables"]
pub fn load_secrets(
    service: &str,
    mappings: &HashMap<String, String>,
) -> Result<Vec<LoadedSecret>> {
    let mut secrets = Vec::with_capacity(mappings.len());

    for (account, env_var) in mappings {
        tracing::debug!("Loading secret '{}' -> ${}", account, env_var);
        let secret = load_secret_by_ref(service, account)?;
        secrets.push(LoadedSecret {
            env_var: env_var.clone(),
            value: secret,
        });
    }

    Ok(secrets)
}

/// Load a single secret, dispatching to the appropriate backend.
///
/// Dispatch order:
/// 1. `file:///path` — reads from a local file (before sandbox activation)
/// 2. `env://VAR` — reads from the process environment
/// 3. `op://vault/item/field` — delegates to the 1Password CLI
/// 4. `apple-password://server/account` — delegates to macOS `security`
/// 5. `keyring://service/account` — loads from system keyring with custom service
/// 6. Everything else — loads from the system keyring (service name `nono`)
///
/// # Arguments
/// * `service` - Keyring service name (only used for keyring backend)
/// * `credential_ref` - A keyring account name, `file://` URI, `op://` URI,
///   Apple Passwords URI, or `env://` URI
///
/// # Security
/// The returned value is wrapped in `Zeroizing<String>`. For URI-based managers
/// (`op://`, `apple-password://`), CLI stdout is captured and trimmed before
/// wrapping. Note: the intermediate `Vec<u8>` from subprocess output is not
/// zeroized — this is the same class of limitation as the keyring crate's
/// internal buffers.
#[must_use = "loaded secret should be used or explicitly dropped"]
pub fn load_secret_by_ref(service: &str, credential_ref: &str) -> Result<Zeroizing<String>> {
    if credential_ref.starts_with(FILE_URI_PREFIX) {
        load_from_file(credential_ref)
    } else if credential_ref.starts_with(ENV_URI_PREFIX) {
        load_from_env(credential_ref)
    } else if credential_ref.starts_with(OP_URI_PREFIX) {
        load_from_op(credential_ref)
    } else if is_apple_password_uri(credential_ref) {
        load_from_apple_password(credential_ref)
    } else if is_keyring_uri(credential_ref) {
        load_from_keyring_uri(credential_ref)
    } else {
        load_single_secret(service, credential_ref)
    }
}

/// Validate an `op://` URI has the correct structure.
///
/// Expected format: `op://vault/item/field` (3 path segments after the scheme).
/// Additional segments (section-qualified) are also accepted:
/// `op://vault/item/section/field`.
///
/// Rejects:
/// - Empty vault, item, or field
/// - Characters that could enable argument injection
/// - URIs with query strings or fragments
pub fn validate_op_uri(uri: &str) -> Result<()> {
    let path = uri.strip_prefix(OP_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, OP_URI_PREFIX
        ))
    })?;

    // Reject shell metacharacters to prevent injection
    if let Some(bad) = path.chars().find(|c| FORBIDDEN_URI_CHARS.contains(c)) {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    // Reject query strings and fragments
    if path.contains('?') || path.contains('#') {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI must not contain query strings or fragments: {}",
            uri
        )));
    }

    // Split into segments: vault/item/field (minimum 3)
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() < 3 {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI must have at least vault/item/field segments: {}",
            uri
        )));
    }

    // No empty segments (catches `op:///item/field`, `op://vault//field`, etc.)
    if segments.iter().any(|s| s.is_empty()) {
        return Err(NonoError::ConfigParse(format!(
            "1Password URI has empty path segment: {}",
            uri
        )));
    }

    Ok(())
}

/// Returns true if the credential reference is a 1Password `op://` URI.
#[must_use]
pub fn is_op_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(OP_URI_PREFIX)
}

fn strip_apple_password_prefix(uri: &str) -> Option<&str> {
    uri.strip_prefix(APPLE_PASSWORD_URI_PREFIX)
        .or_else(|| uri.strip_prefix(APPLE_PASSWORDS_URI_PREFIX))
}

/// Returns true if the credential reference is an Apple Passwords URI.
#[must_use]
pub fn is_apple_password_uri(credential_ref: &str) -> bool {
    strip_apple_password_prefix(credential_ref).is_some()
}

/// Validate an Apple Passwords URI.
///
/// Expected format: `apple-password://server/account`.
///
/// Rejects:
/// - Empty server or account
/// - Characters that could enable argument injection
/// - URIs with query strings or fragments
/// - Any path shape other than `server/account`
pub fn validate_apple_password_uri(uri: &str) -> Result<()> {
    let path = strip_apple_password_prefix(uri).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}' or '{}'",
            uri, APPLE_PASSWORD_URI_PREFIX, APPLE_PASSWORDS_URI_PREFIX
        ))
    })?;

    if let Some(bad) = path.chars().find(|c| FORBIDDEN_URI_CHARS.contains(c)) {
        return Err(NonoError::ConfigParse(format!(
            "Apple Passwords URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    if path.contains('?') || path.contains('#') {
        return Err(NonoError::ConfigParse(format!(
            "Apple Passwords URI must not contain query strings or fragments: {}",
            uri
        )));
    }

    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() != 2 {
        return Err(NonoError::ConfigParse(format!(
            "Apple Passwords URI must be 'apple-password://server/account': {}",
            uri
        )));
    }

    if segments.iter().any(|s| s.is_empty()) {
        return Err(NonoError::ConfigParse(format!(
            "Apple Passwords URI has empty server/account segment: {}",
            uri
        )));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn parse_apple_password_uri(uri: &str) -> Result<(&str, &str)> {
    validate_apple_password_uri(uri)?;
    let path = strip_apple_password_prefix(uri).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' is not an Apple Passwords URI",
            uri
        ))
    })?;
    let mut segments = path.splitn(2, '/');
    let server = segments.next().ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "Apple Passwords URI missing server segment: {}",
            uri
        ))
    })?;
    let account = segments.next().ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "Apple Passwords URI missing account segment: {}",
            uri
        ))
    })?;
    Ok((server, account))
}

/// Returns true if the credential reference is a `keyring://` URI.
#[must_use]
pub fn is_keyring_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(KEYRING_URI_PREFIX)
}

/// Maximum byte length for a `keyring://` URI (scheme + service + account + query).
///
/// Generous enough for real service/account names but prevents accidentally
/// passing absurdly long strings to OS keyring APIs.
const KEYRING_URI_MAX_LEN: usize = 1024;

/// Post-load decoding to apply to a keyring value.
///
/// Some tools wrap stored credentials in their own encoding. This enum
/// represents the supported `?decode=` transforms that can be requested
/// via the `keyring://` URI query string.
#[cfg(feature = "system-keyring")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyringDecode {
    /// No transform — return the raw stored value.
    None,
    /// Strip the `go-keyring-base64:` prefix and base64-decode the remainder.
    ///
    /// Used by Go tools built with `github.com/zalando/go-keyring` (e.g., `gh`).
    GoKeyring,
}

/// The prefix that `zalando/go-keyring` prepends to stored values.
#[cfg(feature = "system-keyring")]
const GO_KEYRING_PREFIX: &str = "go-keyring-base64:";

/// Allowed values for the `?decode=` query parameter.
const KEYRING_DECODE_GO_KEYRING: &str = "go-keyring";

/// Validate a `keyring://` URI.
///
/// Accepted formats:
/// - `keyring://service/account` — look up by service and account
/// - `keyring://service/account?decode=go-keyring` — with post-load decoding
///
/// Rejects:
/// - Empty service or account
/// - Characters that could enable argument injection
/// - Unknown query parameters or values
/// - Fragment identifiers
/// - Missing account segment
/// - URIs exceeding 1024 bytes
pub fn validate_keyring_uri(uri: &str) -> Result<()> {
    if uri.len() > KEYRING_URI_MAX_LEN {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI exceeds maximum length of {} bytes",
            KEYRING_URI_MAX_LEN
        )));
    }

    let path = uri.strip_prefix(KEYRING_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, KEYRING_URI_PREFIX
        ))
    })?;

    // Reject fragments unconditionally.
    if path.contains('#') {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI must not contain fragment identifiers: {}",
            uri
        )));
    }

    // Split off the query string (if any) before validating the path.
    let (path_part, query_part) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    // Validate query parameters against the allowlist.
    if let Some(query) = query_part {
        validate_keyring_query(query, uri)?;
    }

    if let Some(bad) = path_part.chars().find(|c| FORBIDDEN_URI_CHARS.contains(c)) {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    let segments: Vec<&str> = path_part.split('/').collect();
    if segments.len() != 2 {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI must be 'keyring://service/account': {}",
            uri
        )));
    }

    if segments.iter().any(|s| s.is_empty()) {
        return Err(NonoError::ConfigParse(format!(
            "keyring URI has empty service/account segment: {}",
            uri
        )));
    }

    Ok(())
}

/// Validate the query string of a `keyring://` URI.
///
/// Only `decode=go-keyring` is accepted. Unknown keys or values are rejected
/// to prevent silent misconfiguration.
fn validate_keyring_query(query: &str, full_uri: &str) -> Result<()> {
    for param in query.split('&') {
        let (key, value) = param.split_once('=').ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "keyring URI query parameter missing value: '{}' in {}",
                param, full_uri
            ))
        })?;

        match key {
            "decode" => match value {
                KEYRING_DECODE_GO_KEYRING => {}
                _ => {
                    return Err(NonoError::ConfigParse(format!(
                        "keyring URI has unknown decode value '{}'. \
                         Supported: {}",
                        value, KEYRING_DECODE_GO_KEYRING
                    )));
                }
            },
            _ => {
                return Err(NonoError::ConfigParse(format!(
                    "keyring URI has unknown query parameter '{}'. \
                     Supported: decode",
                    key
                )));
            }
        }
    }
    Ok(())
}

/// Parsed components of a `keyring://` URI.
#[cfg(feature = "system-keyring")]
struct KeyringUriParts<'a> {
    service: &'a str,
    account: &'a str,
    decode: KeyringDecode,
}

#[cfg(feature = "system-keyring")]
fn parse_keyring_uri(uri: &str) -> Result<KeyringUriParts<'_>> {
    validate_keyring_uri(uri)?;
    let path = uri.strip_prefix(KEYRING_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' is not a keyring URI",
            uri
        ))
    })?;

    // Split off query string before parsing path segments.
    let (path_part, query_part) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    let mut segments = path_part.splitn(2, '/');
    let service = segments.next().ok_or_else(|| {
        NonoError::ConfigParse(format!("keyring URI missing service segment: {}", uri))
    })?;
    let account = segments.next().ok_or_else(|| {
        NonoError::ConfigParse(format!("keyring URI missing account segment: {}", uri))
    })?;

    let decode = match query_part {
        Some(q) if q.contains(KEYRING_DECODE_GO_KEYRING) => KeyringDecode::GoKeyring,
        _ => KeyringDecode::None,
    };

    Ok(KeyringUriParts {
        service,
        account,
        decode,
    })
}

/// Redact the account segment of a `keyring://` URI for safe logging.
///
/// `keyring://service/account` → `keyring://service/<redacted>`
/// `keyring://service/account?decode=go-keyring` → `keyring://service/<redacted>?decode=go-keyring`
pub fn redact_keyring_uri(uri: &str) -> String {
    if let Some(path) = uri.strip_prefix(KEYRING_URI_PREFIX) {
        // Split off query string so we can preserve it.
        let (path_part, query_part) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path, None),
        };
        let mut segments = path_part.splitn(2, '/');
        if let Some(service) = segments.next() {
            if !service.is_empty() && segments.next().is_some() {
                let suffix = match query_part {
                    Some(q) => format!("?{}", q),
                    None => String::new(),
                };
                return format!("keyring://{}/<redacted>{}", service, suffix);
            }
        }
    }
    "keyring://***".to_string()
}

/// Returns true if the credential reference is an `env://` URI.
#[must_use]
pub fn is_env_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(ENV_URI_PREFIX)
}

/// Check if a credential reference uses the `file://` scheme.
#[must_use]
pub fn is_file_uri(credential_ref: &str) -> bool {
    credential_ref.starts_with(FILE_URI_PREFIX)
}

/// Validate an `env://VAR_NAME` URI.
///
/// Accepts variable names containing only ASCII alphanumeric characters and
/// underscores (`[A-Za-z0-9_]+`). This is stricter than POSIX (which allows
/// any byte except `=` and NUL) but matches real-world conventions and
/// prevents injection through crafted variable names.
///
/// Rejects:
/// - Empty variable name
/// - Names containing non-alphanumeric/underscore characters
/// - Dangerous variable names that control linker/interpreter/shell behavior
pub fn validate_env_uri(uri: &str) -> Result<()> {
    let var_name = uri.strip_prefix(ENV_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, ENV_URI_PREFIX
        ))
    })?;

    if var_name.is_empty() {
        return Err(NonoError::ConfigParse(
            "env:// URI has empty variable name".to_string(),
        ));
    }

    if let Some(bad) = var_name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '_')
    {
        return Err(NonoError::ConfigParse(format!(
            "env:// variable name contains invalid character {:?}: {}",
            bad, uri
        )));
    }

    if DANGEROUS_ENV_VAR_NAMES
        .iter()
        .any(|&d| d.eq_ignore_ascii_case(var_name))
    {
        return Err(NonoError::ConfigParse(format!(
            "env:// cannot read dangerous environment variable: {}",
            var_name
        )));
    }

    Ok(())
}

/// Validate a `file://` URI for local file credential sources.
///
/// Expected format: `file:///absolute/path` (triple slash for absolute paths).
///
/// Rejects:
/// - Non-absolute paths (must start with `/` after `file://`)
/// - Empty or root-only paths
/// - Path traversal (`..` components)
/// - Dangerous characters (null, newline, semicolons, backticks, pipes, shell expansion)
pub fn validate_file_uri(uri: &str) -> Result<()> {
    let path_str = uri.strip_prefix(FILE_URI_PREFIX).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "credential reference '{}' does not start with '{}'",
            uri, FILE_URI_PREFIX
        ))
    })?;

    if !path_str.starts_with('/') {
        return Err(NonoError::ConfigParse(format!(
            "file:// URI must use an absolute path (file:///path), got: {}",
            uri
        )));
    }

    let meaningful = path_str.trim_end_matches('/');
    if meaningful.is_empty() || meaningful == "/" {
        return Err(NonoError::ConfigParse(format!(
            "file:// URI path is empty: {}",
            uri
        )));
    }

    for component in std::path::Path::new(path_str).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(NonoError::ConfigParse(format!(
                "file:// URI must not contain path traversal (..): {}",
                uri
            )));
        }
    }

    const FORBIDDEN_FILE_CHARS: &[char] = &['\0', '\n', '\r', ';', '`', '|', '$', '&', '>', '<'];
    if let Some(bad) = path_str.chars().find(|c| FORBIDDEN_FILE_CHARS.contains(c)) {
        return Err(NonoError::ConfigParse(format!(
            "file:// URI contains forbidden character {:?}: {}",
            bad, uri
        )));
    }

    Ok(())
}

/// Validate a destination environment variable name.
///
/// Ensures the target variable name is not on the dangerous blocklist and
/// follows standard naming conventions (`[A-Za-z0-9_]+`). This prevents
/// Environment Variable Injection where an attacker specifies a dangerous
/// target like `LD_PRELOAD` or `PATH` via explicit `=TARGET` syntax.
///
/// The check is case-insensitive to prevent bypass via `ld_preload` etc.
pub fn validate_destination_env_var(var_name: &str) -> Result<()> {
    if var_name.is_empty() {
        return Err(NonoError::ConfigParse(
            "destination environment variable name cannot be empty".to_string(),
        ));
    }

    if let Some(bad) = var_name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '_')
    {
        return Err(NonoError::ConfigParse(format!(
            "destination environment variable name contains invalid character {:?}: {}",
            bad, var_name
        )));
    }

    if DANGEROUS_ENV_VAR_NAMES
        .iter()
        .any(|&d| d.eq_ignore_ascii_case(var_name))
    {
        return Err(NonoError::ConfigParse(format!(
            "destination environment variable '{}' is on the blocklist of dangerous variables",
            var_name
        )));
    }

    Ok(())
}

/// Load a secret from an environment variable.
///
/// Reads from the current process environment (before sandbox application).
/// The value is wrapped in `Zeroizing<String>` to minimize plaintext lifetime.
///
/// # Errors
///
/// Returns `SecretNotFound` if the variable is unset or empty.
/// Returns `KeystoreAccess` if the variable contains non-UTF-8 data.
fn load_from_env(uri: &str) -> Result<Zeroizing<String>> {
    validate_env_uri(uri)?;

    let var_name = uri
        .strip_prefix(ENV_URI_PREFIX)
        .ok_or_else(|| NonoError::ConfigParse(format!("invalid env:// URI: {}", uri)))?;

    match std::env::var(var_name) {
        Ok(value) if value.is_empty() => Err(NonoError::SecretNotFound(format!(
            "environment variable '{}' is set but empty",
            var_name
        ))),
        Ok(value) => {
            tracing::debug!("Loaded secret from environment variable '{}'", var_name);
            Ok(Zeroizing::new(value))
        }
        Err(std::env::VarError::NotPresent) => Err(NonoError::SecretNotFound(format!(
            "environment variable '{}' is not set",
            var_name
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(NonoError::KeystoreAccess(format!(
            "environment variable '{}' contains non-UTF-8 data",
            var_name
        ))),
    }
}

/// Load a secret from a local file via `file://` URI.
///
/// Reads the file contents at startup (before sandbox activation), trims
/// whitespace, and wraps the result in `Zeroizing<String>`. The file is
/// read once — subsequent access is from the in-memory zeroized copy.
///
/// # Errors
///
/// Returns `SecretNotFound` if the file does not exist or is empty.
/// Returns `KeystoreAccess` for other I/O errors (permissions, etc.).
fn load_from_file(uri: &str) -> Result<Zeroizing<String>> {
    validate_file_uri(uri)?;

    let path_str = uri
        .strip_prefix(FILE_URI_PREFIX)
        .ok_or_else(|| NonoError::ConfigParse(format!("invalid file:// URI: {}", uri)))?;

    let trimmed = load_secret_file(Path::new(path_str)).map_err(|e| match e {
        NonoError::SecretNotFound(_) => {
            NonoError::SecretNotFound(format!("credential file not found: {}", path_str))
        }
        NonoError::KeystoreAccess(_) => {
            NonoError::KeystoreAccess(format!("failed to read credential file '{}'", path_str))
        }
        other => other,
    })?;

    tracing::debug!("Loaded secret from {}", redact_file_uri(uri));
    Ok(trimmed)
}

/// Load a secret from a local file and wrap it in [`Zeroizing`].
///
/// Intended for callers that need a common file-backed secret path without
/// duplicating plaintext handling. A single trailing line ending is removed to
/// match CLI-based secret loaders; other leading/trailing whitespace is
/// preserved.
pub fn load_secret_file(path: &Path) -> Result<Zeroizing<String>> {
    let mut content = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            NonoError::SecretNotFound(format!("secret file not found: {}", path.display()))
        } else {
            NonoError::KeystoreAccess(format!(
                "failed to read secret file '{}': {}",
                path.display(),
                e
            ))
        }
    })?);

    if content.ends_with("\r\n") {
        let new_len = content.len().saturating_sub(2);
        content.truncate(new_len);
    } else if content.ends_with('\n') {
        let new_len = content.len().saturating_sub(1);
        content.truncate(new_len);
    }

    if content.is_empty() {
        return Err(NonoError::SecretNotFound(format!(
            "secret file '{}' is empty",
            path.display()
        )));
    }

    Ok(content)
}

/// Store a secret in a local file with owner-only permissions on Unix.
///
/// This is primarily used by trust-related file-backed keystore adapters and
/// keeps the file handling consistent with runtime secret loading helpers.
pub fn store_secret_file(path: &Path, secret: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "failed to create secret directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    NonoError::KeystoreAccess(format!(
                        "failed to secure existing secret file {}: {e}",
                        path.display()
                    ))
                },
            )?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                NonoError::KeystoreAccess(format!(
                    "failed to store secret at {}: {e}",
                    path.display()
                ))
            })?;

        file.write_all(secret.as_bytes()).map_err(|e| {
            NonoError::KeystoreAccess(format!("failed to store secret at {}: {e}", path.display()))
        })?;

        file.sync_all().map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "failed to sync secret file {}: {e}",
                path.display()
            ))
        })?;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "failed to secure secret file {}: {e}",
                path.display()
            ))
        })?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::File::create(path).map_err(|e| {
            NonoError::KeystoreAccess(format!("failed to store secret at {}: {e}", path.display()))
        })?;

        file.write_all(secret.as_bytes()).map_err(|e| {
            NonoError::KeystoreAccess(format!("failed to store secret at {}: {e}", path.display()))
        })?;
    }

    Ok(())
}

/// Load a single secret from the keystore.
///
/// The returned value is immediately wrapped in `Zeroizing` so the heap
/// buffer will be zeroed on drop. Note: the keyring crate may create
/// intermediate heap allocations internally (e.g. during UTF-8 conversion)
/// that are freed without being zeroed. This is a known limitation of the
/// keyring crate that we cannot address from the caller side.
#[cfg(feature = "system-keyring")]
fn load_single_secret(service: &str, account: &str) -> Result<Zeroizing<String>> {
    let entry = keyring::Entry::new(service, account).map_err(|e| {
        NonoError::KeystoreAccess(format!(
            "Failed to access keystore for '{}': {}",
            account, e
        ))
    })?;

    match entry.get_password() {
        Ok(password) => {
            // Immediately wrap in Zeroizing so the String's heap buffer is
            // zeroed when the secret is dropped. The move does not copy the
            // heap allocation - it transfers ownership of the same buffer.
            tracing::debug!("Successfully loaded secret '{}'", account);
            Ok(Zeroizing::new(password))
        }
        Err(keyring::Error::NoEntry) => Err(NonoError::SecretNotFound(account.to_string())),
        Err(keyring::Error::Ambiguous(creds)) => Err(NonoError::KeystoreAccess(format!(
            "Multiple entries ({}) found for '{}' - please resolve manually",
            creds.len(),
            account
        ))),
        Err(e) => Err(NonoError::KeystoreAccess(format!(
            "Cannot access '{}': {}",
            account, e
        ))),
    }
}

#[cfg(not(feature = "system-keyring"))]
fn load_single_secret(_service: &str, account: &str) -> Result<Zeroizing<String>> {
    Err(NonoError::KeystoreAccess(format!(
        "system keyring is not available (built without system-keyring feature); \
         cannot load '{}'. Use env://, file://, or op:// credential references instead.",
        account
    )))
}

/// Load a secret from 1Password using the `op` CLI.
///
/// Runs `op read <uri>` and captures stdout. The `op` binary must be
/// installed and authenticated (via biometric, CLI session, or
/// `OP_SERVICE_ACCOUNT_TOKEN` in the parent environment).
///
/// # Security Notes
/// - `op` runs BEFORE the sandbox is applied, so it has network access.
/// - stdout is read into a `Zeroizing<String>` to minimize plaintext lifetime.
/// - The URI is validated before being passed to `op` to prevent argument injection.
/// - `Command::new` is used (no shell), so shell metacharacters in the URI
///   cannot cause command injection.
fn load_from_op(uri: &str) -> Result<Zeroizing<String>> {
    validate_op_uri(uri)?;

    tracing::debug!("Loading secret from 1Password: {}", redact_op_uri(uri));

    let mut child = Command::new("op")
        .args(["read", "--", uri])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::KeystoreAccess(
                    "1Password CLI ('op') not found. \
                     Install it from https://developer.1password.com/docs/cli/"
                        .to_string(),
                )
            } else {
                NonoError::KeystoreAccess(format!("Could not start the 1Password CLI: {}", e))
            }
        })?;

    let output = wait_with_timeout(
        &mut child,
        SECRET_MANAGER_TIMEOUT,
        "1Password CLI",
        "Is 1Password waiting for authentication?",
    )
    .map_err(|e| {
        // Kill the process if it timed out
        let _ = child.kill();
        let _ = child.wait();
        e
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(classify_op_error(&stderr, uri));
    }

    // Convert stdout to string, trim trailing newline, wrap in Zeroizing.
    // `op read` outputs the raw secret followed by a newline.
    let raw = String::from_utf8(output.stdout).map_err(|_| {
        NonoError::KeystoreAccess(format!(
            "1Password returned non-UTF-8 data for '{}'",
            redact_op_uri(uri)
        ))
    })?;

    let trimmed = raw.trim_end_matches(['\n', '\r']).to_string();
    Ok(Zeroizing::new(trimmed))
}

/// Load a secret from Apple Passwords using macOS `security`.
///
/// Runs `security find-internet-password -s <server> -a <account> -w` and captures
/// stdout. This backend is macOS-only.
fn load_from_apple_password(uri: &str) -> Result<Zeroizing<String>> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = uri;
        Err(NonoError::KeystoreAccess(
            "Apple Passwords credentials are only supported on macOS".to_string(),
        ))
    }

    #[cfg(target_os = "macos")]
    {
        let (server, account) = parse_apple_password_uri(uri)?;
        tracing::debug!(
            "Loading secret from Apple Passwords: {}",
            redact_apple_password_uri(uri)
        );

        let mut child = Command::new("security")
            .args(["find-internet-password", "-s", server, "-a", account, "-w"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    NonoError::KeystoreAccess(
                        "macOS 'security' CLI not found (required for Apple Passwords lookup)"
                            .to_string(),
                    )
                } else {
                    NonoError::KeystoreAccess(format!("Could not start macOS security CLI: {}", e))
                }
            })?;

        let output = wait_with_timeout(
            &mut child,
            SECRET_MANAGER_TIMEOUT,
            "macOS security CLI",
            "Is Keychain access waiting for user approval?",
        )
        .map_err(|e| {
            let _ = child.kill();
            let _ = child.wait();
            e
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(classify_apple_password_error(&stderr, uri));
        }

        let raw = String::from_utf8(output.stdout).map_err(|_| {
            NonoError::KeystoreAccess(format!(
                "Apple Passwords returned non-UTF-8 data for '{}'",
                redact_apple_password_uri(uri)
            ))
        })?;

        let trimmed = raw.trim_end_matches(['\n', '\r']).to_string();
        Ok(Zeroizing::new(trimmed))
    }
}

/// Load a secret from the system keyring using a custom service name.
///
/// Uses the `keyring` crate with the service and account parsed from a
/// `keyring://service/account` URI. This is cross-platform: macOS Keychain
/// (generic passwords), Linux Secret Service, Windows Credential Manager.
///
/// If `?decode=go-keyring` is specified, the stored value is unwrapped from
/// the `go-keyring-base64:` encoding used by `github.com/zalando/go-keyring`.
#[cfg(feature = "system-keyring")]
fn load_from_keyring_uri(uri: &str) -> Result<Zeroizing<String>> {
    let parts = parse_keyring_uri(uri)?;
    let redacted = redact_keyring_uri(uri);
    tracing::debug!("Loading secret from system keyring: {}", redacted);

    let entry = keyring::Entry::new(parts.service, parts.account).map_err(|e| {
        NonoError::KeystoreAccess(format!(
            "Failed to access keyring for '{}': {}",
            redacted, e
        ))
    })?;

    match entry.get_password() {
        Ok(password) => {
            tracing::debug!("Successfully loaded secret '{}'", redacted);
            let decoded = apply_keyring_decode(password, parts.decode, &redacted)?;
            Ok(decoded)
        }
        Err(keyring::Error::NoEntry) => Err(NonoError::SecretNotFound(format!(
            "keyring entry not found: '{}'. \
             Verify the service and account match the stored credential.",
            redacted
        ))),
        Err(keyring::Error::Ambiguous(creds)) => Err(NonoError::KeystoreAccess(format!(
            "Multiple entries ({}) found for '{}' - please resolve manually",
            creds.len(),
            redacted
        ))),
        Err(e) => Err(NonoError::KeystoreAccess(format!(
            "Cannot access '{}': {}",
            redacted, e
        ))),
    }
}

#[cfg(not(feature = "system-keyring"))]
fn load_from_keyring_uri(uri: &str) -> Result<Zeroizing<String>> {
    let redacted = redact_keyring_uri(uri);
    Err(NonoError::KeystoreAccess(format!(
        "system keyring is not available (built without system-keyring feature); \
         cannot load '{}'. Use env://, file://, or op:// credential references instead.",
        redacted
    )))
}

/// Apply the requested post-load decoding to a keyring value.
#[cfg(feature = "system-keyring")]
fn apply_keyring_decode(
    raw: String,
    decode: KeyringDecode,
    redacted_uri: &str,
) -> Result<Zeroizing<String>> {
    match decode {
        KeyringDecode::None => Ok(Zeroizing::new(raw)),
        KeyringDecode::GoKeyring => {
            let encoded = raw.strip_prefix(GO_KEYRING_PREFIX).ok_or_else(|| {
                NonoError::ConfigParse(format!(
                    "keyring value for '{}' does not have the expected '{}' prefix. \
                     Remove ?decode=go-keyring if this credential was not stored by a Go tool.",
                    redacted_uri, GO_KEYRING_PREFIX
                ))
            })?;
            let bytes = crate::trust::base64::base64_decode(encoded).map_err(|e| {
                NonoError::ConfigParse(format!(
                    "failed to base64-decode go-keyring value for '{}': {}",
                    redacted_uri, e
                ))
            })?;
            let decoded = String::from_utf8(bytes).map_err(|_| {
                NonoError::ConfigParse(format!(
                    "go-keyring decoded value for '{}' is not valid UTF-8",
                    redacted_uri
                ))
            })?;
            Ok(Zeroizing::new(decoded))
        }
    }
}

/// Classify `op` CLI errors into actionable error messages.
fn classify_op_error(stderr: &str, uri: &str) -> NonoError {
    let redacted = redact_op_uri(uri);
    let stderr_trimmed = stderr.trim();

    if stderr.contains("not signed in")
        || stderr.contains("sign in")
        || stderr.contains("authentication required")
        || stderr.contains("session expired")
    {
        NonoError::KeystoreAccess(format!(
            "1Password authentication required for '{}'. \
             Run 'op signin' or set OP_SERVICE_ACCOUNT_TOKEN. \
             Detail: {}",
            redacted, stderr_trimmed
        ))
    } else if stderr.contains("not found")
        || stderr.contains("could not find")
        || stderr.contains("isn't an item")
    {
        NonoError::SecretNotFound(format!(
            "1Password item not found: '{}'. Detail: {}",
            redacted, stderr_trimmed
        ))
    } else {
        NonoError::KeystoreAccess(format!(
            "1Password CLI failed for '{}': {}",
            redacted, stderr_trimmed
        ))
    }
}

/// Classify `security` CLI errors for Apple Passwords lookups.
#[cfg(target_os = "macos")]
fn classify_apple_password_error(stderr: &str, uri: &str) -> NonoError {
    let redacted = redact_apple_password_uri(uri);
    let stderr_trimmed = stderr.trim();

    if stderr.contains("could not be found in the keychain")
        || stderr.contains("The specified item could not be found")
    {
        NonoError::SecretNotFound(format!(
            "Apple Passwords entry not found: '{}'. Detail: {}",
            redacted, stderr_trimmed
        ))
    } else if stderr.contains("User interaction is not allowed") {
        NonoError::KeystoreAccess(format!(
            "Apple Passwords access requires user approval for '{}'. \
             Unlock Keychain/Passwords and retry. Detail: {}",
            redacted, stderr_trimmed
        ))
    } else {
        NonoError::KeystoreAccess(format!(
            "Apple Passwords lookup failed for '{}': {}",
            redacted, stderr_trimmed
        ))
    }
}

/// Redact the field segment of an `op://` URI for safe logging.
///
/// `op://vault/item/field` → `op://vault/item/<redacted>`
pub fn redact_op_uri(uri: &str) -> String {
    if let Some(path) = uri.strip_prefix(OP_URI_PREFIX) {
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() >= 3 {
            return format!("op://{}/{}/<redacted>", parts[0], parts[1]);
        }
    }
    "op://***".to_string()
}

/// Redact the account segment of an Apple Passwords URI for safe logging.
///
/// `apple-password://server/account` → `apple-password://server/<redacted>`
pub fn redact_apple_password_uri(uri: &str) -> String {
    if let Some(path) = strip_apple_password_prefix(uri) {
        let mut segments = path.splitn(2, '/');
        if let Some(server) = segments.next() {
            if !server.is_empty() && segments.next().is_some() {
                return format!("apple-password://{}/<redacted>", server);
            }
        }
    }
    "apple-password://***".to_string()
}

/// Redact a file:// URI for safe logging.
/// Keeps the directory structure but replaces the filename.
/// `file:///run/secrets/api-token` → `file:///run/secrets/[REDACTED]`
pub fn redact_file_uri(uri: &str) -> String {
    if let Some(path) = uri.strip_prefix(FILE_URI_PREFIX) {
        if let Some(last_slash) = path.rfind('/') {
            return format!("{}{}[REDACTED]", FILE_URI_PREFIX, &path[..=last_slash]);
        }
    }
    format!("{}[REDACTED]", FILE_URI_PREFIX)
}

/// Wait for a child process with a timeout.
///
/// Returns the process output on success, or a timeout error.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
    backend_name: &str,
    timeout_hint: &str,
) -> Result<std::process::Output> {
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited — collect output
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    std::io::Read::read_to_end(&mut out, &mut stdout).ok();
                }
                if let Some(mut err) = child.stderr.take() {
                    std::io::Read::read_to_end(&mut err, &mut stderr).ok();
                }
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                // Still running
                if start.elapsed() >= timeout {
                    return Err(NonoError::KeystoreAccess(format!(
                        "{} timed out after {}s. {}",
                        backend_name,
                        timeout.as_secs(),
                        timeout_hint
                    )));
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(NonoError::KeystoreAccess(format!(
                    "Failed to check {} status: {}",
                    backend_name, e
                )));
            }
        }
    }
}

/// Build secret mappings from a comma-separated list of credential entries.
///
/// Supports four formats:
/// - **Keyring names**: `openai_api_key` → env var `OPENAI_API_KEY` (auto-uppercased)
/// - **1Password URIs with explicit var**: `op://vault/item/field=MY_VAR` → env var `MY_VAR`
/// - **Environment URIs**: `env://GITHUB_TOKEN` → env var `GITHUB_TOKEN` (auto-derived)
///   or `env://GITHUB_TOKEN=GH_TOKEN` → env var `GH_TOKEN` (explicit)
///
/// URI-based managers must include explicit target variable names:
/// - `op://...=VAR_NAME`
///
/// Bare URI entries without explicit target variables are rejected.
///
/// Apple Passwords references (`apple-password://...`) and keyring references
/// (`keyring://...`) are not supported in this list-based parser. Use
/// `build_mappings_from_pairs` (CLI: `--env-credential-map <CREDENTIAL_REF>
/// <ENV_VAR>`) for explicit mapping.
///
/// Environment URIs (`env://...`) auto-derive the target variable name from the source
/// when `=` is omitted: `env://GITHUB_TOKEN` maps to env var `GITHUB_TOKEN`.
///
/// # Errors
///
/// Returns an error if a URI-based secret manager entry is provided without an
/// explicit target variable suffix, if an Apple Passwords or keyring URI is
/// provided in list mode, or if any URI fails validation.
///
/// # Example
///
/// ```
/// use nono::keystore::build_mappings_from_list;
///
/// let mappings = build_mappings_from_list("openai_api_key,anthropic_key").unwrap();
/// assert_eq!(mappings.get("openai_api_key"), Some(&"OPENAI_API_KEY".to_string()));
/// assert_eq!(mappings.get("anthropic_key"), Some(&"ANTHROPIC_KEY".to_string()));
/// ```
pub fn build_mappings_from_list(accounts: &str) -> Result<HashMap<String, String>> {
    let mut mappings = HashMap::new();

    for entry in accounts.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        if entry.starts_with(ENV_URI_PREFIX) {
            // env:// URI: auto-derive target var or use explicit =VAR_NAME
            if let Some(eq_pos) = entry.rfind('=') {
                let uri = &entry[..eq_pos];
                let var_name = &entry[eq_pos + 1..];

                if var_name.is_empty() {
                    return Err(NonoError::ConfigParse(format!(
                        "env:// credential '{}' has '=' but no variable name",
                        uri
                    )));
                }

                validate_env_uri(uri)?;
                validate_destination_env_var(var_name)?;
                mappings.insert(uri.to_string(), var_name.to_string());
            } else {
                // Auto-derive: env://GITHUB_TOKEN -> target GITHUB_TOKEN
                validate_env_uri(entry)?;
                // Safe: validate_env_uri confirmed the prefix exists
                let source_var = match entry.strip_prefix(ENV_URI_PREFIX) {
                    Some(v) => v,
                    None => {
                        return Err(NonoError::ConfigParse("invalid env:// URI".to_string()));
                    }
                };
                mappings.insert(entry.to_string(), source_var.to_string());
            }
        } else if entry.starts_with(FILE_URI_PREFIX) {
            // file:// URI: must have explicit =VAR_NAME suffix because
            // you can't derive a meaningful env var name from a file path.
            // Format: file:///path/to/secret=MY_VAR
            if let Some(eq_pos) = entry.rfind('=') {
                let uri = &entry[..eq_pos];
                let var_name = &entry[eq_pos + 1..];

                if var_name.is_empty() {
                    return Err(NonoError::ConfigParse(format!(
                        "file:// credential '{}' has '=' but no variable name. \
                         Use format: file:///path/to/secret=MY_VAR",
                        uri
                    )));
                }

                validate_file_uri(uri)?;
                validate_destination_env_var(var_name)?;
                mappings.insert(uri.to_string(), var_name.to_string());
            } else {
                return Err(NonoError::ConfigParse(format!(
                    "file:// credential '{}' requires an explicit target variable. \
                     Use format: file:///path/to/secret=MY_VAR",
                    entry
                )));
            }
        } else if entry.starts_with(OP_URI_PREFIX) {
            // 1Password URI: must have =VAR_NAME suffix
            // Find the last '=' that separates the URI from the var name.
            // op:// URIs don't contain '=', so the last '=' is unambiguous.
            if let Some(eq_pos) = entry.rfind('=') {
                let uri = &entry[..eq_pos];
                let var_name = &entry[eq_pos + 1..];

                if var_name.is_empty() {
                    return Err(NonoError::ConfigParse(format!(
                        "1Password credential '{}' has '=' but no variable name. \
                         Use format: op://vault/item/field=MY_VAR",
                        redact_op_uri(uri)
                    )));
                }

                // Validate the URI portion
                validate_op_uri(uri)?;
                validate_destination_env_var(var_name)?;

                mappings.insert(uri.to_string(), var_name.to_string());
            } else {
                return Err(NonoError::ConfigParse(format!(
                    "1Password credential requires an explicit variable name. \
                     Use format: op://vault/item/field=MY_VAR (got '{}')",
                    redact_op_uri(entry)
                )));
            }
        } else if is_apple_password_uri(entry) {
            return Err(NonoError::ConfigParse(format!(
                "Apple Passwords credential '{}' is not supported in --env-credential. \
                 Use --env-credential-map 'apple-password://server/account' MY_VAR",
                redact_apple_password_uri(entry)
            )));
        } else if is_keyring_uri(entry) {
            return Err(NonoError::ConfigParse(format!(
                "keyring credential '{}' is not supported in --env-credential. \
                 Use --env-credential-map 'keyring://service/account' MY_VAR",
                redact_keyring_uri(entry)
            )));
        } else {
            // Keyring name: auto-uppercase to env var name
            let env_var = entry.to_uppercase();
            validate_destination_env_var(&env_var)?;
            mappings.insert(entry.to_string(), env_var);
        }
    }

    Ok(mappings)
}

/// Build secret mappings from explicit credential-ref/env-var pairs.
///
/// This is used by CLI options that pass the credential reference and
/// destination environment variable as separate arguments.
///
/// # Arguments
/// * `pairs` - List of `(credential_ref, env_var)` tuples
///
/// # Errors
///
/// Returns an error if any credential reference is empty, the destination env
/// var is invalid, or a URI reference fails structural validation.
pub fn build_mappings_from_pairs(pairs: &[(String, String)]) -> Result<HashMap<String, String>> {
    let mut mappings = HashMap::new();

    for (credential_ref, env_var) in pairs {
        let credential_ref = credential_ref.trim();
        let env_var = env_var.trim();

        if credential_ref.is_empty() {
            return Err(NonoError::ConfigParse(
                "credential reference is empty in --env-credential-map".to_string(),
            ));
        }

        validate_destination_env_var(env_var)?;

        if credential_ref.starts_with(OP_URI_PREFIX) {
            validate_op_uri(credential_ref)?;
        } else if is_apple_password_uri(credential_ref) {
            validate_apple_password_uri(credential_ref)?;
        } else if is_keyring_uri(credential_ref) {
            validate_keyring_uri(credential_ref)?;
        } else if credential_ref.starts_with(ENV_URI_PREFIX) {
            validate_env_uri(credential_ref)?;
        }

        mappings.insert(credential_ref.to_string(), env_var.to_string());
    }

    Ok(mappings)
}

/// Build secret mappings from CLI argument and/or profile secrets
///
/// Merges secrets from both sources, with CLI taking precedence.
///
/// # Arguments
/// * `cli_secrets` - Optional comma-separated list from CLI (--env-credential flag)
/// * `cli_secret_mappings` - Optional explicit mappings from
///   `--env-credential-map <CREDENTIAL_REF> <ENV_VAR>`
/// * `profile_secrets` - Mappings from profile's [secrets] section
///
/// # Returns
/// Combined map of credential reference -> env var name
///
/// # Errors
///
/// Returns an error if a URI-based credential in `cli_secrets` is missing
/// an explicit target variable suffix (`=VAR_NAME` for `op://`), if
/// `apple-password://` or `keyring://` appears in list mode, or if
/// URI/env-var validation fails.
pub fn build_secret_mappings(
    cli_secrets: Option<&str>,
    cli_secret_mappings: &[(String, String)],
    profile_secrets: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut combined = profile_secrets.clone();

    // CLI secrets override profile secrets
    if let Some(secrets_str) = cli_secrets {
        let cli_mappings = build_mappings_from_list(secrets_str)?;
        combined.extend(cli_mappings);
    }

    // Explicit CLI mappings override both profile secrets and --env-credential.
    if !cli_secret_mappings.is_empty() {
        let explicit_mappings = build_mappings_from_pairs(cli_secret_mappings)?;
        combined.extend(explicit_mappings);
    }

    Ok(combined)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::disallowed_methods)] // Tests use unique env var names (NONO_TEST_*), no contention.
mod tests;
