//! Credentials from a systemd credentials directory.
//!
//! `LoadCredential=` hands a service its secrets as files in a private
//! directory only the service user can read. A binding names one of those
//! files and the environment variable the service reads it from, so the
//! secret never sits in an environment file on disk and never appears in
//! the unit's argument list.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

/// The most bytes one credential may carry. Bearer tokens and pinned public
/// keys are far smaller; anything larger is not a value this launcher should
/// place in an environment variable.
pub const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;

/// One credential file and the environment variable that receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialBinding {
    pub variable: String,
    pub name: String,
}

impl FromStr for CredentialBinding {
    type Err = CredentialError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let Some((variable, name)) = spec.split_once('=') else {
            return Err(CredentialError::Binding(
                spec.to_string(),
                "expected VARIABLE=CREDENTIAL",
            ));
        };
        if !is_variable_name(variable) {
            return Err(CredentialError::Binding(
                spec.to_string(),
                "the variable is not a valid environment variable name",
            ));
        }
        if !is_credential_name(name) {
            return Err(CredentialError::Binding(
                spec.to_string(),
                "the credential must be one file name of letters, digits, '.', '-' or '_' that does not start with '.'",
            ));
        }
        Ok(Self {
            variable: variable.to_string(),
            name: name.to_string(),
        })
    }
}

impl fmt::Display for CredentialBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.variable, self.name)
    }
}

fn is_variable_name(variable: &str) -> bool {
    let mut chars = variable.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn is_credential_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Why a credential could not be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// A binding specification could not be parsed.
    Binding(String, &'static str),
    /// Bindings were given but no credentials directory is known.
    NoDirectory,
    /// The credential file could not be opened or read.
    Unreadable { name: String, reason: String },
    /// The credential is not a regular file.
    NotARegularFile(String),
    /// The credential is readable by its group or by others.
    Exposed(String),
    /// The credential exceeds [`MAX_CREDENTIAL_BYTES`].
    TooLarge(String),
    /// The credential is not UTF-8.
    NotUtf8(String),
    /// The credential is empty once its trailing newline is removed.
    Empty(String),
    /// The credential carries whitespace padding or a control character.
    Padded(String),
    /// One variable is bound to two credentials.
    Duplicate(String),
    /// The variable is already set in the environment.
    Shadows(String),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding(spec, reason) => write!(f, "credential binding {spec:?}: {reason}"),
            Self::NoDirectory => write!(
                f,
                "credentials were bound but no credentials directory is known; run under systemd LoadCredential= or pass --credentials-dir"
            ),
            Self::Unreadable { name, reason } => write!(f, "credential {name} cannot be read: {reason}"),
            Self::NotARegularFile(name) => write!(f, "credential {name} is not a regular file"),
            Self::Exposed(name) => write!(f, "credential {name} is readable by its group or by others"),
            Self::TooLarge(name) => write!(
                f,
                "credential {name} exceeds {MAX_CREDENTIAL_BYTES} bytes"
            ),
            Self::NotUtf8(name) => write!(f, "credential {name} is not UTF-8"),
            Self::Empty(name) => write!(f, "credential {name} is empty"),
            Self::Padded(name) => write!(
                f,
                "credential {name} carries whitespace padding or a control character; only one trailing newline is removed"
            ),
            Self::Duplicate(variable) => write!(f, "{variable} is bound to more than one credential"),
            Self::Shadows(variable) => write!(
                f,
                "{variable} is already set in the environment; a credential must be the only source of a secret"
            ),
        }
    }
}

impl std::error::Error for CredentialError {}

/// Read one credential from `directory`.
///
/// The file must be a regular file that only its owner can read, at most
/// [`MAX_CREDENTIAL_BYTES`] of UTF-8. Exactly one trailing newline is
/// removed, because that is how most tools write a file; any other padding
/// or control character is refused rather than silently trimmed.
pub fn load_credential(directory: &Path, name: &str) -> Result<String, CredentialError> {
    if !is_credential_name(name) {
        return Err(CredentialError::Binding(
            name.to_string(),
            "the credential must be one file name of letters, digits, '.', '-' or '_' that does not start with '.'",
        ));
    }
    let path = directory.join(name);
    let unreadable = |reason: String| CredentialError::Unreadable {
        name: name.to_string(),
        reason,
    };
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| unreadable(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| unreadable(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(CredentialError::NotARegularFile(name.to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CredentialError::Exposed(name.to_string()));
        }
    }
    if metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(CredentialError::TooLarge(name.to_string()));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| unreadable(error.to_string()))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_CREDENTIAL_BYTES) {
        return Err(CredentialError::TooLarge(name.to_string()));
    }
    let text = String::from_utf8(bytes).map_err(|_| CredentialError::NotUtf8(name.to_string()))?;
    let value = text.strip_suffix('\n').unwrap_or(&text);
    if value.is_empty() {
        return Err(CredentialError::Empty(name.to_string()));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(CredentialError::Padded(name.to_string()));
    }
    Ok(value.to_string())
}

/// Resolve every binding against `directory`, refusing a variable that is
/// bound twice or already present in the environment (`is_set`).
pub fn load_bindings(
    directory: Option<&Path>,
    bindings: &[CredentialBinding],
    is_set: impl Fn(&str) -> bool,
) -> Result<Vec<(String, String)>, CredentialError> {
    if bindings.is_empty() {
        return Ok(Vec::new());
    }
    let Some(directory) = directory else {
        return Err(CredentialError::NoDirectory);
    };
    let mut seen = BTreeSet::new();
    let mut loaded = Vec::with_capacity(bindings.len());
    for binding in bindings {
        if !seen.insert(binding.variable.as_str()) {
            return Err(CredentialError::Duplicate(binding.variable.clone()));
        }
        if is_set(&binding.variable) {
            return Err(CredentialError::Shadows(binding.variable.clone()));
        }
        let value = load_credential(directory, &binding.name)?;
        loaded.push((binding.variable.clone(), value));
    }
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_credential(directory: &Path, name: &str, bytes: &[u8], mode: u32) {
        let path = directory.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut file = options
            .open(&path)
            .unwrap_or_else(|error| panic!("{error}"));
        std::io::Write::write_all(&mut file, bytes).unwrap_or_else(|error| panic!("{error}"));
    }

    fn binding(spec: &str) -> CredentialBinding {
        spec.parse().unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn bindings_parse_and_reject_malformed_specs() {
        assert_eq!(
            binding("CHIO_AUTH_TOKEN=session-token"),
            CredentialBinding {
                variable: "CHIO_AUTH_TOKEN".to_string(),
                name: "session-token".to_string()
            }
        );
        for spec in [
            "no-equals",
            "1BAD=name",
            "VAR=",
            "VAR=.hidden",
            "VAR=../escape",
            "VAR=a/b",
            "VAR=with space",
        ] {
            assert!(
                spec.parse::<CredentialBinding>().is_err(),
                "{spec} must be rejected"
            );
        }
    }

    #[test]
    fn one_trailing_newline_is_removed_and_padding_is_refused() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        write_credential(directory.path(), "exact", b"token-value", 0o600);
        write_credential(directory.path(), "newline", b"token-value\n", 0o600);
        write_credential(directory.path(), "two-newlines", b"token-value\n\n", 0o600);
        write_credential(directory.path(), "crlf", b"token-value\r\n", 0o600);
        write_credential(directory.path(), "leading", b" token-value", 0o600);
        write_credential(directory.path(), "empty", b"\n", 0o600);
        assert_eq!(
            load_credential(directory.path(), "exact").as_deref(),
            Ok("token-value")
        );
        assert_eq!(
            load_credential(directory.path(), "newline").as_deref(),
            Ok("token-value")
        );
        assert_eq!(
            load_credential(directory.path(), "two-newlines"),
            Err(CredentialError::Padded("two-newlines".to_string()))
        );
        assert_eq!(
            load_credential(directory.path(), "crlf"),
            Err(CredentialError::Padded("crlf".to_string()))
        );
        assert_eq!(
            load_credential(directory.path(), "leading"),
            Err(CredentialError::Padded("leading".to_string()))
        );
        assert_eq!(
            load_credential(directory.path(), "empty"),
            Err(CredentialError::Empty("empty".to_string()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn exposed_linked_oversized_and_missing_credentials_are_refused() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        write_credential(directory.path(), "exposed", b"token", 0o640);
        assert_eq!(
            load_credential(directory.path(), "exposed"),
            Err(CredentialError::Exposed("exposed".to_string()))
        );
        write_credential(directory.path(), "target", b"token", 0o600);
        std::os::unix::fs::symlink(directory.path().join("target"), directory.path().join("link"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            load_credential(directory.path(), "link"),
            Err(CredentialError::Unreadable { .. })
        ));
        let oversized = vec![b'x'; usize::try_from(MAX_CREDENTIAL_BYTES).unwrap_or(0) + 1];
        write_credential(directory.path(), "oversized", &oversized, 0o600);
        assert_eq!(
            load_credential(directory.path(), "oversized"),
            Err(CredentialError::TooLarge("oversized".to_string()))
        );
        assert!(matches!(
            load_credential(directory.path(), "missing"),
            Err(CredentialError::Unreadable { .. })
        ));
        write_credential(directory.path(), "binary", &[0xff, 0xfe], 0o600);
        assert_eq!(
            load_credential(directory.path(), "binary"),
            Err(CredentialError::NotUtf8("binary".to_string()))
        );
    }

    #[test]
    fn bindings_refuse_duplicates_shadowing_and_a_missing_directory() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        write_credential(directory.path(), "session-token", b"s\n", 0o600);
        write_credential(directory.path(), "admin-token", b"a", 0o600);
        let bindings = [
            binding("CHIO_AUTH_TOKEN=session-token"),
            binding("CHIO_ADMIN_TOKEN=admin-token"),
        ];
        let loaded = load_bindings(Some(directory.path()), &bindings, |_| false)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            loaded,
            vec![
                ("CHIO_AUTH_TOKEN".to_string(), "s".to_string()),
                ("CHIO_ADMIN_TOKEN".to_string(), "a".to_string())
            ]
        );
        assert_eq!(
            load_bindings(None, &bindings, |_| false),
            Err(CredentialError::NoDirectory)
        );
        assert_eq!(load_bindings(None, &[], |_| false), Ok(Vec::new()));
        assert_eq!(
            load_bindings(Some(directory.path()), &bindings, |variable| variable == "CHIO_ADMIN_TOKEN"),
            Err(CredentialError::Shadows("CHIO_ADMIN_TOKEN".to_string()))
        );
        let duplicated = [
            binding("CHIO_AUTH_TOKEN=session-token"),
            binding("CHIO_AUTH_TOKEN=admin-token"),
        ];
        assert_eq!(
            load_bindings(Some(directory.path()), &duplicated, |_| false),
            Err(CredentialError::Duplicate("CHIO_AUTH_TOKEN".to_string()))
        );
    }
}
