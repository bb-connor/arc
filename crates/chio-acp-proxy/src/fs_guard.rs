/// Filesystem access guard that enforces path-scoped capabilities.
///
/// The guard is fail-closed: if no allowed prefix matches, access is
/// denied. Path traversal attacks using `..` components are rejected
/// before prefix checking.
///
/// **Symlink limitation**: By default the guard uses purely textual
/// canonicalization and does not resolve symlinks. A path such as
/// `/home/user/project/link -> /etc/secret` will pass the prefix
/// check even though the real target is outside the allowed tree.
/// Enable `resolve_symlinks` to use `std::fs::canonicalize()` which
/// queries the filesystem and resolves symlinks, at the cost of
/// requiring the path to exist (writes to new files fall back to
/// textual canonicalization when the target does not yet exist).
#[derive(Debug, Clone)]
pub struct FsGuard {
    allowed_prefixes: Vec<String>,
    /// When true, attempt `std::fs::canonicalize()` before prefix
    /// matching. Falls back to textual canonicalization if the path
    /// does not exist (e.g. new files being written).
    resolve_symlinks: bool,
}

impl FsGuard {
    /// Create a new guard with the given set of allowed path prefixes.
    ///
    /// Symlink resolution is **off** by default. Call
    /// [`with_resolve_symlinks`](Self::with_resolve_symlinks) to enable it.
    pub fn new(allowed_prefixes: Vec<String>) -> Self {
        Self {
            allowed_prefixes,
            resolve_symlinks: false,
        }
    }

    /// Enable or disable filesystem-level symlink resolution.
    ///
    /// When enabled, the guard calls `std::fs::canonicalize()` to
    /// resolve symlinks before checking prefixes. If the path does
    /// not exist on disk (common for write-to-new-file), the guard
    /// falls back to textual canonicalization.
    #[must_use]
    pub fn with_resolve_symlinks(mut self, resolve: bool) -> Self {
        self.resolve_symlinks = resolve;
        self
    }

    /// Check whether a read operation on `path` is permitted.
    pub fn check_read(&self, path: &str) -> Result<(), AcpProxyError> {
        self.check_path(path, "read")
    }

    /// Check whether a write operation on `path` is permitted.
    pub fn check_write(&self, path: &str) -> Result<(), AcpProxyError> {
        self.check_path(path, "write")
    }

    fn check_path(&self, path: &str, operation: &str) -> Result<(), AcpProxyError> {
        // Reject empty paths immediately.
        if path.is_empty() {
            return Err(AcpProxyError::AccessDenied(format!(
                "fs {operation} denied: empty path"
            )));
        }

        // Reject relative paths -- all allowed prefixes are absolute.
        if !path.starts_with('/') {
            return Err(AcpProxyError::AccessDenied(format!(
                "fs {operation} denied: relative path not allowed: {path}"
            )));
        }

        // Resolve the canonical path (optionally through the filesystem).
        let canonical = self.resolve_path(path);

        // Reject path traversal attempts.
        if contains_traversal(&canonical) {
            return Err(AcpProxyError::PathTraversal(path.to_string()));
        }

        // Fail-closed: deny if no prefix matches.
        if self.allowed_prefixes.is_empty() {
            return Err(AcpProxyError::AccessDenied(format!(
                "fs {operation} denied: no allowed path prefixes configured"
            )));
        }

        for prefix in &self.allowed_prefixes {
            if canonical.starts_with(prefix.as_str()) {
                // Ensure the match is on a path boundary, not a substring.
                // e.g. prefix "/home/user/project" must NOT match
                // "/home/user/project_evil/secret.txt".
                let is_exact = canonical.len() == prefix.len();
                let has_boundary = canonical
                    .as_bytes()
                    .get(prefix.len())
                    .map(|&b| b == b'/')
                    .unwrap_or(false);
                if is_exact || has_boundary {
                    return Ok(());
                }
            }
        }

        Err(AcpProxyError::AccessDenied(format!(
            "fs {operation} denied for path: {path}"
        )))
    }

    /// Resolve a path to its canonical form.
    ///
    /// When `resolve_symlinks` is enabled, attempts filesystem-level
    /// canonicalization first. Falls back to textual canonicalization
    /// if the path does not exist or an I/O error occurs.
    fn resolve_path(&self, path: &str) -> String {
        if self.resolve_symlinks {
            if let Ok(real) = std::fs::canonicalize(path) {
                return real.to_string_lossy().into_owned();
            }
            // Fallback: path may not exist yet (e.g. new file writes).
        }
        canonicalize_path(path)
    }
}

/// Normalize a path string for comparison.
///
/// This performs basic textual normalization (collapsing separators,
/// trimming trailing slashes) without touching the filesystem, so it
/// works in unit tests without real files.
fn canonicalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                // We still collect ".." but `contains_traversal` will
                // reject the path later.
                parts.push("..");
            }
            other => parts.push(other),
        }
    }
    if path.starts_with('/') {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

/// Return true if the path contains parent-directory traversal.
fn contains_traversal(path: &str) -> bool {
    path.split('/').any(|seg| seg == "..")
}
