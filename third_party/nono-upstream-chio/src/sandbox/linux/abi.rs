use landlock::{Access, AccessFs, AccessNet, Scope, ABI};

/// Detected Landlock ABI version with feature query methods.
///
/// Wraps the `landlock::ABI` enum and provides methods to query which
/// features are available at the detected ABI level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedAbi {
    /// The detected ABI version
    pub abi: ABI,
}

impl DetectedAbi {
    /// Create a new `DetectedAbi` from a raw `landlock::ABI`.
    #[must_use]
    pub fn new(abi: ABI) -> Self {
        Self { abi }
    }

    /// Whether file rename across directories is supported (V2+).
    #[must_use]
    pub fn has_refer(&self) -> bool {
        AccessFs::from_all(self.abi).contains(AccessFs::Refer)
    }

    /// Whether file truncation control is supported (V3+).
    #[must_use]
    pub fn has_truncate(&self) -> bool {
        AccessFs::from_all(self.abi).contains(AccessFs::Truncate)
    }

    /// Whether TCP network filtering is supported (V4+).
    #[must_use]
    pub fn has_network(&self) -> bool {
        !AccessNet::from_all(self.abi).is_empty()
    }

    /// Whether device ioctl filtering is supported (V5+).
    #[must_use]
    pub fn has_ioctl_dev(&self) -> bool {
        AccessFs::from_all(self.abi).contains(AccessFs::IoctlDev)
    }

    /// Whether process scoping (signals and abstract UNIX sockets) is supported (V6+).
    #[must_use]
    pub fn has_scoping(&self) -> bool {
        !Scope::from_all(self.abi).is_empty()
    }

    /// Return a human-readable version string (e.g., "V4").
    #[must_use]
    pub fn version_string(&self) -> &'static str {
        match self.abi {
            ABI::V1 => "V1",
            ABI::V2 => "V2",
            ABI::V3 => "V3",
            ABI::V4 => "V4",
            ABI::V5 => "V5",
            ABI::V6 => "V6",
            _ => "unknown",
        }
    }

    /// Return a list of available feature names at this ABI level.
    ///
    /// Each feature includes the specific Landlock flags in parentheses
    /// for consistency and debuggability.
    #[must_use]
    pub fn feature_names(&self) -> Vec<String> {
        let mut features = vec!["Basic filesystem access control".to_string()];
        if self.has_refer() {
            features.push("File rename across directories (Refer)".to_string());
        }
        if self.has_truncate() {
            features.push("File truncation (Truncate)".to_string());
        }
        if self.has_network() {
            features.push("TCP network filtering".to_string());
        }
        if self.has_ioctl_dev() {
            features.push("Device ioctl filtering".to_string());
        }
        if self.has_scoping() {
            features.push("Process scoping".to_string());
        }
        features
    }
}

impl std::fmt::Display for DetectedAbi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Landlock {}", self.version_string())
    }
}
