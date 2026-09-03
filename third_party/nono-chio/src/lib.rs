//! Fail-closed Chio adapter for the pinned nono capability model.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::os::fd::BorrowedFd;

use landlock::{
    Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus as KernelRulesetStatus, ABI,
};
use nono::{AccessMode, NetworkMode};

/// Reviewed upstream nono release.
pub const UPSTREAM_NONO_VERSION: &str = "0.53.0";

/// Version of Chio's wrapper patch semantics.
pub const CHIO_PATCH_VERSION: &str = "chio.2";

/// Minimum ABI providing Landlock TCP connect and bind mediation.
pub const MINIMUM_LANDLOCK_ABI: u32 = 4;

/// A caller-owned filesystem descriptor grant.
#[derive(Clone, Copy, Debug)]
pub struct CallerOwnedPathGrant<'fd> {
    fd: BorrowedFd<'fd>,
    access: PathAccess,
    is_directory: bool,
}

/// Filesystem access compiled from Chio's retained descriptor table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathAccess {
    Read,
    ReadDirectory,
    WriteExactFile,
    ExecuteRead,
}

/// Kernel-observed Landlock ruleset status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RulesetStatus {
    FullyEnforced,
    PartiallyEnforced,
    NotEnforced,
}

/// Enforcement facts returned only after both Landlock layers were applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnforcementStatus {
    pub abi: u32,
    pub filesystem: RulesetStatus,
    pub network: RulesetStatus,
}

/// A deny-all nono capability set extended with caller-owned path descriptors.
#[derive(Debug)]
pub struct CapabilitySet<'fd> {
    upstream: nono::CapabilitySet,
    grants: Vec<CallerOwnedPathGrant<'fd>>,
}

impl<'fd> CapabilitySet<'fd> {
    /// Construct a set whose network baseline is blocked, never `AllowAll`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            upstream: nono::CapabilitySet::new().block_network(),
            grants: Vec::new(),
        }
    }

    /// Add a rule from a descriptor that remains owned by the caller.
    pub fn add_path_fd(&mut self, fd: BorrowedFd<'fd>, access: PathAccess, is_directory: bool) {
        self.grants.push(CallerOwnedPathGrant {
            fd,
            access,
            is_directory,
        });
    }

    /// Apply independent filesystem and deny-all TCP network Landlock layers.
    pub fn enforce(self) -> Result<EnforcementStatus, Error> {
        if !matches!(self.upstream.network_mode(), NetworkMode::Blocked) {
            return Err(Error::NetworkBaseline);
        }

        let detected = nono::detect_abi().map_err(|error| Error::AbiProbe(error.to_string()))?;
        let kernel_abi = detected.abi;
        let abi = abi_number(kernel_abi);
        if abi < MINIMUM_LANDLOCK_ABI {
            return Err(Error::UnsupportedAbi {
                detected: abi,
                required: MINIMUM_LANDLOCK_ABI,
            });
        }

        let filesystem = enforce_filesystem(&self.grants, kernel_abi)?;
        require_full("filesystem", filesystem)?;
        let network = enforce_network_blocked(kernel_abi)?;
        require_full("network", network)?;

        Ok(EnforcementStatus {
            abi,
            filesystem,
            network,
        })
    }
}

impl<'fd> Default for CapabilitySet<'fd> {
    fn default() -> Self {
        Self::new()
    }
}

fn enforce_filesystem(
    grants: &[CallerOwnedPathGrant<'_>],
    kernel_abi: ABI,
) -> Result<RulesetStatus, Error> {
    let handled = AccessFs::from_all(kernel_abi);
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(|error| Error::Filesystem(error.to_string()))?
        .create()
        .map_err(|error| Error::Filesystem(error.to_string()))?;

    for grant in grants {
        let access_mode = match grant.access {
            PathAccess::Read | PathAccess::ReadDirectory | PathAccess::ExecuteRead => {
                AccessMode::Read
            }
            PathAccess::WriteExactFile => AccessMode::Write,
        };
        let access = filesystem_access(access_mode, grant.access, grant.is_directory)?;
        ruleset = ruleset
            .set_compatibility(CompatLevel::HardRequirement)
            .add_rule(PathBeneath::new(grant.fd, access))
            .map_err(|error| Error::Filesystem(error.to_string()))?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|error| Error::Filesystem(error.to_string()))?;
    if !status.no_new_privs {
        return Err(Error::NoNewPrivileges("filesystem"));
    }
    Ok(map_status(&status.ruleset))
}

fn enforce_network_blocked(kernel_abi: ABI) -> Result<RulesetStatus, Error> {
    let handled = AccessNet::from_all(kernel_abi);
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(|error| Error::Network(error.to_string()))?
        .create()
        .map_err(|error| Error::Network(error.to_string()))?
        .restrict_self()
        .map_err(|error| Error::Network(error.to_string()))?;
    if !status.no_new_privs {
        return Err(Error::NoNewPrivileges("network"));
    }
    Ok(map_status(&status.ruleset))
}

fn filesystem_access(
    upstream_mode: AccessMode,
    access: PathAccess,
    is_directory: bool,
) -> Result<landlock::BitFlags<AccessFs>, Error> {
    match (upstream_mode, access, is_directory) {
        (AccessMode::Read, PathAccess::Read, false) => Ok(AccessFs::ReadFile.into()),
        (AccessMode::Read, PathAccess::ReadDirectory, true) => Ok(AccessFs::ReadDir.into()),
        (AccessMode::Read, PathAccess::ExecuteRead, false) => {
            Ok(AccessFs::Execute | AccessFs::ReadFile)
        }
        (AccessMode::Write, PathAccess::WriteExactFile, false) => {
            Ok(AccessFs::WriteFile | AccessFs::Truncate)
        }
        _ => Err(Error::InvalidGrant),
    }
}

fn require_full(class: &'static str, status: RulesetStatus) -> Result<(), Error> {
    if status == RulesetStatus::FullyEnforced {
        Ok(())
    } else {
        Err(Error::Incomplete { class, status })
    }
}

fn map_status(status: &KernelRulesetStatus) -> RulesetStatus {
    match status {
        KernelRulesetStatus::FullyEnforced => RulesetStatus::FullyEnforced,
        KernelRulesetStatus::PartiallyEnforced => RulesetStatus::PartiallyEnforced,
        KernelRulesetStatus::NotEnforced => RulesetStatus::NotEnforced,
    }
}

fn abi_number(abi: ABI) -> u32 {
    match abi {
        ABI::V1 => 1,
        ABI::V2 => 2,
        ABI::V3 => 3,
        ABI::V4 => 4,
        ABI::V5 => 5,
        ABI::V6 => 6,
        ABI::Unsupported => 0,
        _ => 0,
    }
}

/// Fail-closed adapter errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("pinned nono capability set did not start with network blocked")]
    NetworkBaseline,
    #[error("unable to probe Landlock through pinned nono: {0}")]
    AbiProbe(String),
    #[error("Landlock ABI {detected} is below required ABI {required}")]
    UnsupportedAbi { detected: u32, required: u32 },
    #[error("filesystem Landlock setup failed: {0}")]
    Filesystem(String),
    #[error("network Landlock setup failed: {0}")]
    Network(String),
    #[error("{class} Landlock status was {status:?}")]
    Incomplete {
        class: &'static str,
        status: RulesetStatus,
    },
    #[error("{0} Landlock layer did not establish no_new_privs")]
    NoNewPrivileges(&'static str),
    #[error("caller-owned descriptor grant is incompatible with its object kind")]
    InvalidGrant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_read_grant_authorizes_listing_without_descendant_file_reads() {
        let access = match filesystem_access(AccessMode::Read, PathAccess::ReadDirectory, true) {
            Ok(access) => access,
            Err(error) => panic!("directory access should compile: {error}"),
        };
        assert!(access.contains(AccessFs::ReadDir));
        assert!(!access.contains(AccessFs::ReadFile));
        assert!(filesystem_access(AccessMode::Read, PathAccess::Read, true).is_err());
        assert!(filesystem_access(AccessMode::Read, PathAccess::ReadDirectory, false).is_err());
    }
}
