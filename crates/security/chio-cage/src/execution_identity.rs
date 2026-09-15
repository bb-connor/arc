use serde::{Deserialize, Serialize};

use crate::CageError;

/// Maximum supplementary groups admitted for one target execution identity.
pub const MAX_SUPPLEMENTARY_GIDS: usize = 64;

/// Exact non-root Unix credentials applied to the target before sandboxing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIdentity {
    uid: u32,
    gid: u32,
    supplementary_gids: Vec<u32>,
}

impl ExecutionIdentity {
    pub fn new(uid: u32, gid: u32, supplementary_gids: Vec<u32>) -> Result<Self, CageError> {
        let identity = Self {
            uid,
            gid,
            supplementary_gids,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), CageError> {
        if self.uid == 0 {
            return Err(CageError::InvalidExecutionIdentity("root uid"));
        }
        if self.uid == u32::MAX {
            return Err(CageError::InvalidExecutionIdentity("sentinel uid"));
        }
        if self.gid == 0 {
            return Err(CageError::InvalidExecutionIdentity("root primary gid"));
        }
        if self.gid == u32::MAX {
            return Err(CageError::InvalidExecutionIdentity("sentinel primary gid"));
        }
        if self.supplementary_gids.len() > MAX_SUPPLEMENTARY_GIDS {
            return Err(CageError::InvalidExecutionIdentity(
                "supplementary gid limit",
            ));
        }
        let mut previous = None;
        for gid in &self.supplementary_gids {
            if *gid == 0 {
                return Err(CageError::InvalidExecutionIdentity(
                    "root supplementary gid",
                ));
            }
            if *gid == u32::MAX {
                return Err(CageError::InvalidExecutionIdentity(
                    "sentinel supplementary gid",
                ));
            }
            if *gid == self.gid {
                return Err(CageError::InvalidExecutionIdentity(
                    "primary gid duplicated as supplementary gid",
                ));
            }
            if previous.is_some_and(|previous_gid| previous_gid >= *gid) {
                return Err(CageError::InvalidExecutionIdentity(
                    "supplementary gids must be sorted and unique",
                ));
            }
            previous = Some(*gid);
        }
        Ok(())
    }

    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    #[must_use]
    pub fn supplementary_gids(&self) -> &[u32] {
        &self.supplementary_gids
    }
}

/// Validate that prepared kernel evidence reports the exact sealed plan identity.
pub fn validate_cage_execution_identity_binding(
    plan: &crate::CageInitPlan,
    prepared: &crate::EnforcementPrepared,
) -> Result<(), CageError> {
    plan.execution_identity.validate()?;
    prepared.applied_execution_identity.validate()?;
    if plan.execution_identity != prepared.applied_execution_identity {
        return Err(CageError::ExecutionIdentityMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_root_zero_unsorted_duplicate_and_primary_groups() {
        assert!(ExecutionIdentity::new(0, 10001, Vec::new()).is_err());
        assert!(ExecutionIdentity::new(10001, 0, Vec::new()).is_err());
        assert!(ExecutionIdentity::new(u32::MAX, 10001, Vec::new()).is_err());
        assert!(ExecutionIdentity::new(10001, u32::MAX, Vec::new()).is_err());
        assert!(ExecutionIdentity::new(10001, 10001, vec![0]).is_err());
        assert!(ExecutionIdentity::new(10001, 10001, vec![u32::MAX]).is_err());
        assert!(ExecutionIdentity::new(10001, 10001, vec![10001]).is_err());
        assert!(ExecutionIdentity::new(10001, 10001, vec![10003, 10002]).is_err());
        assert!(ExecutionIdentity::new(10001, 10001, vec![10002, 10002]).is_err());
    }

    #[test]
    fn accepts_bounded_canonical_non_root_identity() {
        let identity = ExecutionIdentity::new(10001, 10001, vec![10002, 10003])
            .unwrap_or_else(|error| panic!("identity must be valid: {error}"));
        assert_eq!(identity.uid(), 10001);
        assert_eq!(identity.gid(), 10001);
        assert_eq!(identity.supplementary_gids(), [10002, 10003]);
    }
}
