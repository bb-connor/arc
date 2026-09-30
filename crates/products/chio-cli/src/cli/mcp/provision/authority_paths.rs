//! Keep provisioning authority outside the grants of both discovery and tools.
use super::{CliError, ProvisionProfile, ProvisionedCeilings};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

pub(super) fn protect(
    profile: &mut ProvisionProfile,
    output: &Path,
    runtime: &Path,
) -> Result<(), CliError> {
    profile
        .ceilings
        .forbidden_paths
        .extend([output.to_owned(), runtime.to_owned()]);
    profile
        .ceilings
        .forbidden_paths
        .extend(profile.receipt_rollback_anchor_root.iter().cloned());
    for grant in profile
        .ceilings
        .read_paths
        .iter()
        .chain(&profile.ceilings.write_paths)
    {
        for forbidden in &profile.ceilings.forbidden_paths {
            if grant.starts_with(forbidden) || forbidden.starts_with(grant) {
                return Err(CliError::with_source(
                    &chio_errors::_generated::error_codes::CAPABILITY_SCOPE_EXCEEDED,
                    chio_cage::CageError::ForbiddenPathOverlap {
                        allowed: grant.clone(),
                        forbidden: forbidden.clone(),
                    },
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn existing(profile: &ProvisionProfile) -> Result<BTreeSet<PathBuf>, CliError> {
    // Fresh provisioning has not published output/runtime directories yet.
    // Lexical overlap is rejected above even for those future authority paths.
    let mut existing = BTreeSet::new();
    for path in &profile.ceilings.forbidden_paths {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                existing.insert(path.clone());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(existing)
}

pub(super) fn runtime_ceilings(profile: &ProvisionProfile, runtime: &Path) -> ProvisionedCeilings {
    // Staging output may be absent in the deployment filesystem. Its exclusion
    // is enforced before discovery; runtime admission retains deployed authority.
    let mut forbidden_paths = BTreeSet::from([runtime.to_owned()]);
    forbidden_paths.extend(profile.receipt_rollback_anchor_root.iter().cloned());
    ProvisionedCeilings {
        forbidden_paths,
        ..profile.ceilings.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn authority_is_excluded_before_creation_and_on_restart() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("authority");
        let anchors = directory.path().join("anchors");
        std::fs::create_dir(&anchors)?;
        let mut profile = ProvisionProfile::native_mcp_demo();
        profile.receipt_rollback_anchor_root = Some(anchors.clone());
        protect(&mut profile, &output, &output)?;
        assert_eq!(existing(&profile)?, BTreeSet::from([anchors.clone()]));
        std::fs::create_dir(&output)?;
        assert_eq!(
            existing(&profile)?,
            BTreeSet::from([anchors, output.clone()])
        );
        for grant in [
            directory.path().to_owned(),
            output.clone(),
            output.join("receipt-seed"),
        ] {
            profile.ceilings.read_paths = BTreeSet::from([grant]);
            let error = protect(&mut profile, &output, &output)
                .err()
                .ok_or("authority grant accepted")?;
            assert!(error
                .source()
                .and_then(Error::source)
                .is_some_and(|cause| cause.is::<chio_cage::CageError>()));
        }
        Ok(())
    }

    #[test]
    fn deployed_policy_does_not_require_the_staging_filesystem() -> Result<(), Box<dyn Error>> {
        let staging = tempfile::tempdir()?;
        let runtime = tempfile::tempdir()?;
        let anchor = tempfile::tempdir()?;
        let mut profile = ProvisionProfile::native_mcp_demo();
        profile.receipt_rollback_anchor_root = Some(anchor.path().to_owned());
        protect(&mut profile, staging.path(), runtime.path())?;
        let deployed = runtime_ceilings(&profile, runtime.path());
        drop(staging);
        profile.ceilings = deployed;
        assert_eq!(
            existing(&profile)?,
            BTreeSet::from([runtime.path().to_owned(), anchor.path().to_owned(),])
        );
        Ok(())
    }
}
