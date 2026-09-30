use crate::input::collection::{directory, member, Budget};
use crate::CliError;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn sorted_files(dir: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut budget = Budget::default();
    Ok(directory(dir, &mut budget)?
        .into_iter()
        .filter(|path| path.is_file())
        .collect())
}

pub(super) fn file_name_ends_with(path: &Path, suffix: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(suffix))
}

pub(super) const ARCHIVE_PACKAGE_MANIFEST_PATH: &str = "archive-package-manifest.json";
const ARCHIVE_PACKAGE_MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const ARCHIVE_PACKAGE_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const ARCHIVE_PACKAGE_MAX_MEMBER_BYTES: u64 = 32 * 1024 * 1024;
const ARCHIVE_PACKAGE_MAX_MEMBER_COUNT: usize = 512;
const ARCHIVE_PACKAGE_MAX_TAR_MEMBER_COUNT: usize = ARCHIVE_PACKAGE_MAX_MEMBER_COUNT + 1;
const ARCHIVE_PACKAGE_MAX_DECOMPRESSION_RATIO: u64 = 200;

pub(super) fn archive_package_limits() -> crate::archive::SafeArchiveLimits {
    crate::archive::SafeArchiveLimits {
        max_compressed_bytes: ARCHIVE_PACKAGE_MAX_COMPRESSED_BYTES,
        max_member_bytes: ARCHIVE_PACKAGE_MAX_MEMBER_BYTES,
        max_total_bytes: ARCHIVE_PACKAGE_MAX_TOTAL_BYTES,
        max_member_count: ARCHIVE_PACKAGE_MAX_TAR_MEMBER_COUNT,
        max_decompression_ratio: ARCHIVE_PACKAGE_MAX_DECOMPRESSION_RATIO,
    }
}

pub(super) fn trusted_archive_packagers_from_signing_key(
    packager_id: &str,
    packager_key_id: &str,
    public_key: chio_core::crypto::PublicKey,
    local_kernel_id: String,
    now_unix_ms: u64,
) -> chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackagersDocument {
    chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackagersDocument {
        schema:
            chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA
                .to_string(),
        local_kernel_id,
        min_created_at_unix_ms: now_unix_ms,
        packagers: vec![
            chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackager {
                packager_id: packager_id.to_string(),
                key_id: packager_key_id.to_string(),
                public_key,
                valid_from_unix_ms: now_unix_ms.saturating_sub(1),
                valid_until_unix_ms: now_unix_ms.saturating_add(24 * 60 * 60 * 1000),
                status: "active".to_string(),
            },
        ],
    }
}

pub(super) fn write_relay_alert_assurance_bundle(
    out_dir: &Path,
    bundle: &chio_pheromone_relay::RelayAlertAssuranceExportBundle,
) -> Result<(), CliError> {
    let manifest = chio_core::canonical_json_bytes(&bundle.manifest)?;
    let report = chio_core::canonical_json_bytes(&bundle.report)?;
    let entries = std::iter::once(("manifest.json", manifest.as_slice()))
        .chain(std::iter::once((
            "relay-alert-assurance-export-report.json",
            report.as_slice(),
        )))
        .chain(
            bundle
                .files
                .iter()
                .map(|file| (file.path.as_str(), file.bytes.as_slice())),
        )
        .collect::<Vec<_>>();
    let snapshot = crate::input::snapshot::Snapshot::from_entries(entries.iter().copied())?;
    ensure_clean_output_dir(out_dir)?;
    let files = entries
        .iter()
        .map(|(path, _)| {
            Ok(crate::archive::SafeArchiveEntry {
                path: (*path).to_owned(),
                bytes: crate::input::read(snapshot.path().join(path))?,
                mode: 0o600,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    crate::archive::write_entries_to_existing_dir(out_dir, "Chio assurance export", &files)
}

pub(super) fn read_relay_alert_assurance_bundle(
    bundle_dir: &Path,
) -> Result<chio_pheromone_relay::RelayAlertAssuranceExportBundle, CliError> {
    read_bundle_budget(bundle_dir, &mut Budget::default())
}

fn read_bundle_budget(
    bundle_dir: &Path,
    budget: &mut Budget,
) -> Result<chio_pheromone_relay::RelayAlertAssuranceExportBundle, CliError> {
    budget.enter(0)?;
    let manifest: chio_pheromone_relay::RelayAlertAssuranceExportManifest =
        crate::input::json(&budget.read(&member(bundle_dir, "manifest.json")?)?)?;
    let report: chio_pheromone_relay::RelayAlertAssuranceExportReport =
        crate::input::json(&budget.read(&member(
            bundle_dir,
            "relay-alert-assurance-export-report.json",
        )?)?)?;
    let mut files = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for artifact in &manifest.body.artifacts {
        if !names.insert(&artifact.path)
            || matches!(
                artifact.path.as_str(),
                "manifest.json" | "relay-alert-assurance-export-report.json"
            )
        {
            return Err(CliError::cli_other_error(
                "duplicate or reserved assurance bundle member",
            ));
        }
        budget.enter(artifact.path.split('/').count())?;
        let path = member(bundle_dir, &artifact.path)?;
        let bytes = budget.read(&path)?;
        files.push(chio_pheromone_relay::RelayAlertAssuranceExportFile {
            path: artifact.path.clone(),
            bytes,
        });
    }
    Ok(chio_pheromone_relay::RelayAlertAssuranceExportBundle {
        manifest,
        report,
        files,
    })
}

pub(super) fn read_relay_alert_assurance_bundle_root(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceExportBundle>, CliError> {
    let mut budget = Budget::default();
    let dirs = bundle_directories(bundle_root, &mut budget)?;
    dirs.into_iter()
        .map(|dir| read_bundle_budget(&dir, &mut budget))
        .collect()
}

pub(super) fn read_relay_alert_assurance_archive_candidates(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate>, CliError> {
    let mut budget = Budget::default();
    let dirs = bundle_directories(bundle_root, &mut budget)?;
    let mut candidates = Vec::new();
    for dir in dirs {
        let bundle = read_bundle_budget(&dir, &mut budget);
        candidates.push(candidate_from_result(&dir, bundle));
    }
    Ok(candidates)
}

pub(super) fn relay_alert_assurance_bundle_label(bundle_dir: &Path) -> String {
    bundle_dir
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("export-bundle")
        .to_string()
}

fn ensure_clean_output_dir(out_dir: &Path) -> Result<(), CliError> {
    if out_dir.exists() {
        let mut entries = fs::read_dir(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect Chio output directory {}: {error}",
                out_dir.display()
            ))
        })?;
        if entries
            .next()
            .transpose()
            .map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to inspect Chio output directory {}: {error}",
                    out_dir.display()
                ))
            })?
            .is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "Chio output directory {} must be empty",
                out_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create Chio output directory {}: {error}",
                out_dir.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_clean_output_dir;

    #[test]
    fn output_directory_errors_use_chio_boundary_label() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        std::fs::write(tempdir.path().join("existing.json"), "{}").expect("write fixture");

        let error = ensure_clean_output_dir(tempdir.path())
            .expect_err("non-empty output dir should fail")
            .to_string();

        assert!(error.contains("Chio output directory"));
    }
}

fn bundle_directories(root: &Path, budget: &mut Budget) -> Result<Vec<PathBuf>, CliError> {
    if fs::symlink_metadata(root.join("manifest.json")).is_ok() {
        return Ok(vec![root.to_owned()]);
    }
    let mut dirs = Vec::new();
    for path in directory(root, budget)? {
        if path.is_dir() && fs::symlink_metadata(path.join("manifest.json")).is_ok() {
            dirs.push(path);
        }
    }
    if dirs.is_empty() {
        return Err(CliError::cli_other_error(
            "Chio assurance bundle root contains no bundles",
        ));
    }
    Ok(dirs)
}

fn candidate_from_result(
    dir: &Path,
    result: Result<chio_pheromone_relay::RelayAlertAssuranceExportBundle, CliError>,
) -> chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
    let bundle_path = relay_alert_assurance_bundle_label(dir);
    match result {
        Ok(bundle) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: Some(bundle),
            error_code: None,
            error_detail: None,
        },
        Err(error) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: None,
            error_code: Some("bundle_read_failed".to_string()),
            error_detail: Some(error.to_string()),
        },
    }
}
