//! Regeneration of the signed three-vendor, attestation-loopback and
//! pheromone relay fixtures through their owning generators.
//!
//! Every output is produced into a scratch directory first. Regeneration copies
//! each changed output over its committed path; `check` compares and writes
//! nothing.

use super::*;

const THREE_VENDOR_FIXTURE_DIR: &str = "examples/chio-3vendor/fixtures";
const ATTEST_LOOPBACK_FIXTURE_DIR: &str = "crates/trust/chio-attest-loopback/fixtures";
const RELAY_FIXTURE_DIR: &str = "examples/chio-3vendor/fixtures/pheromone/relay";
const ALERT_ASSURANCE_FIXTURE_DIR: &str =
    "examples/chio-3vendor/fixtures/pheromone/relay/alert-assurance";

const PROOF_PACKAGE_OUTPUTS: [&str; 5] = [
    "buyer-auditor-proof-package.json",
    "selective-disclosure-proof.json",
    "verifier-trust-bundle.json",
    "verification-context.json",
    "verifier-report.json",
];

const ATTEST_LOOPBACK_OUTPUTS: [&str; 4] = [
    "buyer-auditor-proof-package.json",
    "verifier-trust-bundle.json",
    "verification-context.json",
    "verifier-report.json",
];

const PHEROMONE_OUTPUTS: [&str; 8] = [
    "deposit.json",
    "gossip-batch.json",
    "transit-policy.json",
    "concentration.json",
    "negative-cases.json",
    "receive-report.json",
    "query-report.json",
    "peer-weights.json",
];

const RELAY_DIRECTORY_OUTPUTS: [&str; 5] = [
    "peer-directory.json",
    "peer-directory-bundle.json",
    "peer-directory-candidate.json",
    "peer-directory-state.json",
    "peer-directory-rotation-report.json",
];

/// Regenerate (or, with `check`, compare) the three-vendor proof package
/// set, its attestation-loopback copy, the pheromone transit fixtures, the
/// relay peer-directory lifecycle and the signed alert-assurance export bundle.
pub(crate) fn regenerate_three_vendor_fixtures(check: bool) -> Result<(), XtaskError> {
    let root = crate::workspace_root()?;
    let scratch = ScratchDir::new("signed-three-vendor")?;
    let three_vendor = root.join(THREE_VENDOR_FIXTURE_DIR);
    let assurance = root.join(ALERT_ASSURANCE_FIXTURE_DIR);

    let proof = scratch.join("proof");
    let committed_disclosure = three_vendor.join("selective-disclosure-proof.json");
    generate_three_vendor(
        &root,
        &[
            "--out-dir",
            &display(&proof),
            "--keep-disclosure",
            &display(&committed_disclosure),
        ],
    )?;
    let pheromone = scratch.join("pheromone");
    generate_three_vendor(
        &root,
        &[
            "--pheromone-package",
            &display(&proof.join("buyer-auditor-proof-package.json")),
            &display(&pheromone),
        ],
    )?;
    let relay = scratch.join("relay");
    generate_three_vendor(&root, &["--relay-directory-out-dir", &display(&relay)])?;
    let export_bundle = scratch.join("export-bundle");
    let export_report = scratch.join("relay-alert-assurance-export-report.json");
    assurance_run_export(&root, &assurance, &export_bundle, &export_report)?;

    let mut outputs = Vec::new();
    for name in PROOF_PACKAGE_OUTPUTS {
        outputs.push((proof.join(name), three_vendor.join(name)));
    }
    for name in ATTEST_LOOPBACK_OUTPUTS {
        outputs.push((
            proof.join(name),
            root.join(ATTEST_LOOPBACK_FIXTURE_DIR).join(name),
        ));
    }
    for name in PHEROMONE_OUTPUTS {
        outputs.push((
            pheromone.join(name),
            three_vendor.join("pheromone").join(name),
        ));
    }
    for name in RELAY_DIRECTORY_OUTPUTS {
        outputs.push((relay.join(name), root.join(RELAY_FIXTURE_DIR).join(name)));
    }
    let committed_bundle = assurance.join("export-bundle");
    let generated_files = relative_files(&export_bundle)?;
    let committed_files = relative_files(&committed_bundle)?;
    if generated_files != committed_files {
        return Err(XtaskError::Drift(format!(
            "{} holds {committed_files:?}; the export writes {generated_files:?}",
            display(&committed_bundle)
        )));
    }
    for relative in generated_files {
        outputs.push((
            export_bundle.join(&relative),
            committed_bundle.join(&relative),
        ));
    }
    outputs.push((
        export_report,
        assurance.join("relay-alert-assurance-export-report.json"),
    ));
    sync_outputs(&outputs, check)
}

fn generate_three_vendor(root: &Path, args: &[&str]) -> Result<(), XtaskError> {
    let mut argv = vec![
        "-p",
        "chio-three-vendor-example",
        "--bin",
        "generate-chio-three-vendor-fixtures",
        "--",
    ];
    argv.extend_from_slice(args);
    require_cli(root, &argv)
}

/// Every regular file under `dir`, as sorted paths relative to it.
fn relative_files(dir: &Path) -> Result<Vec<PathBuf>, XtaskError> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), XtaskError> {
        let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display(dir), err))?;
        for entry in entries {
            let entry = entry.map_err(|err| XtaskError::Io(display(dir), err))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| XtaskError::Io(display(&path), err))?;
            if file_type.is_dir() {
                walk(base, &path, out)?;
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(base)
                    .map_err(|err| XtaskError::Validation(format!("{}: {err}", display(&path))))?;
                out.push(relative.to_path_buf());
            } else {
                return Err(XtaskError::Validation(format!(
                    "{} is neither a file nor a directory",
                    display(&path)
                )));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort();
    Ok(out)
}

/// Copy each generated file over its committed path when the bytes differ;
/// with `check`, report every path that would change and write nothing.
fn sync_outputs(outputs: &[(PathBuf, PathBuf)], check: bool) -> Result<(), XtaskError> {
    let mut stale = Vec::new();
    for (generated, committed) in outputs {
        let bytes = fs::read(generated).map_err(|err| XtaskError::Io(display(generated), err))?;
        let current = match fs::read(committed) {
            Ok(current) => Some(current),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(XtaskError::Io(display(committed), err)),
        };
        if current.as_deref() == Some(bytes.as_slice()) {
            continue;
        }
        if check {
            stale.push(display(committed));
        } else {
            fs::write(committed, &bytes).map_err(|err| XtaskError::Io(display(committed), err))?;
        }
    }
    if stale.is_empty() {
        Ok(())
    } else {
        Err(XtaskError::Drift(format!(
            "stale three-vendor fixtures: {}",
            stale.join(", ")
        )))
    }
}
