use std::fs;
use std::path::Path;

use crate::admission_loop::RuntimeLoopbackAdmissionOutput;
use crate::evidence_io::read_utf8_json_file;
use crate::proof_assembly::{assemble_runtime_loopback_outputs, StaticProofBaseline};
use crate::scenario::RuntimeLoopbackStep;
use crate::RuntimeLoopbackError;

pub fn generate_runtime_loopback_fixture(
    scenario: &Path,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
    static_package_json: &str,
    static_report_json: &str,
) -> Result<(), RuntimeLoopbackError> {
    let package =
        chio_attest_buyer_core::proof_package::proof_package_from_json(static_package_json)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!("Chio static proof package: {error}"))
            })?;
    let report = chio_attest_buyer_core::report::verifier_report_from_json(static_report_json)
        .map_err(|error| {
            RuntimeLoopbackError::message(format!("Chio static verifier report: {error}"))
        })?;
    crate::run_runtime_loopback_scenario_with_static_baseline(
        scenario,
        store_dir,
        now_unix_ms,
        out_dir,
        StaticProofBaseline { package, report },
        true,
    )
}

pub(crate) fn assemble_qualified_fixture(
    run_id: &str,
    steps: &[RuntimeLoopbackStep],
    out_dir: &Path,
    now_unix_ms: u64,
    admission: RuntimeLoopbackAdmissionOutput,
    previous_baseline: StaticProofBaseline,
) -> Result<(), RuntimeLoopbackError> {
    if !admission.accepted {
        return Err(RuntimeLoopbackError::message(
            "fixture admission was not accepted",
        ));
    }
    let bootstrap = assemble_runtime_loopback_outputs(
        run_id,
        steps,
        out_dir,
        now_unix_ms,
        admission.clone(),
        previous_baseline,
    );
    let baseline = read_baseline(out_dir)?;
    let parity: chio_runtime_core::RuntimeProofParityReport =
        serde_json::from_str(&read_utf8_json_file(
            &out_dir.join("runtime-proof-parity-report.json"),
            "fixture parity",
        )?)
        .map_err(|error| RuntimeLoopbackError::message(format!("fixture parity parse: {error}")))?;
    if !baseline.report.accepted || !parity.mismatches.is_empty() {
        return Err(RuntimeLoopbackError::message(
            "fixture baseline verification or semantics refused",
        ));
    }
    if let Err(error) = bootstrap {
        if parity.failure_code.as_deref() != Some("runtime_proof_semantic_parity_mismatch")
            || !error.to_string().starts_with(
                "Chio runtime loopback rejected request: runtime_proof_semantic_parity_mismatch;",
            )
        {
            return Err(error);
        }
    }
    let first = out_dir.join("same-source-first");
    fs::create_dir(&first).map_err(io_error)?;
    for name in &admission.evidence_paths {
        fs::copy(out_dir.join(name), first.join(name)).map_err(io_error)?;
    }
    assemble_runtime_loopback_outputs(
        run_id,
        steps,
        &first,
        now_unix_ms,
        admission.clone(),
        baseline.clone(),
    )?;
    assemble_runtime_loopback_outputs(run_id, steps, out_dir, now_unix_ms, admission, baseline)?;
    compare_generated_files(&first, out_dir)
}

fn read_baseline(out_dir: &Path) -> Result<StaticProofBaseline, RuntimeLoopbackError> {
    let package = chio_attest_buyer_core::proof_package::proof_package_from_json(
        &read_utf8_json_file(&out_dir.join("proof-package.json"), "fixture package")?,
    )
    .map_err(|error| RuntimeLoopbackError::message(format!("fixture package parse: {error}")))?;
    let report = chio_attest_buyer_core::report::verifier_report_from_json(&read_utf8_json_file(
        &out_dir.join("verifier-report.json"),
        "fixture verifier report",
    )?)
    .map_err(|error| {
        RuntimeLoopbackError::message(format!("fixture verifier report parse: {error}"))
    })?;
    Ok(StaticProofBaseline { package, report })
}

fn compare_generated_files(first: &Path, second: &Path) -> Result<(), RuntimeLoopbackError> {
    for entry in fs::read_dir(first).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if !entry.file_type().map_err(io_error)?.is_file() {
            return Err(RuntimeLoopbackError::message(
                "fixture output is not a regular file",
            ));
        }
        let name = entry.file_name();
        if fs::read(entry.path()).map_err(io_error)?
            != fs::read(second.join(&name)).map_err(io_error)?
        {
            return Err(RuntimeLoopbackError::message(format!(
                "same-source fixture output differs: {}",
                name.to_string_lossy(),
            )));
        }
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> RuntimeLoopbackError {
    RuntimeLoopbackError::message(format!("same-source fixture I/O: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_source_fixture_regeneration_is_byte_equal() -> Result<(), RuntimeLoopbackError> {
        let root = crate::tests::temp_root("same-qualified-source")?;
        fs::create_dir_all(&root).map_err(io_error)?;
        let scenario = root.join("scenario.json");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../examples/chio-3vendor/fixtures/runtime-spine/scenario.json");
        crate::tests::write_executable_scenario(&fixture, &scenario)?;
        let inputs = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation");
        let out = root.join("out");
        generate_runtime_loopback_fixture(
            &scenario,
            &root.join("store"),
            1_800_000_001_000,
            &out,
            &read_utf8_json_file(&inputs.join("proof-package.json"), "package")?,
            &read_utf8_json_file(&inputs.join("verifier-report.json"), "report")?,
        )?;
        let parity: chio_runtime_core::RuntimeProofParityReport = serde_json::from_str(
            &read_utf8_json_file(&out.join("runtime-proof-parity-report.json"), "parity")?,
        )
        .expect("parity");
        assert!(parity.accepted);
        assert!(parity.mismatches.is_empty());
        assert_eq!(
            parity.static_proof_package_sha256,
            parity.runtime_proof_package_sha256
        );
        assert_eq!(
            parity.static_verifier_report_sha256,
            parity.runtime_verifier_report_sha256
        );
        assert!(read_baseline(&out)?.report.accepted);
        let first = out.join("same-source-first");
        compare_generated_files(&first, &out)?;
        fs::write(out.join("proof-package.json"), b"tampered").map_err(io_error)?;
        assert_eq!(
            compare_generated_files(&first, &out)
                .expect_err("changed package")
                .to_string(),
            "same-source fixture output differs: proof-package.json"
        );
        fs::remove_dir_all(root).map_err(io_error)?;
        Ok(())
    }
}
