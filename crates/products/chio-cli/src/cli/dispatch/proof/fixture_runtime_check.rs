use super::*;

const SOURCE_BOUND_RUNTIME_FIXTURES: &[(&str, &str, &str)] = &[(
    "recursive-runtime-swarm",
    "proof-room",
    "fixtures/proof-room/public-stages/recursive-runtime-swarm",
)];

pub(super) fn is_source_bound_runtime_fixture(
    descriptor: &ProofFixtureDescriptor,
) -> Result<bool, CliError> {
    let Some((_, kind, path)) = SOURCE_BOUND_RUNTIME_FIXTURES
        .iter()
        .find(|(id, _, _)| *id == descriptor.id)
    else {
        return Ok(false);
    };
    if descriptor.kind != *kind || descriptor.path != *path {
        return Err(CliError::cli_other_error(format!(
            "runtime fixture descriptor mismatch: {}",
            descriptor.id
        )));
    }
    Ok(true)
}

pub(super) fn verify_committed_runtime_fixture(target: &Path) -> Result<(), CliError> {
    let snapshot = crate::input::snapshot::Snapshot::capture(target)?;
    let bundle = snapshot.path().join("proof-room-bundle");
    let package = read_runtime_document(
        &bundle,
        "proof-package.json",
        "chio.attest.proof-package.v1",
    )?;
    let stored_report = read_runtime_document(
        &bundle,
        "verifier-report.json",
        "chio.attest.verifier-report.v1",
    )?;
    let trust = read_runtime_document(
        &bundle,
        "verifier-trust-bundle.json",
        "chio.federation.verifier-trust-bundle.v1",
    )?;
    let context = read_runtime_document(
        &bundle,
        "verification-context.json",
        "chio.federation.verification-context.v1",
    )?;
    let actual = chio_attest_buyer::verify_proof_package_json(&package, &trust, &context).map_err(
        |error| CliError::cli_other_error(format!("runtime fixture proof decoding: {error}")),
    )?;
    if !actual.accepted {
        return Err(CliError::cli_other_error(format!(
            "runtime fixture proof rejected: {}",
            actual
                .failure_code
                .as_deref()
                .unwrap_or("missing_failure_code")
        )));
    }
    let stored: chio_attest_buyer_core::report::VerifierReport =
        crate::input::text(&stored_report)?;
    let verified: chio_attest_buyer_core::report::VerifierReport =
        crate::input::text(&actual.json)?;
    if stored != verified {
        return Err(CliError::cli_other_error(
            "runtime fixture verifier report mismatch",
        ));
    }
    chio_proof_room::verify_proof_room_bundle(&bundle.join("manifest.json")).map_err(|error| {
        CliError::cli_other_error(format!("runtime fixture bundle integrity: {error}"))
    })?;
    if crate::input::read(snapshot.path().join("verifier-report.json"))?
        != crate::input::read(bundle.join("verifier/report.json"))?
    {
        return Err(CliError::cli_other_error(
            "runtime fixture public report mismatch",
        ));
    }
    Ok(())
}

fn read_runtime_document(bundle: &Path, name: &str, schema: &str) -> Result<String, CliError> {
    let bytes = crate::input::read(bundle.join(name)).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CliError::cli_other_error(format!("runtime fixture missing required file: {name}"))
        } else {
            error.into()
        }
    })?;
    let value: serde_json::Value = crate::input::json(&bytes)?;
    if value.get("schema").and_then(serde_json::Value::as_str) != Some(schema) {
        return Err(CliError::cli_other_error(format!(
            "runtime fixture schema mismatch: {name}"
        )));
    }
    String::from_utf8(bytes).map_err(|source| {
        CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn runtime_fixture_verifier_scope_is_closed() {
        assert_eq!(
            SOURCE_BOUND_RUNTIME_FIXTURES,
            &[(
                "recursive-runtime-swarm",
                "proof-room",
                "fixtures/proof-room/public-stages/recursive-runtime-swarm",
            )]
        );
        let fixtures = proof_fixtures().test_expect("fixture catalog");
        let mut selected = Vec::new();
        for descriptor in fixtures {
            if is_source_bound_runtime_fixture(&descriptor).test_expect("descriptor scope") {
                selected.push(descriptor.id);
            }
        }
        assert_eq!(selected, vec!["recursive-runtime-swarm"]);
    }
}
