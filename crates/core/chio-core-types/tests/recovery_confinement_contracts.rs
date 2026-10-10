use chio_core_types::{canonical_json_bytes, recovery::*};
use chio_security_types::{confinement::*, recovery::*};
#[path = "../../../../fixtures/recovery-confined-profile.rs"]
mod profile;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn typed(schema: &str, bytes: &[u8]) -> bool {
    macro_rules! read {
        ($t:ty) => {
            decode_contract::<$t>(bytes).is_ok()
        };
    }
    match schema {
        "confined-limits.schema.json" => {
            decode_contract::<ConfinedLimitsV1>(bytes).is_ok_and(|b| b.validate().is_ok())
        }
        "confined-execution-profile.schema.json" => read!(ConfinedExecutionProfileV1),
        "return-contract.schema.json" => {
            decode_contract::<ReturnContractV1>(bytes).is_ok_and(|b| b.validate().is_ok())
        }
        "isolation-boundary.schema.json" => {
            decode_contract::<IsolationBoundaryV1>(bytes).is_ok_and(|b| b.validate().is_ok())
        }
        "confined-return-evidence.schema.json" => {
            decode_contract::<ConfinedReturnEvidenceV1>(bytes).is_ok_and(|b| b.validate().is_ok())
        }
        "return-admission.schema.json" => read!(ReturnAdmissionV1),
        "signed-confined-disclosure.schema.json" => {
            decode_contract::<SignedConfinedDisclosureV1>(bytes)
                .is_ok_and(|b| b.verify_signature().is_ok_and(|v| v))
        }
        "signed-confined-endorsement.schema.json" => {
            decode_contract::<SignedConfinedEndorsementV1>(bytes)
                .is_ok_and(|b| b.verify_signature().is_ok_and(|v| v))
        }
        _ => false,
    }
}
fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}
fn vectors() -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for (schema, body) in profile::contracts()? {
        out.push(serde_json::json!({"name":schema,"schema":schema,"body":body,"valid":true,"schema_valid":true}));
        let mut unknown = body.clone();
        unknown
            .as_object_mut()
            .ok_or("body")?
            .insert("unregistered_channel".into(), true.into());
        out.push(serde_json::json!({"name":format!("{schema}:unknown"),"schema":schema,"body":unknown,"valid":false,"schema_valid":false}));
        let mut missing = body.clone();
        let key = missing
            .as_object()
            .ok_or("body")?
            .keys()
            .next()
            .ok_or("key")?
            .clone();
        missing.as_object_mut().ok_or("body")?.remove(&key);
        out.push(serde_json::json!({"name":format!("{schema}:missing"),"schema":schema,"body":missing,"valid":false,"schema_valid":false}));
        if schema.starts_with("signed-") {
            let mut changed = body;
            changed["body"]["launch"] = serde_json::to_value([0u8; 32])?;
            out.push(serde_json::json!({"name":format!("{schema}:substituted-launch"),"schema":schema,"body":changed,"valid":false,"schema_valid":true}));
        }
    }
    Ok(out)
}
#[test]
fn closed_contracts_and_shared_vectors() -> TestResult {
    let schema_root = root().join("spec/schemas/chio-wire/v1");
    let mut registry = jsonschema::Registry::new();
    for group in std::fs::read_dir(&schema_root)? {
        let group = group?;
        if !group.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(group.path())? {
            let path = entry?.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let schema: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            if let Some(id) = schema.get("$id").and_then(|v| v.as_str()) {
                registry = registry.add(id, schema.clone())?;
                let alias = format!(
                    "https://chio.computer/schemas/chio-wire/v1/{}",
                    path.strip_prefix(&schema_root)?.to_string_lossy()
                );
                if id != alias {
                    registry = registry.add(&alias, schema)?;
                }
            }
        }
    }
    let registry = registry.prepare()?;
    for vector in vectors()? {
        let schema = vector["schema"].as_str().ok_or("schema")?;
        assert_eq!(
            typed(schema, &canonical_json_bytes(&vector["body"])?),
            vector["valid"].as_bool().ok_or("valid")?,
            "typed {schema}"
        );
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(schema_root.join("recovery").join(schema))?)?;
        let validator = jsonschema::options().with_registry(&registry).build(&raw)?;
        assert_eq!(
            validator.is_valid(&vector["body"]),
            vector["schema_valid"].as_bool().ok_or("valid")?,
            "schema {schema}"
        );
    }
    Ok(())
}
#[test]
fn disclosure_cannot_substitute_for_integrity_and_exact_binding_mutations_fail() -> TestResult {
    let contract = profile::contracts()?
        .into_iter()
        .find(|(n, _)| *n == "signed-confined-disclosure.schema.json")
        .ok_or("proof")?
        .1;
    let original: SignedConfinedDisclosureV1 = serde_json::from_value(contract.clone())?;
    assert!(original.verify_signature()?);
    let wrong: SignedConfinedEndorsementV1 = serde_json::from_value(contract.clone())?;
    assert!(!wrong.verify_signature()?);
    for field in [
        "boundary",
        "launch",
        "content",
        "contract",
        "implementation",
        "policy",
    ] {
        let mut changed = contract.clone();
        changed["body"][field] = serde_json::to_value([171u8; 32])?;
        assert!(
            !serde_json::from_value::<SignedConfinedDisclosureV1>(changed)?.verify_signature()?,
            "{field}"
        );
    }
    for field in ["principal", "lineage", "isolation_epoch", "runtime"] {
        let mut changed = contract.clone();
        changed["body"]["parent"][field] = "substitute".into();
        assert!(
            !serde_json::from_value::<SignedConfinedDisclosureV1>(changed)?.verify_signature()?,
            "parent {field}"
        );
    }
    Ok(())
}
#[test]
fn projection_and_packet_bounds_do_not_release_schema_only_predicates() -> TestResult {
    let source = br#"{"eligible":true,"private":"canary"}"#;
    assert_eq!(project_confined_boolean(source, "eligible")?, b"true");
    for source in [
        br#"{"eligible":"true"}"#.as_slice(),
        b"{",
        br#"{"private":true}"#,
    ] {
        assert!(project_confined_boolean(source, "eligible").is_err());
    }
    let packet = encode_confined_input("eligible", source, &[b"secret-seed".to_vec()])?;
    let DecodedConfinedInput {
        field,
        observation,
        seeds,
    } = decode_confined_input(&packet)?;
    assert_eq!(field, "eligible");
    assert_eq!(observation, source);
    assert_eq!(seeds, vec![b"secret-seed".as_slice()]);
    for length in 0..packet.len() {
        assert!(decode_confined_input(&packet[..length]).is_err());
    }
    let mut extra = packet.clone();
    extra.push(0);
    assert!(decode_confined_input(&extra).is_err());
    assert!(encode_confined_input("eligible", &vec![0; 65536], &[]).is_err());
    let mut limits = profile::limits()?;
    limits.tool_calls = SafeInteger::new(1)?;
    assert!(limits.validate().is_err());
    Ok(())
}
#[test]
fn write_shared_vectors() -> TestResult {
    let Some(output) = std::env::var_os("CHIO_CONFINED_VECTOR_OUT") else {
        return Ok(());
    };
    let value = serde_json::json!({"schema":"chio.recovery-confinement-contract-vectors.v1","cases":vectors()?});
    std::fs::write(output, serde_json::to_string_pretty(&value)? + "\n")?;
    Ok(())
}
