use chio_core_types::{canonical_json_bytes, recovery::*, PublicKey};
use chio_security_types::{knowledge::*, recovery::*};
#[path = "../../../../fixtures/recovery-knowledge-profile.rs"]
mod profile;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn typed(schema: &str, bytes: &[u8]) -> bool {
    macro_rules! read {
        ($kind:ty) => {
            decode_contract::<$kind>(bytes).is_ok()
        };
    }
    match schema {
        "artifact-reference.schema.json" => read!(ArtifactVersionRefV1),
        "artifact-influence.schema.json" => read!(ArtifactInfluenceV1),
        "artifact-producer.schema.json" => read!(ArtifactProducerV1),
        "artifact-version.schema.json" => read!(ArtifactVersionV1),
        "artifact-recipient.schema.json" => read!(ArtifactRecipientV1),
        "artifact-certificate.schema.json" => read!(ArtifactCertificateV1),
        "signed-artifact-certificate.schema.json" => {
            decode_contract::<SignedArtifactCertificateV1>(bytes)
                .is_ok_and(|proof| proof.verify_signature().is_ok_and(|valid| valid))
        }
        "artifact-archive-manifest.schema.json" => read!(ArtifactArchiveManifestV1),
        "signed-artifact-archive-manifest.schema.json" => {
            decode_contract::<SignedArtifactArchiveManifestV1>(bytes)
                .is_ok_and(|proof| proof.verify_signature().is_ok_and(|valid| valid))
        }
        "model-context.schema.json" => read!(ModelContextV1),
        "labeled-checkpoint.schema.json" => read!(LabeledCheckpointV1),
        "artifact-release-intent.schema.json" => read!(ArtifactReleaseIntentV1),
        "artifact-handle.schema.json" => read!(ArtifactHandleV1),
        _ => false,
    }
}
fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}
#[test]
fn shared_contracts_and_closed_ingress() -> TestResult {
    let vectors = profile::contracts()?;
    let schema_root = root().join("spec/schemas/chio-wire/v1");
    let mut registry = jsonschema::Registry::new();
    for group in std::fs::read_dir(&schema_root)? {
        let group = group?;
        if !group.path().is_dir() {
            continue;
        }
        for file in std::fs::read_dir(group.path())? {
            let path = file?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let schema: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            if let Some(id) = schema.get("$id").and_then(serde_json::Value::as_str) {
                registry = registry.add(id, schema.clone())?;
                let alias = format!(
                    "https://chio.computer/schemas/chio-wire/v1/{}",
                    path.strip_prefix(&schema_root)?.to_string_lossy()
                );
                if alias != id {
                    registry = registry.add(&alias, schema)?;
                }
            }
        }
    }
    let registry = registry.prepare()?;
    for (schema, body) in &vectors {
        let bytes = canonical_json_bytes(body)?;
        assert!(typed(schema, &bytes), "typed: {schema}");
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(schema_root.join("recovery").join(schema))?)?;
        let validator = jsonschema::options().with_registry(&registry).build(&raw)?;
        assert!(validator.is_valid(body), "schema: {schema}");
        let mut extra = body.clone();
        extra
            .as_object_mut()
            .ok_or("object")?
            .insert("unexpected".into(), true.into());
        assert!(!typed(schema, &canonical_json_bytes(&extra)?));
        assert!(!validator.is_valid(&extra));
    }
    Ok(())
}
#[test]
fn signatures_content_and_role_domains_cannot_substitute() -> TestResult {
    let vectors = profile::contracts()?;
    let signed = vectors
        .iter()
        .find(|(name, _)| *name == "signed-artifact-certificate.schema.json")
        .ok_or("certificate")?;
    let proof: SignedArtifactCertificateV1 = decode_contract(&canonical_json_bytes(&signed.1)?)?;
    assert!(proof.verify_signature()?);
    let mut changed = signed.1.clone();
    changed["body"]["output_label"] = serde_json::json!({"kind":"top"});
    assert!(
        decode_contract::<SignedArtifactCertificateV1>(&canonical_json_bytes(&changed)?)
            .map(|proof| proof.verify_signature().unwrap_or(false))
            .is_ok_and(|valid| !valid)
    );
    assert!(proof
        .signing_bytes()?
        .starts_with(b"chio:artifact-certificate:v1\0"));
    let mut wrong = b"chio:scoped-endorsement:v1\0".to_vec();
    wrong.extend(canonical_json_bytes(proof.body())?);
    assert!(!proof.authority_key().verify(&wrong, proof.signature()));
    let key: PublicKey = proof.authority_key().clone();
    assert_eq!(key.algorithm(), proof.algorithm());
    Ok(())
}
#[test]
fn bounds_missing_keys_duplicate_keys_and_provenance() -> TestResult {
    let first = profile::metadata()?;
    let mut second = first.clone();
    second.artifact = ArtifactId::new("different-origin")?;
    assert_eq!(first.content, second.content);
    assert_ne!(
        artifact_provenance_digest(&first)?,
        artifact_provenance_digest(&second)?
    );
    second.size_bytes = SafeInteger::new(MAX_ARTIFACT_BYTES as u64 + 1)?;
    assert!(second.validate().is_err());
    let body = canonical_json_bytes(&first)?;
    let mut value = serde_json::to_value(&first)?;
    value.as_object_mut().ok_or("body")?.remove("label");
    assert!(decode_contract::<ArtifactVersionV1>(&canonical_json_bytes(&value)?).is_err());
    let duplicated = format!(
        "{{\"label\":{},{}",
        serde_json::to_string(&first.label)?,
        std::str::from_utf8(&body)?
            .strip_prefix('{')
            .ok_or("object")?
    );
    assert!(decode_contract::<ArtifactVersionV1>(duplicated.as_bytes()).is_err());
    let mut checkpoint = profile::contracts()?
        .into_iter()
        .find(|(name, _)| *name == "labeled-checkpoint.schema.json")
        .ok_or("checkpoint")?
        .1;
    checkpoint["artifacts"] = serde_json::json!([]);
    assert!(decode_contract::<LabeledCheckpointV1>(&canonical_json_bytes(&checkpoint)?).is_err());
    Ok(())
}
fn shared_vectors() -> TestResult<serde_json::Value> {
    let cases = profile::contracts()?;
    let mut output_cases = Vec::new();
    for (schema, body) in cases {
        output_cases.push(serde_json::json!({"name":schema,"schema":schema,"body":body,"valid":true,"schema_valid":true}));
        let mut unknown = body.clone();
        unknown
            .as_object_mut()
            .ok_or("body")?
            .insert("unexpected".into(), true.into());
        output_cases.push(serde_json::json!({"name":format!("{schema}:unknown-field"),"schema":schema,"body":unknown,"valid":false,"schema_valid":false}));
        let mut absent = body.clone();
        let object = absent.as_object_mut().ok_or("body")?;
        let key = object.keys().next().cloned().ok_or("field")?;
        object.remove(&key);
        output_cases.push(serde_json::json!({"name":format!("{schema}:missing-field"),"schema":schema,"body":absent,"valid":false,"schema_valid":false}));
    }
    for (schema, mut body) in profile::contracts()?
        .into_iter()
        .filter(|(schema, _)| schema.starts_with("signed-"))
    {
        body["signature"] = serde_json::Value::String("00".repeat(64));
        output_cases.push(serde_json::json!({"name":format!("{schema}:invalid-signature"),"schema":schema,"body":body,"valid":false,"schema_valid":true}));
    }
    Ok(
        serde_json::json!({"schema":"chio.recovery-knowledge-contract-vectors.v1","cases":output_cases}),
    )
}

fn compare_shared_vectors(committed_json: &str) -> TestResult {
    let committed: serde_json::Value = serde_json::from_str(committed_json)?;
    let generated = shared_vectors()?;
    assert_eq!(generated, committed);
    assert_eq!(
        canonical_json_bytes(&generated)?,
        chio_core_types::canonical_json_bytes_from_str(committed_json)?,
        "generated knowledge corpus changed its canonical bytes"
    );
    Ok(())
}

#[test]
fn shared_vectors_match_the_committed_native_corpus() -> TestResult {
    compare_shared_vectors(include_str!(
        "../../../../spec/vectors/recovery/v1/knowledge-contracts.json"
    ))
}

#[test]
fn shared_corpus_rejects_ambiguous_raw_json() -> TestResult {
    let committed = include_str!("../../../../spec/vectors/recovery/v1/knowledge-contracts.json");
    let corpus: serde_json::Value = serde_json::from_str(committed)?;
    let duplicated_schema = format!(
        "{{\"schema\":{},{}",
        corpus["schema"],
        committed.strip_prefix('{').ok_or("corpus object")?
    );
    assert!(compare_shared_vectors(&duplicated_schema).is_err());
    Ok(())
}

#[test]
#[ignore = "explicit regeneration of the shared native knowledge contract corpus"]
fn write_shared_vectors() -> TestResult {
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_KNOWLEDGE_VECTOR_OUT").ok_or("explicit vector output required")?,
    );
    std::fs::write(path, serde_json::to_vec_pretty(&shared_vectors()?)?)?;
    Ok(())
}

#[test]
fn pure_certificate_and_archive_recompute_exact_provenance() -> TestResult {
    let values = profile::contracts()?;
    let metadata = profile::metadata()?;
    let certificate: SignedArtifactCertificateV1 = decode_contract(&canonical_json_bytes(
        &values
            .iter()
            .find(|(name, _)| *name == "signed-artifact-certificate.schema.json")
            .ok_or("certificate")?
            .1,
    )?)?;
    verify_artifact_certificate(&certificate, certificate.authority_key(), &metadata, 15_000)?;
    for now in [9_999, 20_000, 30_000] {
        assert!(verify_artifact_certificate(
            &certificate,
            certificate.authority_key(),
            &metadata,
            now
        )
        .is_err());
    }
    let mut changed = metadata.clone();
    changed.content = knowledge_content_digest(b"substituted");
    assert!(verify_artifact_certificate(
        &certificate,
        certificate.authority_key(),
        &changed,
        15_000
    )
    .is_err());
    let manifest: SignedArtifactArchiveManifestV1 = decode_contract(&canonical_json_bytes(
        &values
            .iter()
            .find(|(name, _)| *name == "signed-artifact-archive-manifest.schema.json")
            .ok_or("archive")?
            .1,
    )?)?;
    verify_artifact_archive(&manifest, manifest.authority_key(), &metadata.scope)?;
    let mut absent = manifest.body().clone();
    absent.root.version = ArtifactRevisionId::new("missing-root")?;
    let signed = SignedArtifactArchiveManifestV1::sign(
        absent,
        &chio_core_types::Keypair::from_seed(&[225; 32]),
    )?;
    assert!(verify_artifact_archive(&signed, manifest.authority_key(), &metadata.scope).is_err());
    Ok(())
}
