use chio_core_types::{
    canonical::CanonicalBytes,
    recovery::{
        decode_contract, decode_contract_with_limits, RecoveryDecodeLimits, RECOVERY_DIGEST_DOMAINS,
    },
};
use chio_security_types::recovery::{
    ContractError, RecoveryObservationV1, RecoveryProfileRequirementsV1, RecoveryTrajectoryV1,
};
use chio_semantic_contracts::{DependencyGraphV1, EffectContractV1};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const VECTORS: &str = include_str!("../../../../spec/vectors/recovery/v1/contracts.json");

#[derive(Deserialize)]
struct Corpus {
    format_version: u8,
    vectors: Vec<Vector>,
}
#[derive(Deserialize)]
struct Vector {
    name: String,
    contract: String,
    valid: bool,
    schema_valid: bool,
    wire: String,
    error: Option<String>,
    expected_scope: Option<chio_security_types::recovery::RecoveryScopeV1>,
}

#[test]
fn shared_negative_recovery_vectors() -> Result {
    let corpus: Corpus = serde_json::from_str(VECTORS)?;
    assert_eq!(corpus.format_version, 1);
    for vector in corpus.vectors {
        let result = match vector.contract.as_str() {
            "observation" => decode_contract::<RecoveryObservationV1>(vector.wire.as_bytes())
                .and_then(|observation| {
                    if let Some(scope) = &vector.expected_scope {
                        observation.scope().ensure_matches(scope)?;
                    }
                    Ok(())
                }),
            "profile" => {
                decode_contract::<RecoveryProfileRequirementsV1>(vector.wire.as_bytes()).map(|_| ())
            }
            "trajectory" => {
                decode_contract::<RecoveryTrajectoryV1>(vector.wire.as_bytes()).map(|_| ())
            }
            "effect_contract" => {
                decode_contract::<EffectContractV1>(vector.wire.as_bytes()).map(|_| ())
            }
            "graph" => decode_contract::<DependencyGraphV1>(vector.wire.as_bytes()).map(|_| ()),
            _ => return Err("unknown fixture contract".into()),
        };
        assert_eq!(result.is_ok(), vector.valid, "{}: {result:?}", vector.name);
        if let Some(error) = vector.error {
            assert_eq!(
                result.err().map(|error| error.to_string()),
                Some(format!("recovery.{error}")),
                "{}",
                vector.name
            );
        }
    }
    Ok(())
}

#[test]
fn schemas_share_structural_vectors_with_typed_reader() -> Result {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1/recovery");
    let mut resources = Vec::new();
    for name in [
        "observation",
        "profile-requirements",
        "effect-contract",
        "dependency-graph",
        "trajectory",
    ] {
        let schema: Value =
            serde_json::from_slice(&std::fs::read(root.join(format!("{name}.schema.json")))?)?;
        let id = schema["$id"]
            .as_str()
            .ok_or("missing schema id")?
            .to_owned();
        resources.push((id, schema));
    }
    let mut registry = jsonschema::Registry::new();
    for (id, schema) in &resources {
        registry = registry.add(id, schema)?;
    }
    let registry = registry.prepare()?;
    let corpus: Corpus = serde_json::from_str(VECTORS)?;
    for vector in corpus.vectors {
        let name = match vector.contract.as_str() {
            "profile" => "profile-requirements",
            "effect_contract" => "effect-contract",
            "graph" => "dependency-graph",
            name => name,
        };
        let schema: Value =
            serde_json::from_slice(&std::fs::read(root.join(format!("{name}.schema.json")))?)?;
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&schema)?;
        let value: Value = serde_json::from_str(&vector.wire)?;
        assert_eq!(
            validator.is_valid(&value),
            vector.schema_valid,
            "schema disagrees on {}",
            vector.name
        );
    }
    Ok(())
}

#[test]
fn nested_allocation_and_aggregate_budgets_refuse_before_typed_decode() -> Result {
    let limits = RecoveryDecodeLimits::new(4096, 3, 12, 16, 4)?;
    assert!(decode_contract_with_limits::<Value>(b"[1,2,3,4]", limits).is_ok());
    for input in [
        b"[[[[0]]]]".as_slice(),
        b"[1,2,3,4,5]",
        b"[\"abcdefghijklmnopq\"]",
        b"[[0,1,2],[0,1,2],[0,1,2]]",
    ] {
        assert_eq!(
            decode_contract_with_limits::<Value>(input, limits),
            Err(ContractError::LimitExceeded)
        );
    }
    // Escaped text is checked before serde_json can grow its unescape scratch.
    assert_eq!(
        decode_contract_with_limits::<Value>(br#"["\u0061\u0061\u0061"]"#, limits),
        Err(ContractError::LimitExceeded)
    );
    assert!(RecoveryDecodeLimits::new(65537, 16, 4096, 32768, 256).is_err());
    assert!(RecoveryDecodeLimits::new(4096, 0, 12, 16, 4).is_err());
    Ok(())
}

#[test]
fn domains_frame_canonical_bodies_and_refuse_cross_domain_substitution() -> Result {
    let body = CanonicalBytes::new(&serde_json::json!({"a":1,"b":2}))?;
    let reordered = CanonicalBytes::new(&serde_json::json!({"b":2,"a":1}))?;
    for (index, domain) in RECOVERY_DIGEST_DOMAINS.iter().enumerate() {
        assert_eq!(domain.prefix().last(), Some(&0));
        assert_eq!(domain.digest(&body), domain.digest(&reordered));
        for other in &RECOVERY_DIGEST_DOMAINS[index + 1..] {
            assert_ne!(domain.digest(&body), other.digest(&body));
        }
        let mut framed = domain.prefix().to_vec();
        framed.extend_from_slice(body.as_bytes());
        assert_eq!(
            domain.digest(&body).as_bytes(),
            chio_core_types::hashing::sha256(&framed).as_bytes()
        );
    }
    Ok(())
}

#[test]
fn public_errors_and_debug_do_not_expose_canaries() -> Result {
    let mut vector: Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/observation.json"
    ))?;
    vector["scope"]["tenant_id"] = Value::String("protected-canary".into());
    let bytes = chio_core_types::canonical_json_bytes(&vector)?;
    let observation: RecoveryObservationV1 = decode_contract(&bytes)?;
    assert!(!format!("{observation:?}").contains("protected-canary"));
    vector["scope"]["tenant_id"] = Value::String("protected-canary\n".into());
    let error =
        decode_contract::<RecoveryObservationV1>(&chio_core_types::canonical_json_bytes(&vector)?)
            .err()
            .ok_or("expected refusal")?;
    assert!(!error.to_string().contains("protected-canary"));
    Ok(())
}

#[test]
fn malformed_tokens_and_nested_duplicates_have_no_permissive_fallback() {
    for input in [
        br#"{"a":{"b":1,"b":2}}"#.as_slice(),
        b"[9007199254740992]",
        b"[1.0]",
        b"[1e0]",
        b"[-1]",
        b"[01]",
        br#"{"a":1,}"#,
        b"[{]}",
        b"\xff",
        b"[null]garbage",
    ] {
        assert!(
            decode_contract::<Value>(input).is_err(),
            "accepted malformed vector"
        );
    }
}
