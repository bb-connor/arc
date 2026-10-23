use chio_core_types::capability::caveat::{
    CapabilitySecurityBinding, Caveat, CAPABILITY_SECURITY_BINDING_SCHEMA,
};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::Keypair;
use serde_json::Value;

use super::{load_schema, repo_root, schema_root, to_json, validator_for_schema};

const TOKEN_SCHEMA: &str = "capability/token.schema.json";
const BINDING_SCHEMA: &str = "capability/security-binding.schema.json";

fn vectors() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(
            repo_root().join("tests/bindings/vectors/capability/security-binding-v1.json"),
        )
        .expect("security binding vectors exist"),
    )
    .expect("security binding vectors parse")
}

fn token_body(issuer: &Keypair) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "cap-security-bound".to_string(),
        issuer: issuer.public_key(),
        subject: Keypair::from_seed(&[0x0c; 32]).public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "server-1".to_string(),
                tool_name: "tool-1".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        issued_at: 10,
        expires_at: 20,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    }
}

#[test]
fn security_binding_vectors_match_native_verifier_and_published_schemas() {
    let vectors = vectors();
    assert_eq!(
        vectors["binding_schema"],
        CAPABILITY_SECURITY_BINDING_SCHEMA
    );
    let workload = Keypair::from_seed_hex(
        vectors["workload_signer_seed_hex"]
            .as_str()
            .expect("seed is a string"),
    )
    .expect("seed decodes");
    let cases = vectors["cases"].as_array().expect("cases are an array");
    let reference = &cases[0];
    assert_eq!(reference["id"], "bound-workload");
    let predicate = reference["caveats"][0]["predicate"]
        .as_str()
        .expect("reference predicate is a string");
    let binding: CapabilitySecurityBinding =
        serde_json::from_str(predicate).expect("reference predicate decodes");
    assert_eq!(
        binding.workload_signer_public_key,
        workload.public_key().to_hex()
    );
    assert_eq!(
        Caveat::bind_security_context(&binding)
            .expect("reference binding is valid")
            .predicate,
        predicate,
        "reference predicate is not the native canonical encoding"
    );
    let token =
        CapabilityToken::sign_with_security_binding(token_body(&workload), binding, &workload)
            .expect("reference token signs");
    assert!(token.verify_integrity_embedded_key().expect("signature verifies"));

    let token_validator = validator_for_schema(
        &schema_root().join(TOKEN_SCHEMA),
        &load_schema(TOKEN_SCHEMA),
    );
    let binding_validator = validator_for_schema(
        &schema_root().join(BINDING_SCHEMA),
        &load_schema(BINDING_SCHEMA),
    );

    // Unicode format characters are not whitespace or control characters.
    for marker in ['\u{feff}', '\u{200b}', '\u{2060}'] {
        for value in [format!("{marker}id"), format!("id{marker}")] {
            let mut candidate: CapabilitySecurityBinding =
                serde_json::from_str(predicate).expect("reference binding decodes");
            candidate.tenant_id = value.clone();
            assert!(candidate.validate().is_ok(), "native rejected {value:?}");
            assert!(
                binding_validator.is_valid(&to_json(&candidate)),
                "schema rejected {value:?}"
            );
        }
    }

    let mut mismatches = Vec::new();
    for case in cases {
        let id = case["id"].as_str().expect("case id is a string");
        let native = serde_json::from_value::<Vec<Caveat>>(case["caveats"].clone())
            .map(|caveats| {
                let mut candidate = token.clone();
                candidate.caveats = caveats;
                candidate.validate_schema().is_ok()
            })
            .unwrap_or(false);
        let mut wire = to_json(&token);
        wire["caveats"] = case["caveats"].clone();
        let predicates_valid = case["caveats"]
            .as_array()
            .expect("case caveats are an array")
            .iter()
            .filter(|caveat| caveat["kind"] == "bind_security_context")
            .all(|caveat| {
                caveat["predicate"]
                    .as_str()
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
                    .is_some_and(|decoded| binding_validator.is_valid(&decoded))
            });
        let schema = token_validator.is_valid(&wire) && predicates_valid;
        if native != case["native_valid"] {
            mismatches.push(format!("{id}: native verifier returned {native}"));
        }
        if schema != case["schema_valid"] {
            mismatches.push(format!("{id}: published schemas returned {schema}"));
        }
        if schema && !native && !id.starts_with("noncanonical-") {
            mismatches.push(format!(
                "{id}: schemas accept a binding the native verifier rejects for a stated rule"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "security binding vector mismatches:\n  {}",
        mismatches.join("\n  ")
    );
}
