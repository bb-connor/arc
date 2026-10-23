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
    assert!(token
        .verify_integrity_embedded_key()
        .expect("signature verifies"));

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

#[derive(serde::Serialize)]
struct VectorCaveat {
    kind: &'static str,
    predicate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
}

#[derive(serde::Serialize)]
struct VectorCase {
    id: &'static str,
    caveats: Vec<VectorCaveat>,
    native_valid: bool,
    schema_valid: bool,
}

#[derive(serde::Serialize)]
struct VectorFile {
    version: u32,
    description: &'static str,
    binding_schema: &'static str,
    workload_signer_seed_hex: String,
    cases: Vec<VectorCase>,
}

const WORKLOAD_SIGNER_SEED_HEX: &str =
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

fn reference_binding(workload: &Keypair) -> CapabilitySecurityBinding {
    CapabilitySecurityBinding {
        schema: CAPABILITY_SECURITY_BINDING_SCHEMA.to_string(),
        tenant_id: "tenant-1".to_string(),
        lineage_id: "lineage-1".to_string(),
        session_id: "session-1".to_string(),
        principal_id: "agent-1".to_string(),
        isolation_epoch_id: "epoch-1".to_string(),
        context_generation: 7,
        workload_id: "workload-1".to_string(),
        server_id: "server-1".to_string(),
        workload_signer_public_key: workload.public_key().to_hex(),
    }
}

fn binding_caveat(predicate: String) -> VectorCaveat {
    VectorCaveat {
        kind: "bind_security_context",
        predicate,
        sig: None,
    }
}

fn mutated_predicate(
    canonical: &str,
    mutate: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> String {
    let mut decoded: Value = serde_json::from_str(canonical).expect("canonical predicate decodes");
    mutate(decoded.as_object_mut().expect("predicate is an object"));
    serde_json::to_string(&decoded).expect("mutated predicate encodes")
}

fn vector_case(
    id: &'static str,
    caveats: Vec<VectorCaveat>,
    native_valid: bool,
    schema_valid: bool,
) -> VectorCase {
    VectorCase {
        id,
        caveats,
        native_valid,
        schema_valid,
    }
}

fn single_invalid(id: &'static str, predicate: String) -> VectorCase {
    vector_case(id, vec![binding_caveat(predicate)], false, false)
}

fn security_binding_vector_file() -> VectorFile {
    let workload = Keypair::from_seed_hex(WORKLOAD_SIGNER_SEED_HEX).expect("workload seed decodes");
    let binding = reference_binding(&workload);
    let canonical = Caveat::bind_security_context(&binding)
        .expect("reference binding is valid")
        .predicate;

    let spaced = canonical.replace("\":", "\": ").replace(",\"", ", \"");
    let reordered = {
        let decoded: Value = serde_json::from_str(&canonical).expect("canonical predicate decodes");
        let members: Vec<String> = [
            "schema",
            "tenantId",
            "lineageId",
            "sessionId",
            "principalId",
            "isolationEpochId",
            "contextGeneration",
            "workloadId",
            "serverId",
            "workloadSignerPublicKey",
        ]
        .iter()
        .map(|key| format!("\"{key}\":{}", decoded[*key]))
        .collect();
        format!("{{{}}}", members.join(","))
    };
    let workload_key = binding.workload_signer_public_key.clone();

    let cases = vec![
        vector_case(
            "bound-workload",
            vec![binding_caveat(canonical.clone())],
            true,
            true,
        ),
        vector_case("no-caveats", vec![], true, true),
        vector_case(
            "detached-signature",
            vec![VectorCaveat {
                sig: Some("0".repeat(128)),
                ..binding_caveat(canonical.clone())
            }],
            false,
            false,
        ),
        vector_case(
            "noncanonical-whitespace",
            vec![binding_caveat(spaced)],
            false,
            true,
        ),
        vector_case(
            "noncanonical-key-order",
            vec![binding_caveat(reordered)],
            false,
            true,
        ),
        single_invalid(
            "unknown-binding-field",
            mutated_predicate(&canonical, |members| {
                members.insert("region".to_string(), Value::from("eu-1"));
            }),
        ),
        single_invalid(
            "missing-server-id",
            mutated_predicate(&canonical, |members| {
                members.remove("serverId");
            }),
        ),
        single_invalid(
            "zero-context-generation",
            mutated_predicate(&canonical, |members| {
                members.insert("contextGeneration".to_string(), Value::from(0));
            }),
        ),
        single_invalid(
            "foreign-binding-schema",
            mutated_predicate(&canonical, |members| {
                members.insert(
                    "schema".to_string(),
                    Value::from("chio.capability-security-binding.v2"),
                );
            }),
        ),
        single_invalid(
            "padded-tenant-id",
            mutated_predicate(&canonical, |members| {
                members.insert("tenantId".to_string(), Value::from(" tenant-1"));
            }),
        ),
        single_invalid(
            "control-character-session-id",
            mutated_predicate(&canonical, |members| {
                members.insert("sessionId".to_string(), Value::from("session\u{7}1"));
            }),
        ),
        single_invalid(
            "uppercase-workload-key",
            mutated_predicate(&canonical, |members| {
                members.insert(
                    "workloadSignerPublicKey".to_string(),
                    Value::from(workload_key.to_uppercase()),
                );
            }),
        ),
        single_invalid(
            "prefixed-workload-key",
            mutated_predicate(&canonical, |members| {
                members.insert(
                    "workloadSignerPublicKey".to_string(),
                    Value::from(format!("0x{workload_key}")),
                );
            }),
        ),
        vector_case(
            "two-bindings",
            vec![
                binding_caveat(canonical.clone()),
                binding_caveat(canonical.clone()),
            ],
            false,
            false,
        ),
        vector_case(
            "unenforced-caveat-kind",
            vec![VectorCaveat {
                kind: "restrict_tool",
                predicate: "server-1/tool-1".to_string(),
                sig: None,
            }],
            false,
            false,
        ),
    ];

    VectorFile {
        version: 1,
        description: "bind_security_context caveat vectors. native_valid is the verdict of CapabilityToken::validate_schema; schema_valid is the verdict of capability/token.schema.json on the token together with capability/security-binding.schema.json on each decoded bind_security_context predicate. The canonical-bytes rule is the only native rule the schemas cannot state.",
        binding_schema: CAPABILITY_SECURITY_BINDING_SCHEMA,
        workload_signer_seed_hex: WORKLOAD_SIGNER_SEED_HEX.to_string(),
        cases,
    }
}

fn security_binding_vector_path() -> std::path::PathBuf {
    repo_root().join("tests/bindings/vectors/capability/security-binding-v1.json")
}

fn security_binding_vector_text() -> String {
    let mut rendered = serde_json::to_string_pretty(&security_binding_vector_file())
        .expect("security binding vectors serialize");
    rendered.push('\n');
    rendered
}

#[test]
fn security_binding_vectors_are_current() {
    let path = security_binding_vector_path();
    let committed = std::fs::read_to_string(&path).expect("security binding vectors exist");
    assert_eq!(
        committed,
        security_binding_vector_text(),
        "fixture {} is out of date",
        path.display()
    );
}

#[test]
#[ignore = "regenerator: rewrite the security binding vectors from security_binding_vector_file(); run with --ignored, then `cargo xtask freeze-vectors`"]
fn regenerate_security_binding_vectors() {
    std::fs::write(
        security_binding_vector_path(),
        security_binding_vector_text(),
    )
    .expect("write security binding vectors");
}
