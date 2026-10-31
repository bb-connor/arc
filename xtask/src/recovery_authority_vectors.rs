//! Deterministic signer and corpus builder for the recovery authority vectors.
//!
//! `authority-positive.json` holds the authored positive contracts. Every
//! signature in it is derived from the fixed test signers, and
//! `authority-contracts.json` is derived from those positives by fixed
//! structural, signature, canonical-form and UTF-8 bound mutations.

use std::fs;

use chio_core_types::canonical::CanonicalBytes;
use chio_core_types::crypto::Keypair;
use chio_core_types::recovery::{
    RecoveryDigestDomain, RecoveryGrantBody, SignedAuthorityCoverageAttestationV1,
    SignedRecoveryGrant, SignedRecoveryProviderFinalityV1,
};
use chio_core_types::SignedDeclassificationGrant;
use serde::Serialize;
use serde_json::{json, Map, Value};

use super::{display_path, workspace_root, XtaskError};

const POSITIVE_PATH: &str = "spec/vectors/recovery/v1/authority-positive.json";
const CORPUS_PATH: &str = "spec/vectors/recovery/v1/authority-contracts.json";
const AUTHORITY_SEED: [u8; 32] = [143; 32];
const COVERAGE_SEED: [u8; 32] = [142; 32];
const UNSAFE_INTEGER: &str = "9007199254740992";

/// Contracts whose positives carry a `version` member, with the member's path.
const VERSIONED: [(&str, &[&str]); 9] = [
    ("action", &["version"]),
    ("requirements", &["version"]),
    ("approval_intent", &["version"]),
    ("grant", &["body", "version"]),
    ("command", &["version"]),
    ("provider_finality", &["body", "version"]),
    ("coverage", &["body", "version"]),
    ("grant_binding", &["version"]),
    ("provider_body", &["version"]),
];
const UNVERSIONED: [&str; 5] = [
    "support_issue_effect",
    "support_issue_input",
    "command_response",
    "command_result",
    "review_document",
];
const SIGNED: [&str; 3] = ["grant", "coverage", "provider_finality"];

/// Decoded UTF-8 ceilings: (name, contract, field path, ceiling in bytes).
const UTF8_BOUNDS: [(&str, &str, &[&str], usize); 9] = [
    ("title", "support_issue_input", &["title"], 256),
    ("body", "support_issue_input", &["body"], 16_384),
    ("resource", "support_issue_effect", &["resource"], 2_048),
    ("provider", "provider_body", &["provider"], 256),
    ("account", "provider_body", &["account"], 256),
    ("capability", "action", &["capability_id"], 256),
    ("recipient", "requirements", &["recipient"], 256),
    ("purpose", "requirements", &["purpose"], 256),
    (
        "compartment",
        "requirements",
        &["source_label", "compartments", "0"],
        256,
    ),
];

pub fn run(check_only: bool) -> Result<(), XtaskError> {
    let root = workspace_root()?;
    let positive_path = root.join(POSITIVE_PATH);
    let corpus_path = root.join(CORPUS_PATH);
    let existing_positive = read(&positive_path)?;
    let existing_corpus = read(&corpus_path)?;
    let mut positive: Value = serde_json::from_str(&existing_positive)
        .map_err(|err| XtaskError::Json(display_path(&positive_path), err))?;
    sign_positive(&mut positive)?;
    let generated_positive = canonical_text(&positive)?;
    let mut generated_corpus = serde_json::to_string_pretty(&json!({
        "format_version": 1,
        "vectors": corpus(&positive)?,
    }))
    .map_err(|err| XtaskError::Json(CORPUS_PATH.to_owned(), err))?;
    generated_corpus.push('\n');

    if check_only {
        for (path, existing, generated) in [
            (&positive_path, &existing_positive, &generated_positive),
            (&corpus_path, &existing_corpus, &generated_corpus),
        ] {
            if existing != generated {
                return Err(XtaskError::Drift(format!(
                    "{} is stale; rerun `cargo xtask gen recovery-authority-vectors`",
                    display_path(path)
                )));
            }
        }
        println!("recovery authority vectors in sync");
        return Ok(());
    }
    for (path, generated) in [
        (&positive_path, &generated_positive),
        (&corpus_path, &generated_corpus),
    ] {
        fs::write(path, generated).map_err(|err| XtaskError::Io(display_path(path), err))?;
        println!("wrote {}", display_path(path));
    }
    Ok(())
}

fn read(path: &std::path::Path) -> Result<String, XtaskError> {
    fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn drift(detail: impl std::fmt::Display) -> XtaskError {
    XtaskError::Drift(format!("recovery authority vectors: {detail}"))
}

fn sign_positive(positive: &mut Value) -> Result<(), XtaskError> {
    let authority = Keypair::from_seed(&AUTHORITY_SEED);
    let coverage_signer = Keypair::from_seed(&COVERAGE_SEED);

    let coverage = positive["coverage"]
        .as_array_mut()
        .ok_or_else(|| drift("coverage is not an array"))?;
    let mut attestations = Vec::with_capacity(coverage.len());
    for proof in coverage.iter_mut() {
        let signed =
            SignedAuthorityCoverageAttestationV1::sign(typed(&proof["body"])?, &coverage_signer)
                .map_err(drift)?;
        *proof = to_value(&signed)?;
        attestations.push(signed);
    }

    // Same order as `chio_flow::verify_recovery_coverage`.
    attestations.sort_by_key(|a| (a.body().principal.clone(), a.body().issuer_id.clone()));
    let canonical = CanonicalBytes::new(&attestations).map_err(drift)?;
    let digest = RecoveryDigestDomain::AuthorityCoverage.digest(&canonical);
    positive["grant"]["body"]["recovery"]["coverage_digest"] = to_value(digest.as_bytes())?;

    let grant_body: RecoveryGrantBody = typed(&positive["grant"]["body"])?;
    let grant = SignedRecoveryGrant::sign(grant_body, &authority).map_err(drift)?;
    positive["grant"] = to_value(&grant)?;
    positive["request"]["declassification_grant"] =
        json!({ "kind": "recovery", "grant": positive["grant"].clone() });

    let finality = SignedRecoveryProviderFinalityV1::sign(
        typed(&positive["provider_finality"]["body"])?,
        &authority,
    )
    .map_err(drift)?;
    positive["provider_finality"] = to_value(&finality)?;
    Ok(())
}

fn typed<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, XtaskError> {
    serde_json::from_value(value.clone()).map_err(drift)
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, XtaskError> {
    serde_json::to_value(value).map_err(drift)
}

fn canonical_text(value: &Value) -> Result<String, XtaskError> {
    let bytes = chio_core_types::canonical_json_bytes(value).map_err(drift)?;
    String::from_utf8(bytes).map_err(drift)
}

fn sample(positive: &Value, contract: &str) -> Result<Value, XtaskError> {
    let value = match contract {
        "coverage" => &positive["coverage"][0],
        "grant_binding" => &positive["grant"]["body"]["recovery"],
        "provider_body" => &positive["provider_finality"]["body"],
        other => &positive[other],
    };
    if value.is_null() {
        return Err(drift(format!("no positive {contract}")));
    }
    Ok(value.clone())
}

fn member<'a>(value: &'a mut Value, path: &[&str]) -> Result<&'a mut Value, XtaskError> {
    path.iter().try_fold(value, |node, key| match node {
        Value::Object(map) => map
            .get_mut(*key)
            .ok_or_else(|| drift(format!("missing member {key}"))),
        Value::Array(items) => key
            .parse::<usize>()
            .ok()
            .and_then(|index| items.get_mut(index))
            .ok_or_else(|| drift(format!("missing element {key}"))),
        _ => Err(drift(format!("cannot descend into {key}"))),
    })
}

fn object(value: &mut Value) -> Result<&mut Map<String, Value>, XtaskError> {
    value
        .as_object_mut()
        .ok_or_else(|| drift("expected an object"))
}

fn replace_once(text: &str, from: &str, to: &str) -> Result<String, XtaskError> {
    if text.matches(from).count() != 1 {
        return Err(drift(format!("expected exactly one {from}")));
    }
    Ok(text.replacen(from, to, 1))
}

fn with_unsafe_integer(text: &str, member: &str, value: &Value) -> Result<String, XtaskError> {
    replace_once(
        text,
        &format!("\"{member}\":{value}"),
        &format!("\"{member}\":{UNSAFE_INTEGER}"),
    )
}

struct Corpus(Vec<Value>);

impl Corpus {
    fn wire(&mut self, name: &str, contract: &str, valid: bool, schema_valid: bool, wire: String) {
        self.0.push(json!({
            "name": name,
            "contract": contract,
            "valid": valid,
            "schema_valid": schema_valid,
            "wire": wire,
        }));
    }

    fn value(
        &mut self,
        name: &str,
        contract: &str,
        valid: bool,
        schema_valid: bool,
        value: &Value,
    ) -> Result<(), XtaskError> {
        self.wire(name, contract, valid, schema_valid, canonical_text(value)?);
        Ok(())
    }

    fn refused(&mut self, name: &str, contract: &str, value: &Value) -> Result<(), XtaskError> {
        self.value(name, contract, false, false, value)
    }
}

fn corpus(positive: &Value) -> Result<Vec<Value>, XtaskError> {
    let mut corpus = Corpus(Vec::new());
    let canary = Value::String("protected-canary".to_owned());

    for (contract, version) in VERSIONED {
        let base = sample(positive, contract)?;
        corpus.value(&format!("{contract}-positive"), contract, true, true, &base)?;
        for (label, replacement) in [("null", Value::Null), ("99", Value::from(99))] {
            let mut value = base.clone();
            *member(&mut value, version)? = replacement;
            corpus.refused(&format!("{contract}-version-{label}"), contract, &value)?;
        }
        let mut value = base;
        object(&mut value)?.insert("unexpected".to_owned(), canary.clone());
        corpus.refused(&format!("{contract}-unknown-field"), contract, &value)?;
    }
    for contract in UNVERSIONED {
        let base = sample(positive, contract)?;
        corpus.value(&format!("{contract}-positive"), contract, true, true, &base)?;
        let mut value = base;
        object(&mut value)?.insert("unexpected".to_owned(), canary.clone());
        corpus.refused(&format!("{contract}-unknown-field"), contract, &value)?;
    }

    let binding = sample(positive, "grant_binding")?;
    let mut fields = binding.clone();
    for field in object(&mut fields)?.keys() {
        let mut missing = binding.clone();
        object(&mut missing)?.remove(field);
        corpus.refused(
            &format!("grant_binding-missing-{field}"),
            "grant_binding",
            &missing,
        )?;
        let mut null = binding.clone();
        object(&mut null)?.insert(field.clone(), Value::Null);
        corpus.refused(
            &format!("grant_binding-null-{field}"),
            "grant_binding",
            &null,
        )?;
    }

    for contract in SIGNED {
        let base = sample(positive, contract)?;
        let signature = base["signature"]
            .as_str()
            .ok_or_else(|| drift(format!("{contract} has no signature")))?;
        let mut forged = base.clone();
        forged["signature"] = Value::String("0".repeat(signature.len()));
        corpus.value(
            &format!("{contract}-invalid-signature"),
            contract,
            false,
            true,
            &forged,
        )?;
        let mut unknown = base;
        unknown["algorithm"] = Value::String("unknown".to_owned());
        corpus.refused(&format!("{contract}-unknown-algorithm"), contract, &unknown)?;
    }

    let grant = sample(positive, "grant")?;
    let mut unbound = grant.clone();
    object(member(&mut unbound, &["body"])?)?.remove("recovery");
    corpus.refused("grant-missing-binding", "grant", &unbound)?;
    let claims = typed(&grant["body"]["claims"])?;
    let declassification =
        SignedDeclassificationGrant::sign(claims, &Keypair::from_seed(&AUTHORITY_SEED))
            .map_err(drift)?;
    corpus.refused(
        "grant-declassification-shape",
        "grant",
        &to_value(&declassification)?,
    )?;

    let command = canonical_text(&sample(positive, "command")?)?;
    let revision = sample(positive, "command")?["command"]["expected_revision"].clone();
    corpus.wire(
        "command-unsafe-integer",
        "command",
        false,
        false,
        with_unsafe_integer(&command, "expected_revision", &revision)?,
    );
    let binding_text = canonical_text(&binding)?;
    let epoch = binding["isolation_epoch"].clone();
    corpus.wire(
        "grant_binding-unsafe-integer",
        "grant_binding",
        false,
        false,
        with_unsafe_integer(&binding_text, "isolation_epoch", &epoch)?,
    );
    corpus.wire(
        "grant_binding-duplicate-key",
        "grant_binding",
        false,
        true,
        replace_once(
            &binding_text,
            "\"version\":1",
            "\"version\":1,\"version\":1",
        )?,
    );
    corpus.wire(
        "command-noncanonical",
        "command",
        false,
        true,
        serde_json::to_string_pretty(&sample(positive, "command")?).map_err(drift)?,
    );

    origin_vectors(&mut corpus, positive)?;
    utf8_vectors(&mut corpus, positive)?;
    Ok(corpus.0)
}

fn origin_vectors(corpus: &mut Corpus, positive: &Value) -> Result<(), XtaskError> {
    let action = sample(positive, "action")?;
    let origin = action["origin"].clone();
    let mutations: [(&str, &[&str], Option<Value>); 12] = [
        ("origin-missing", &[], None),
        ("origin-null", &["origin"], Some(Value::Null)),
        ("origin-empty", &["origin"], Some(json!({}))),
        ("origin-array", &["origin"], Some(json!([origin.clone()]))),
        ("origin-missing-operation", &["origin", "operation"], None),
        ("origin-missing-request_id", &["origin", "request_id"], None),
        ("origin-missing-closure", &["origin", "closure"], None),
        (
            "origin-operation-version-zero",
            &["origin", "operation", "operation_version"],
            Some(Value::from(0)),
        ),
        (
            "origin-closure-newline",
            &["origin", "closure"],
            Some(Value::String("closure\n".to_owned())),
        ),
        (
            "origin-request-id-newline",
            &["origin", "request_id"],
            Some(Value::String("request\n".to_owned())),
        ),
        (
            "origin-unknown-member",
            &["origin", "claimed_authority"],
            Some(Value::Bool(true)),
        ),
        (
            "origin-operation-unknown-member",
            &["origin", "operation", "other"],
            Some(Value::Bool(true)),
        ),
    ];
    for (name, path, replacement) in mutations {
        let mut value = action.clone();
        match (path.split_last(), replacement) {
            (None, _) => {
                object(&mut value)?.remove("origin");
            }
            (Some((last, parent)), Some(replacement)) => {
                object(member(&mut value, parent)?)?.insert((*last).to_owned(), replacement);
            }
            (Some((last, parent)), None) => {
                object(member(&mut value, parent)?)?.remove(*last);
            }
        }
        corpus.refused(name, "action", &value)?;
    }

    let text = canonical_text(&action)?;
    let version = origin["operation"]["operation_version"].clone();
    let version_token = format!("\"operation_version\":{version}");
    corpus.wire(
        "origin-operation-version-unsafe",
        "action",
        false,
        false,
        with_unsafe_integer(&text, "operation_version", &version)?,
    );
    for (name, token) in [
        ("origin-operation-version-float-token", "1.0"),
        ("origin-operation-version-exponent-token", "1e0"),
    ] {
        corpus.wire(
            name,
            "action",
            false,
            true,
            replace_once(
                &text,
                &version_token,
                &format!("\"operation_version\":{token}"),
            )?,
        );
    }
    let closure = origin["closure"]
        .as_str()
        .ok_or_else(|| drift("origin closure is not a string"))?;
    let closure_member = format!("\"closure\":\"{closure}\"");
    corpus.wire(
        "origin-duplicate",
        "action",
        false,
        true,
        replace_once(&text, "\"origin\":{", "\"origin\":null,\"origin\":{")?,
    );
    corpus.wire(
        "origin-duplicate-closure",
        "action",
        false,
        true,
        replace_once(
            &text,
            &closure_member,
            &format!("{closure_member},\"closure\":\"substituted-closure\""),
        )?,
    );
    corpus.wire(
        "action-noncanonical",
        "action",
        false,
        true,
        serde_json::to_string_pretty(&action).map_err(drift)?,
    );
    Ok(())
}

fn utf8_vectors(corpus: &mut Corpus, positive: &Value) -> Result<(), XtaskError> {
    for (name, contract, path, ceiling) in UTF8_BOUNDS {
        for (label, characters, valid) in [
            ("exact", ceiling / 2, true),
            ("oversized", ceiling / 2 + 1, false),
        ] {
            let mut value = sample(positive, contract)?;
            *member(&mut value, path)? = Value::String("\u{e9}".repeat(characters));
            let name = format!("utf8-{name}-{label}");
            corpus.value(&name, contract, valid, valid, &value)?;
        }
    }
    for (label, characters, valid) in [("exact", 128, true), ("oversized", 129, false)] {
        let wide = "\u{e9}".repeat(characters);
        for (name, owners) in [
            ("owner", json!({ wide.clone(): [wide.clone()] })),
            ("reader", json!({ "owner": ["owner", wide.clone()] })),
        ] {
            let mut value = sample(positive, "requirements")?;
            value["source_label"] = json!({
                "kind": "known",
                "owners": owners,
                "compartments": [],
            });
            let name = format!("utf8-{name}-{label}");
            corpus.value(&name, "requirements", valid, valid, &value)?;
        }
    }
    Ok(())
}
