//! The `chio.receipt-disclosure.v1` document, the salt wire form and the commitment opener.

use std::path::PathBuf;

use chio_core_types::receipt::commitment::{
    CommitmentDomain, ContentPreimage, ReceiptCommitment, Salt, CONTENT_SALT_REF, PARAMS_SALT_REF,
    SALT_LEN,
};
use chio_core_types::receipt::disclosure::{
    open_commitments, DisclosureSchema, FieldVerdict, Opening, OpeningReport, ReceiptDisclosure,
    CHIO_RECEIPT_DISCLOSURE_SCHEMA,
};
use chio_core_types::root_authority::SaltRef;
use chio_test_support::prelude::*;
use serde_json::{json, Value};

const RECEIPT_ID: &str = "d9f4cc34e357aaf0c22e38974c82c093a31948087cc955f769a87fd454711c33";

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative)
}

fn read_json(relative: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(repo_path(relative)).test_unwrap()).test_unwrap()
}

fn salt_ref(text: &str) -> SaltRef {
    SaltRef::new(text).test_unwrap()
}

fn parameters() -> Value {
    json!({"mode": "read", "path": "/workspace/docs/roadmap.md"})
}

fn output() -> Value {
    json!({"lines": 42, "text": "Roadmap"})
}

fn commitments(params_salt: &Salt, content_salt: &Salt) -> (ReceiptCommitment, ReceiptCommitment) {
    let parameters_bytes =
        chio_core_types::canonical::canonical_json_bytes(&parameters()).test_unwrap();
    let output_bytes = ContentPreimage::Value(&output()).to_bytes().test_unwrap();
    (
        ReceiptCommitment::compute(
            CommitmentDomain::Parameters,
            salt_ref(PARAMS_SALT_REF),
            params_salt,
            &parameters_bytes,
        ),
        ReceiptCommitment::compute(
            CommitmentDomain::Content,
            salt_ref(CONTENT_SALT_REF),
            content_salt,
            &output_bytes,
        ),
    )
}

fn opening(reference: &str, salt: &Salt, payload: Option<Value>) -> Opening {
    Opening {
        salt_ref: salt_ref(reference),
        salt: salt.clone(),
        payload,
    }
}

fn disclosure(openings: Vec<Opening>) -> ReceiptDisclosure {
    ReceiptDisclosure {
        schema: DisclosureSchema::V1,
        receipt_id: RECEIPT_ID.to_owned(),
        openings,
    }
}

fn report(
    parameters: FieldVerdict,
    content: FieldVerdict,
    disclosure_valid: bool,
) -> OpeningReport {
    OpeningReport {
        parameters,
        content,
        disclosure_valid,
    }
}

fn open(
    document: &ReceiptDisclosure,
    params: &ReceiptCommitment,
    content: &ReceiptCommitment,
) -> OpeningReport {
    let own = output();
    open_commitments(
        RECEIPT_ID,
        params,
        content,
        document,
        Some(&parameters()),
        Some(ContentPreimage::Value(&own)),
    )
}

fn flip_low_bit(salt: &Salt) -> Salt {
    let mut bytes = *salt.as_bytes();
    bytes[0] ^= 1;
    Salt::from_bytes(bytes)
}

#[test]
fn salt_wire_form_round_trips() {
    let salt = Salt::from_bytes([0x10; SALT_LEN]);
    let encoded = serde_json::to_value(&salt).test_unwrap();
    assert_eq!(
        encoded,
        Value::String("b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA".to_owned())
    );
    assert_eq!(serde_json::from_value::<Salt>(encoded).test_unwrap(), salt);
}

#[test]
fn salt_wire_form_is_strict() {
    let canonical = "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA";
    let refused = [
        format!("{canonical}="),
        "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEA".to_owned(),
        "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEA".to_owned(),
        format!("b64u:{}B", "A".repeat(42)),
        "EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".to_owned(),
        "b64:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA".to_owned(),
        "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB+".to_owned(),
        "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB/".to_owned(),
        String::new(),
    ];
    for text in refused {
        assert!(
            serde_json::from_value::<Salt>(Value::String(text.clone())).is_err(),
            "{text:?} decoded"
        );
    }
    assert!(serde_json::from_value::<Salt>(json!(16)).is_err());
    assert!(serde_json::from_str::<Salt>(&format!("\"{canonical}\"")).is_ok());
}

#[test]
fn opener_verifies_both_fields() {
    let (params_salt, content_salt) = (Salt::from_bytes([0x10; 32]), Salt::from_bytes([0x11; 32]));
    let (params, content) = commitments(&params_salt, &content_salt);
    let document = disclosure(vec![
        opening("params", &params_salt, Some(parameters())),
        opening("content", &content_salt, Some(output())),
    ]);
    assert_eq!(
        open(&document, &params, &content),
        report(FieldVerdict::Verified, FieldVerdict::Verified, true)
    );
}

#[test]
fn absent_opening_or_preimage_is_unverifiable() {
    let (params_salt, content_salt) = (Salt::from_bytes([0x10; 32]), Salt::from_bytes([0x11; 32]));
    let (params, content) = commitments(&params_salt, &content_salt);
    let document = disclosure(vec![opening("params", &params_salt, None)]);
    assert_eq!(
        open(&document, &params, &content),
        report(FieldVerdict::Verified, FieldVerdict::Unverifiable, true)
    );
    let both = disclosure(vec![
        opening("params", &params_salt, None),
        opening("content", &content_salt, None),
    ]);
    assert_eq!(
        open_commitments(RECEIPT_ID, &params, &content, &both, None, None),
        report(FieldVerdict::Unverifiable, FieldVerdict::Unverifiable, true)
    );
}

#[test]
fn duplicate_salt_marks_disclosure_invalid() {
    let salt = Salt::from_bytes([0x10; 32]);
    let (params, content) = commitments(&salt, &salt);
    let document = disclosure(vec![
        opening("params", &salt, None),
        opening("content", &salt, None),
    ]);
    assert_eq!(
        open(&document, &params, &content),
        report(FieldVerdict::Rejected, FieldVerdict::Rejected, false)
    );
}

#[test]
fn structural_faults_mark_every_field_rejected() {
    let (params_salt, content_salt) = (Salt::from_bytes([0x10; 32]), Salt::from_bytes([0x11; 32]));
    let (params, content) = commitments(&params_salt, &content_salt);
    let duplicate_ref = disclosure(vec![
        opening("params", &params_salt, None),
        opening("params", &content_salt, None),
        opening("content", &content_salt, None),
    ]);
    let mut other_receipt = disclosure(vec![
        opening("params", &params_salt, None),
        opening("content", &content_salt, None),
    ]);
    other_receipt.receipt_id = "e".repeat(64);
    let duplicate_salt_under_unrelated_ref = disclosure(vec![
        opening("params", &params_salt, None),
        opening("content", &content_salt, None),
        opening("anchor.sub", &params_salt, None),
    ]);
    for document in [
        duplicate_ref,
        other_receipt,
        duplicate_salt_under_unrelated_ref,
    ] {
        assert_eq!(
            open(&document, &params, &content),
            report(FieldVerdict::Rejected, FieldVerdict::Rejected, false),
            "{document:?}"
        );
    }
}

#[test]
fn commitment_mismatch_marks_disclosure_invalid() {
    let (params_salt, content_salt) = (Salt::from_bytes([0x10; 32]), Salt::from_bytes([0x11; 32]));
    let (params, content) = commitments(&params_salt, &content_salt);

    let one_bit_salt = disclosure(vec![
        opening("params", &flip_low_bit(&params_salt), None),
        opening("content", &content_salt, None),
    ]);
    assert_eq!(
        open(&one_bit_salt, &params, &content),
        report(FieldVerdict::Rejected, FieldVerdict::Verified, false)
    );

    let honest = disclosure(vec![
        opening("params", &params_salt, None),
        opening("content", &content_salt, None),
    ]);
    let tampered_output = json!({"lines": 43, "text": "Roadmap"});
    assert_eq!(
        open_commitments(
            RECEIPT_ID,
            &params,
            &content,
            &honest,
            Some(&parameters()),
            Some(ContentPreimage::Value(&tampered_output)),
        ),
        report(FieldVerdict::Verified, FieldVerdict::Rejected, false)
    );

    let parameters_for_content = disclosure(vec![opening("content", &params_salt, None)]);
    let as_content = parameters();
    assert_eq!(
        open_commitments(
            RECEIPT_ID,
            &params,
            &content,
            &parameters_for_content,
            Some(&parameters()),
            Some(ContentPreimage::Value(&as_content)),
        ),
        report(FieldVerdict::Unverifiable, FieldVerdict::Rejected, false)
    );

    let output_bytes = ContentPreimage::Value(&output()).to_bytes().test_unwrap();
    let wrong_domain = ReceiptCommitment::compute(
        CommitmentDomain::Parameters,
        salt_ref(CONTENT_SALT_REF),
        &content_salt,
        &output_bytes,
    );
    assert_eq!(
        open(&honest, &params, &wrong_domain),
        report(FieldVerdict::Verified, FieldVerdict::Rejected, false)
    );
}

#[test]
fn commitment_in_the_wrong_position_is_rejected() {
    let (params_salt, content_salt) = (Salt::from_bytes([0x10; 32]), Salt::from_bytes([0x11; 32]));
    let (params, content) = commitments(&params_salt, &content_salt);
    let honest = disclosure(vec![
        opening("params", &params_salt, None),
        opening("content", &content_salt, None),
    ]);
    assert_eq!(
        open(&honest, &content, &params),
        report(FieldVerdict::Rejected, FieldVerdict::Rejected, false)
    );
}

#[test]
fn disclosure_wire_form_round_trips() {
    let (params_salt, content_salt) = (Salt::from_bytes([0x10; 32]), Salt::from_bytes([0x11; 32]));
    let document = disclosure(vec![
        opening("params", &params_salt, Some(parameters())),
        opening("content", &content_salt, None),
    ]);
    let encoded = serde_json::to_value(&document).test_unwrap();
    assert_eq!(encoded["schema"], json!(CHIO_RECEIPT_DISCLOSURE_SCHEMA));
    assert_eq!(encoded["openings"][1]["payload"], Value::Null);
    assert_eq!(
        serde_json::from_value::<ReceiptDisclosure>(encoded.clone()).test_unwrap(),
        document
    );
    let text = serde_json::to_string(&document).test_unwrap();
    assert_eq!(
        serde_json::to_value(serde_json::from_str::<ReceiptDisclosure>(&text).test_unwrap())
            .test_unwrap(),
        encoded
    );
}

#[test]
fn padded_document_and_opening_fail_decoding() {
    let valid = json!({
        "schema": "chio.receipt-disclosure.v1",
        "receipt_id": RECEIPT_ID,
        "openings": [{"salt_ref": "params", "salt": "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA", "payload": null}],
    });
    assert!(serde_json::from_value::<ReceiptDisclosure>(valid.clone()).is_ok());
    let mut padded_document = valid.clone();
    padded_document["pad"] = json!(0);
    let mut padded_opening = valid.clone();
    padded_opening["openings"][0]["pad"] = json!(0);
    let mut no_payload = valid.clone();
    if let Some(object) = no_payload["openings"][0].as_object_mut() {
        object.remove("payload");
    }
    let mut other_schema = valid.clone();
    other_schema["schema"] = json!("chio.receipt-disclosure.v2");
    let mut tagged_schema = valid.clone();
    tagged_schema["schema"] = json!({"chio.receipt-disclosure.v1": null});
    let mut prefixed_id = valid.clone();
    prefixed_id["receipt_id"] = json!(format!("sha256:{RECEIPT_ID}"));
    let mut upper_id = valid.clone();
    upper_id["receipt_id"] = json!(RECEIPT_ID.to_uppercase());
    let mut no_openings = valid.clone();
    no_openings["openings"] = json!([]);
    let mut too_many = valid.clone();
    too_many["openings"] = Value::Array(vec![valid["openings"][0].clone(); 65]);
    let mut bad_ref = valid.clone();
    bad_ref["openings"][0]["salt_ref"] = json!("Params");
    let mut long_ref = valid.clone();
    long_ref["openings"][0]["salt_ref"] = json!(format!("a{}", "b".repeat(64)));
    for (name, document) in [
        ("padded_document", padded_document),
        ("padded_opening", padded_opening),
        ("no_payload", no_payload),
        ("other_schema", other_schema),
        ("tagged_schema", tagged_schema),
        ("prefixed_id", prefixed_id),
        ("upper_id", upper_id),
        ("no_openings", no_openings),
        ("too_many", too_many),
        ("bad_ref", bad_ref),
        ("long_ref", long_ref),
    ] {
        assert!(
            serde_json::from_value::<ReceiptDisclosure>(document.clone()).is_err(),
            "{name} decoded through from_value"
        );
        assert!(
            serde_json::from_str::<ReceiptDisclosure>(&document.to_string()).is_err(),
            "{name} decoded through from_str"
        );
    }
    let duplicate = format!(
        r#"{{"schema":"chio.receipt-disclosure.v1","receipt_id":"{RECEIPT_ID}","receipt_id":"{RECEIPT_ID}","openings":[{{"salt_ref":"params","salt":"b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA","payload":null}}]}}"#
    );
    assert!(serde_json::from_str::<ReceiptDisclosure>(&duplicate).is_err());
    let duplicate_opening_member = format!(
        r#"{{"schema":"chio.receipt-disclosure.v1","receipt_id":"{RECEIPT_ID}","openings":[{{"salt_ref":"params","salt_ref":"content","salt":"b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA","payload":null}}]}}"#
    );
    assert!(serde_json::from_str::<ReceiptDisclosure>(&duplicate_opening_member).is_err());
}

#[test]
fn delegation_claim_salt_refs_are_accepted() {
    let document = json!({
        "schema": "chio.receipt-disclosure.v1",
        "receipt_id": RECEIPT_ID,
        "openings": [{"salt_ref": "anchor.claims.client_id", "salt": "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA", "payload": "agent"}],
    });
    let decoded = serde_json::from_value::<ReceiptDisclosure>(document).test_unwrap();
    assert_eq!(
        decoded.openings[0].salt_ref.as_str(),
        "anchor.claims.client_id"
    );
}

#[test]
fn disclosure_schema_examples_decode_as_the_schema_says() {
    let examples = repo_path("spec/schemas/chio-wire/v1/root_authority/examples");
    let valid =
        read_json("spec/schemas/chio-wire/v1/root_authority/examples/valid/disclosure.json");
    serde_json::from_value::<ReceiptDisclosure>(valid).test_unwrap();
    let mut refused = 0;
    for entry in std::fs::read_dir(examples.join("invalid")).test_unwrap() {
        let path = entry.test_unwrap().path();
        let name = path
            .file_name()
            .test_unwrap()
            .to_string_lossy()
            .into_owned();
        if !name.starts_with("disclosure.") {
            continue;
        }
        let text = std::fs::read_to_string(&path).test_unwrap();
        assert!(
            serde_json::from_str::<ReceiptDisclosure>(&text).is_err(),
            "{name} decoded"
        );
        refused += 1;
    }
    assert_eq!(refused, 7);
}

fn verdict(text: &str) -> FieldVerdict {
    match text {
        "verified" => FieldVerdict::Verified,
        "rejected" => FieldVerdict::Rejected,
        "unverifiable" => FieldVerdict::Unverifiable,
        other => panic!("unknown verdict {other}"),
    }
}

/// The vector content preimage as the caller's own output: a stream is a run of lowercase hex
/// chunk digests, an empty preimage is an empty output, anything else is a canonical value.
fn own_output(bytes: &[u8]) -> (Option<Value>, Vec<[u8; 32]>) {
    let text = std::str::from_utf8(bytes).test_unwrap();
    let is_stream = !text.is_empty()
        && text.len() % 64 == 0
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if is_stream {
        let chunks = text
            .as_bytes()
            .chunks(64)
            .map(|chunk| {
                let mut digest = [0_u8; 32];
                hex::decode_to_slice(chunk, &mut digest).test_unwrap();
                digest
            })
            .collect();
        return (None, chunks);
    }
    if text.is_empty() {
        return (None, Vec::new());
    }
    (Some(serde_json::from_str(text).test_unwrap()), Vec::new())
}

#[test]
fn opener_reproduces_committed_vectors() {
    let vectors = read_json("tests/bindings/vectors/receipt/committed/v1.json");
    let cases = vectors["cases"].as_array().test_unwrap();
    let mut opened = 0;
    for case in cases {
        let id = case["id"].as_str().test_unwrap();
        let receipt = &case["receipt"];
        let params: ReceiptCommitment =
            serde_json::from_value(receipt["action"]["parameter_commitment"].clone()).test_unwrap();
        let content: ReceiptCommitment =
            serde_json::from_value(receipt["content_commitment"].clone()).test_unwrap();
        let own_parameters: Value = serde_json::from_str(
            case["preimages"]["parameters_canonical"]
                .as_str()
                .test_unwrap(),
        )
        .test_unwrap();
        let preimage = hex::decode(
            case["preimages"]["content_preimage_hex"]
                .as_str()
                .test_unwrap(),
        )
        .test_unwrap();
        let (value, chunks) = own_output(&preimage);
        let own_output = match (&value, chunks.is_empty()) {
            (Some(value), _) => ContentPreimage::Value(value),
            (None, false) => ContentPreimage::Stream(&chunks),
            (None, true) => ContentPreimage::Empty,
        };
        assert_eq!(own_output.to_bytes().test_unwrap(), preimage, "{id}");
        let actual = match serde_json::from_value::<ReceiptDisclosure>(case["disclosure"].clone()) {
            Ok(document) => open_commitments(
                receipt["id"].as_str().test_unwrap(),
                &params,
                &content,
                &document,
                Some(&own_parameters),
                Some(own_output),
            ),
            Err(_) => report(FieldVerdict::Rejected, FieldVerdict::Rejected, false),
        };
        let expected = &case["expected"];
        assert_eq!(
            actual.parameters,
            verdict(expected["parameters"].as_str().test_unwrap()),
            "{id}"
        );
        assert_eq!(
            actual.content,
            verdict(expected["content"].as_str().test_unwrap()),
            "{id}"
        );
        if case.get("delegation_context").is_none() {
            assert_eq!(
                Value::Bool(actual.disclosure_valid),
                expected["disclosure_valid"],
                "{id}"
            );
        }
        opened += 1;
    }
    assert_eq!(opened, cases.len());
    assert!(cases
        .iter()
        .any(|case| case["id"] == "salt_noncanonical_tail"));
}
