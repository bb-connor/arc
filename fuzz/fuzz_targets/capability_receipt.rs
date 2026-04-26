#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chio_core::capability::{
    validate_delegation_chain, CapabilityToken, CapabilityTokenBody, ChioScope, Constraint,
    MonetaryAmount, Operation, ToolGrant,
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{
    ChildRequestReceipt, ChioReceipt, ChioReceiptBody, Decision, GuardEvidence, ToolCallAction,
};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 64 * 1024;
const MAX_TEXT_CHARS: usize = 512;
const CAPABILITY_VECTOR_SEEDS: &[&[u8]] = &[
    include_bytes!("../corpus/fuzz_capability_receipt/binding-valid_delegated_capability.json"),
    include_bytes!("../corpus/fuzz_capability_receipt/binding-expired_capability.json"),
    include_bytes!("../corpus/fuzz_capability_receipt/binding-not_yet_valid_capability.json"),
    include_bytes!("../corpus/fuzz_capability_receipt/binding-tampered_capability_signature.json"),
    include_bytes!(
        "../corpus/fuzz_capability_receipt/binding-broken_delegation_chain_signature.json"
    ),
];
const RECEIPT_VECTOR_SEEDS: &[&[u8]] = &[
    include_bytes!("../corpus/fuzz_capability_receipt/binding-allow_receipt.json"),
    include_bytes!("../corpus/fuzz_capability_receipt/binding-deny_receipt.json"),
    include_bytes!(
        "../corpus/fuzz_capability_receipt/binding-signed_receipt_with_invalid_parameter_hash.json"
    ),
    include_bytes!("../corpus/fuzz_capability_receipt/binding-tampered_receipt_signature.json"),
];

#[derive(Arbitrary, Debug)]
struct CapabilityReceiptInput {
    issuer_seed: [u8; 32],
    subject_seed: [u8; 32],
    kernel_seed: [u8; 32],
    id: u32,
    issued_at: u32,
    ttl: u16,
    max_invocations: u8,
    max_cost: u16,
    text: String,
    allow: bool,
    include_metadata: bool,
}

fn trim(input: &str) -> String {
    input.chars().take(MAX_TEXT_CHARS).collect()
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn bool_expected(value: &serde_json::Value, key: &str) -> Option<bool> {
    value
        .get("expected")
        .and_then(|expected| expected.get(key))
        .and_then(|value| value.as_bool())
}

fn string_expected<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value
        .get("expected")
        .and_then(|expected| expected.get(key))
        .and_then(|value| value.as_str())
}

fn u64_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|value| value.as_u64())
}

fn is_exact_seed(data: &[u8], seeds: &[&[u8]]) -> bool {
    seeds.contains(&data)
}

fn capability_time_status(token: &CapabilityToken, now: u64) -> &'static str {
    if token.is_valid_at(now) {
        "valid"
    } else if now < token.issued_at {
        "not_yet_valid"
    } else {
        "expired"
    }
}

fn receipt_decision(receipt: &ChioReceipt) -> &'static str {
    if receipt.is_allowed() {
        "allow"
    } else if receipt.is_denied() {
        "deny"
    } else if receipt.is_cancelled() {
        "cancelled"
    } else if receipt.is_incomplete() {
        "incomplete"
    } else {
        "unknown"
    }
}

fn exercise_capability_token(
    token: &CapabilityToken,
    case: Option<&serde_json::Value>,
    enforce_expected: bool,
) {
    let signature_valid = token.verify_signature().unwrap_or(false);
    if let Some(case) = case.filter(|_| enforce_expected) {
        if let Some(expected) = bool_expected(case, "signature_valid") {
            assert_eq!(signature_valid, expected);
        }
        if let Some(expected) = bool_expected(case, "delegation_chain_valid") {
            let actual = validate_delegation_chain(&token.delegation_chain, None).is_ok();
            assert_eq!(actual, expected);
        }
        if let Some(verify_at) = u64_field(case, "verify_at") {
            if let Some(expected) = bool_expected(case, "time_valid") {
                assert_eq!(token.is_valid_at(verify_at), expected);
                assert_eq!(token.validate_time(verify_at).is_ok(), expected);
            }
            if let Some(expected) = string_expected(case, "time_status") {
                assert_eq!(capability_time_status(token, verify_at), expected);
            }
        }
        if let Some(expected_body) = case
            .get("capability_body_canonical_json")
            .and_then(|value| value.as_str())
        {
            let actual = match chio_core::canonical_json_string(&token.body()) {
                Ok(actual) => actual,
                Err(error) => panic!("capability body should canonicalize: {error}"),
            };
            assert_eq!(actual, expected_body);
        }
    }

    if signature_valid {
        let mut tampered = token.clone();
        tampered.expires_at = tampered.expires_at.saturating_add(1);
        if tampered.expires_at != token.expires_at {
            assert!(matches!(tampered.verify_signature(), Ok(false)));
        }
    }
}

fn exercise_receipt(
    receipt: &ChioReceipt,
    case: Option<&serde_json::Value>,
    enforce_expected: bool,
) {
    let signature_valid = receipt.verify_signature().unwrap_or(false);
    let parameter_hash_valid = receipt.action.verify_hash().unwrap_or(false);

    if let Some(case) = case.filter(|_| enforce_expected) {
        if let Some(expected) = bool_expected(case, "signature_valid") {
            assert_eq!(signature_valid, expected);
        }
        if let Some(expected) = bool_expected(case, "parameter_hash_valid") {
            assert_eq!(parameter_hash_valid, expected);
        }
        if let Some(expected) = string_expected(case, "decision") {
            assert_eq!(receipt_decision(receipt), expected);
        }
        if let Some(expected_body) = case
            .get("receipt_body_canonical_json")
            .and_then(|value| value.as_str())
        {
            let actual = match chio_core::canonical_json_string(&receipt.body()) {
                Ok(actual) => actual,
                Err(error) => panic!("receipt body should canonicalize: {error}"),
            };
            assert_eq!(actual, expected_body);
        }
    }

    if signature_valid {
        let mut policy_tampered = receipt.clone();
        policy_tampered.policy_hash = sha256_hex(b"tampered-policy");
        assert!(matches!(policy_tampered.verify_signature(), Ok(false)));

        let mut tenant_tampered = receipt.clone();
        tenant_tampered.tenant_id = Some("tenant-tampered".to_string());
        assert!(matches!(tenant_tampered.verify_signature(), Ok(false)));
    }
}

fn exercise_child_receipt(receipt: &ChildRequestReceipt) {
    let signature_valid = receipt.verify_signature().unwrap_or(false);
    if signature_valid {
        let mut tampered = receipt.clone();
        tampered.policy_hash = sha256_hex(b"tampered-child-policy");
        assert!(matches!(tampered.verify_signature(), Ok(false)));
    }
}

fn exercise_case(case: &serde_json::Value, enforce_expected: bool) {
    if let Some(capability) = case.get("capability") {
        if let Ok(token) = serde_json::from_value::<CapabilityToken>(capability.clone()) {
            exercise_capability_token(&token, Some(case), enforce_expected);
        }
    }
    if let Some(receipt) = case.get("receipt") {
        if let Ok(receipt) = serde_json::from_value::<ChioReceipt>(receipt.clone()) {
            exercise_receipt(&receipt, Some(case), enforce_expected);
        }
    }
}

fn exercise_value(value: &serde_json::Value, enforce_expected: bool) {
    if let Some(cases) = value.get("cases").and_then(|cases| cases.as_array()) {
        for case in cases {
            exercise_case(case, enforce_expected);
        }
    } else {
        exercise_case(value, enforce_expected);
    }

    if let Some(receipt) = value.get("receipt") {
        if let Ok(receipt) = serde_json::from_value::<ChioReceipt>(receipt.clone()) {
            exercise_receipt(&receipt, None, false);
        }
    }
    if let Ok(receipt) = serde_json::from_value::<ChioReceipt>(value.clone()) {
        exercise_receipt(&receipt, None, false);
    }
    if let Ok(receipt) = serde_json::from_value::<ChildRequestReceipt>(value.clone()) {
        exercise_child_receipt(&receipt);
    }
    if let Ok(token) = serde_json::from_value::<CapabilityToken>(value.clone()) {
        exercise_capability_token(&token, None, false);
    }
    if let Some(grants_json) = value.get("grants_json").and_then(|value| value.as_str()) {
        match serde_json::from_str::<ChioScope>(grants_json) {
            Ok(_scope) => {}
            Err(error) if enforce_expected => {
                panic!("capability lineage grants_json should be a ChioScope: {error}");
            }
            Err(_) => {}
        }
    }
}

fn exercise_raw(data: &[u8]) {
    if data.len() > MAX_RAW_BYTES {
        return;
    }

    let enforce_expected =
        is_exact_seed(data, CAPABILITY_VECTOR_SEEDS) || is_exact_seed(data, RECEIPT_VECTOR_SEEDS);

    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        exercise_value(&value, enforce_expected);
    }

    if let Ok(text) = std::str::from_utf8(data) {
        for line in text.lines().take(128) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                exercise_value(&value, false);
            }
        }
    }
}

fn exercise_generated(input: CapabilityReceiptInput) {
    let issuer = Keypair::from_seed(&input.issuer_seed);
    let subject = Keypair::from_seed(&input.subject_seed);
    let kernel = Keypair::from_seed(&input.kernel_seed);
    let issued_at = u64::from(input.issued_at);
    let expires_at = issued_at + (u64::from(input.ttl) % 86_400) + 1;
    let max_cost = u64::from(input.max_cost) + 1;

    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-fuzz".to_string(),
            tool_name: "fuzz_tool".to_string(),
            operations: vec![Operation::Invoke, Operation::ReadResult],
            constraints: vec![
                Constraint::MaxLength(MAX_TEXT_CHARS),
                Constraint::PathPrefix("/tmp/chio-fuzz".to_string()),
            ],
            max_invocations: Some(u32::from(input.max_invocations) + 1),
            max_cost_per_invocation: Some(usd(max_cost)),
            max_total_cost: Some(usd(max_cost * 2)),
            dpop_required: Some(false),
        }],
        ..ChioScope::default()
    };

    let token_body = CapabilityTokenBody {
        id: format!("cap-fuzz-{}", input.id),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: scope.clone(),
        issued_at,
        expires_at,
        delegation_chain: Vec::new(),
    };
    let token = match CapabilityToken::sign(token_body, &issuer) {
        Ok(token) => token,
        Err(error) => panic!("capability signing should succeed: {error}"),
    };
    assert!(matches!(token.verify_signature(), Ok(true)));

    let encoded = match serde_json::to_vec(&token) {
        Ok(encoded) => encoded,
        Err(error) => panic!("signed capability should serialize: {error}"),
    };
    let restored: CapabilityToken = match serde_json::from_slice(&encoded) {
        Ok(token) => token,
        Err(error) => panic!("signed capability should deserialize: {error}"),
    };
    assert_eq!(token.id, restored.id);
    assert!(matches!(restored.verify_signature(), Ok(true)));

    let mut tampered = restored.clone();
    tampered.expires_at = tampered.expires_at.saturating_add(1);
    if tampered.expires_at != restored.expires_at {
        assert!(matches!(tampered.verify_signature(), Ok(false)));
    }

    let text = trim(&input.text);
    let parameters = serde_json::json!({
        "path": "/tmp/chio-fuzz/input.txt",
        "text": text,
        "maxCost": max_cost,
    });
    let action = match ToolCallAction::from_parameters(parameters.clone()) {
        Ok(action) => action,
        Err(error) => panic!("tool-call action should hash parameters: {error}"),
    };
    assert!(matches!(action.verify_hash(), Ok(true)));

    let decision = if input.allow {
        Decision::Allow
    } else {
        Decision::Deny {
            reason: "fuzz-deny".to_string(),
            guard: "fuzz".to_string(),
        }
    };
    let metadata = input.include_metadata.then(|| {
        serde_json::json!({
            "fuzz": true,
            "capabilityId": token.id,
            "parameterHash": action.parameter_hash,
        })
    });
    let receipt_body = ChioReceiptBody {
        id: format!("rcpt-fuzz-{}", input.id),
        timestamp: issued_at,
        capability_id: token.id.clone(),
        tool_server: "srv-fuzz".to_string(),
        tool_name: "fuzz_tool".to_string(),
        action,
        decision,
        content_hash: sha256_hex(text.as_bytes()),
        policy_hash: sha256_hex(b"fuzz-policy"),
        evidence: vec![GuardEvidence {
            guard_name: "fuzz".to_string(),
            verdict: input.allow,
            details: Some("generated by fuzz target".to_string()),
        }],
        metadata,
        trust_level: Default::default(),
        tenant_id: input.include_metadata.then(|| "tenant-fuzz".to_string()),
        kernel_key: kernel.public_key(),
    };
    let receipt = match ChioReceipt::sign(receipt_body, &kernel) {
        Ok(receipt) => receipt,
        Err(error) => panic!("receipt signing should succeed: {error}"),
    };
    assert!(matches!(receipt.verify_signature(), Ok(true)));
    assert!(matches!(receipt.action.verify_hash(), Ok(true)));

    let encoded = match serde_json::to_vec(&receipt) {
        Ok(encoded) => encoded,
        Err(error) => panic!("signed receipt should serialize: {error}"),
    };
    let restored: ChioReceipt = match serde_json::from_slice(&encoded) {
        Ok(receipt) => receipt,
        Err(error) => panic!("signed receipt should deserialize: {error}"),
    };
    assert_eq!(receipt.id, restored.id);
    assert!(matches!(restored.verify_signature(), Ok(true)));

    let mut tampered = restored.clone();
    tampered.content_hash = sha256_hex(b"tampered");
    if tampered.content_hash != restored.content_hash {
        assert!(matches!(tampered.verify_signature(), Ok(false)));
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_raw(data);

    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = CapabilityReceiptInput::arbitrary(&mut unstructured) {
        exercise_generated(input);
    }
});
