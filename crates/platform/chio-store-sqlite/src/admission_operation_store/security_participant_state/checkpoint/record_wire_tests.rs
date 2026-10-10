//! Exact record bytes and commitment only; native owner/anchor qualification
//! remains in admission_operation_store_tests/security_participant_state.
use super::*;

const BYTES: &[u8] = include_bytes!("fixtures/native-security-checkpoint-v1.json");
const TABLES: &[(&str, &str)] = &[
    (
        "security_declassification_evidence_identity",
        "7a2bf4ad790806a8791b3ceec8c329d58c0ff84b4526c506e12d4003197d58da",
    ),
    (
        "security_declassification_lifecycle",
        "b524a90457d9f46197d05ca5638990f6b756dacc36bd480332eb014562b1ec74",
    ),
    (
        "security_declassification_receipt_outbox",
        "0e531b2275d16147b4dd06f587b11720547bd1441fe1b8f3f416666e0d225088",
    ),
    (
        "security_declassification_tombstones",
        "e039d022f05c3b92d3402ac5ee8b7d27c319b0f11b75ca424aa9ee6c7be92f38",
    ),
    (
        "security_declassification_uses",
        "479bad3d0449c3a359819bc3b3bf063a8dfc1adaa0094b04ff14ee39ff82a0e6",
    ),
    (
        "security_egress_fences",
        "7197e9b1637d0832e08847757ba871ca3b80cd5049199ecd3166e8b75f962481",
    ),
    (
        "security_flow_contexts",
        "db914cacff70ae6af270b6d61d77da99e987c1c772ca7cc77d2a6f2f9356a1d0",
    ),
    (
        "security_flow_sequences",
        "2e21ac172d61f03884112a3062e710d0051e93f56a5d2e3e9019ff1b8ed0ec02",
    ),
    (
        "security_isolation_epochs",
        "91d1040c0129ad5e709f511b21b6fbb605b434163f1542adb4b4ae3ed8f6eefa",
    ),
    (
        "security_lineage_flow_state",
        "8bbed967556ee3bdc7ffe9ae6835ea15bc6ff04f6496cb05c044ba730b1146e5",
    ),
    (
        "security_principal_flow_state",
        "7e824e5d05574e2f9dbc694dc79d9df18ca3cb1b46988f1c9cc68c9bf4c59c9e",
    ),
    (
        "security_session_flow_state",
        "82eb7e1f017a1577949a26dd0ed07f64de2f70c1d92ed8a6110aa0bad1a700dc",
    ),
    (
        "security_session_memberships",
        "d442c4ba18e4907c16c4e54b8346e30549fe4d6436ba6718f296b9baf9be2232",
    ),
    (
        "security_transitions",
        "eb8a0557b09a46b7725ef3a20958a5cb6d39e5dd66110f75996e3fe78ebee244",
    ),
];

fn record() -> Result<Record, AdmissionOperationStoreError> {
    Ok(Record {
        schema: Record::format(),
        authority: AdmissionIdentifier::try_new("authority", "wire-authority")?,
        sequence: 1,
        initialization: "1".repeat(64),
        previous: "1".repeat(64),
        global_sequence: 5,
        global_digest: "2".repeat(64),
        fence: StoreMutationFence {
            store_uuid: "wire-store".into(),
            lease_id: "wire-lease".into(),
            owner_epoch: 3,
        },
        observed_at: 42,
        heads: [1, 0, 0, 0].map(|sequence| FamilyHead {
            sequence,
            digest: "1".repeat(64),
        }),
        tables: TABLES
            .iter()
            .map(|(table, digest)| rows::Fingerprint {
                table: (*table).into(),
                row_count: 0,
                encoded_bytes: 0,
                digest: (*digest).into(),
            })
            .collect(),
        current_rows: 0,
        current_bytes: 0,
        segment_events: 0,
        segment_bytes: 0,
    })
}

#[test]
fn native_security_checkpoint_wire_pins_canonical_record_and_commitment(
) -> Result<(), Box<dyn std::error::Error>> {
    let prepared = record()?;
    assert_eq!(prepared.bytes()?, BYTES);
    assert_eq!(
        prepared.digest()?,
        "78c2f19a58a70219d773e5c14050d94797b1d4c8affb9742a3780582f3039fda"
    );
    let decoded: Record = chio_core::canonical::UntrustedJsonText::from_wire(BYTES, 65_536)
        .and_then(|input| input.decode_signed())?;
    assert_eq!(decoded, prepared);
    assert_eq!(decoded.bytes()?, BYTES);
    Ok(())
}

#[test]
fn native_security_checkpoint_wire_refuses_unknown_record_and_nested_facts(
) -> Result<(), Box<dyn std::error::Error>> {
    for field in ["record", "head", "table"] {
        let mut value: serde_json::Value = serde_json::from_slice(BYTES)?;
        match field {
            "head" => value["heads"][0]["authority"] = serde_json::json!(true),
            "table" => value["tables"][0]["authority"] = serde_json::json!(true),
            _ => value["authority_override"] = serde_json::json!(true),
        }
        let bytes = canonical_json_bytes(&value)?;
        match chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 65_536)
            .and_then(|input| input.decode_signed::<Record>())
        {
            Err(chio_core::canonical::UntrustedJsonError::Decode(error)) => {
                assert_eq!(error.classify(), serde_json::error::Category::Data);
                let expected = if field == "record" {
                    "unknown field `authority_override`, expected "
                } else {
                    "unknown field `authority`, expected "
                };
                assert!(error.to_string().starts_with(expected), "{field}");
            }
            Err(error) => {
                panic!("{field}: unknown checkpoint facts changed error owner: {error:?}")
            }
            Ok(_) => panic!("{field}: checkpoint wire accepted unknown facts"),
        }
    }
    Ok(())
}
