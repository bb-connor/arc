// Run as an additional integration target against the checksum-verified archive.
use sigstore_types::{pae, Checkpoint, LogIndex, Sha256Hash};

#[test]
fn fixed_hash_and_key_hint_lengths_reject_malformed_inputs() {
    for length in 0..=65 {
        let bytes = vec![0_u8; length];
        assert_eq!(Sha256Hash::try_from_slice(&bytes).is_ok(), length == 32);
        assert_eq!(
            sigstore_types::KeyHint::try_from_slice(&bytes).is_ok(),
            length == 4
        );
    }
    for invalid in ["", "!", "AA==", "AAAA", "0", "gg"] {
        assert!(Sha256Hash::from_hex_or_base64(invalid).is_err());
    }
}

#[test]
fn pae_binds_utf8_type_and_binary_payload_without_ambiguity() {
    let mut expected = b"DSSEv1 2 ".to_vec();
    expected.extend_from_slice("é".as_bytes());
    expected.extend_from_slice(b" 4 \0 \xff\n");
    assert_eq!(pae("é", b"\0 \xff\n"), expected);
    assert_ne!(pae("a", b"b c"), pae("a b", b"c"));
    assert_eq!(pae("", b""), b"DSSEv1 0  0 ");
}

#[test]
fn integer_conversion_requires_the_checked_unsigned_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    for encoded in [
        "-1",
        "\"-1\"",
        "9223372036854775808",
        "18446744073709551615",
    ] {
        let index: LogIndex = serde_json::from_str(encoded)?;
        assert_eq!(index.as_u64(), None);
    }
    let maximum: LogIndex = serde_json::from_str("9223372036854775807")?;
    assert_eq!(maximum.as_u64(), Some(i64::MAX as u64));
    assert!(serde_json::from_str::<LogIndex>("\"9223372036854775808\"").is_err());
    assert!(serde_json::from_str::<LogIndex>("1.5").is_err());
    Ok(())
}

#[test]
fn checkpoint_verification_bytes_preserve_the_original_body(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = Sha256Hash::from_bytes([7_u8; 32]).to_base64();
    let body = format!(" log.example \n0001\n{root}\n metadata \n");
    let envelope = format!("{body}\n\u{2014} log.example AQIDBAU=\n");
    let checkpoint = Checkpoint::from_text(&envelope)?;
    assert_eq!(checkpoint.signed_data(), body.as_bytes());
    assert_ne!(
        checkpoint.signed_data(),
        checkpoint.to_signed_note_body().as_bytes()
    );
    assert_eq!(checkpoint.tree_size, 1);

    // JSON is a data representation, not a replacement for the signed note.
    let decoded: Checkpoint = serde_json::from_str(&serde_json::to_string(&checkpoint)?)?;
    assert!(decoded.signed_data().is_empty());
    Ok(())
}

#[test]
fn malformed_checkpoint_components_reject() {
    let root = Sha256Hash::from_bytes([7_u8; 32]).to_base64();
    for body in [
        String::new(),
        format!("log.example\n1\n{root}\n"),
        format!("log.example\n-1\n{root}\n\n\u{2014} signer AQIDBAU=\n"),
        "log.example\n1\nAA==\n\n\u{2014} signer AQIDBAU=\n".to_owned(),
        format!("log.example\n1\n{root}\n\n- signer AQIDBAU=\n"),
        format!("log.example\n1\n{root}\n\n\u{2014} signer AQIDBA==\n"),
    ] {
        assert!(Checkpoint::from_text(&body).is_err());
    }
}
