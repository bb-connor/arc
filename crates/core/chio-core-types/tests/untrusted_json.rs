use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Amount {
    amount: u64,
}

#[test]
fn signed_native_input_preserves_the_entire_integer_domain(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = UntrustedJsonText::new("{ \"amount\": 18446744073709551615 }");
    assert_eq!(
        input.decode_signed::<Amount>()?,
        Amount { amount: u64::MAX }
    );
    assert!(matches!(
        input.canonicalize(),
        Err(UntrustedJsonError::Canonicalization(_))
    ));
    Ok(())
}

#[test]
fn ambiguous_signed_tokens_cannot_be_decoded_as_evidence() {
    for input in [
        r#"{"amount":1,"amount":2}"#,
        r#"{"amount":9007199254740991.1}"#,
    ] {
        let error = match UntrustedJsonText::new(input).decode_signed::<Amount>() {
            Err(error) => error,
            Ok(_) => panic!("ambiguous original tokens decoded successfully"),
        };
        assert!(matches!(error, UntrustedJsonError::SignedInput(_)));
        assert_eq!(
            error.code(),
            "urn:chio:error:attest:signed-json-invalid-input"
        );
        assert!(!error.to_string().contains(input));
        assert!(!format!("{error:?}").contains(input));
        assert!(std::error::Error::source(&error).is_some());
    }
}

#[test]
fn canonical_wire_bytes_reject_aliases_and_unknown_fields() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(
        UntrustedJsonText::new(r#"{"amount":4}"#).decode_canonical::<Amount>()?,
        Amount { amount: 4 }
    );
    assert!(matches!(
        UntrustedJsonText::new("{\"amount\": 4}").decode_canonical::<Amount>(),
        Err(UntrustedJsonError::NonCanonical)
    ));
    assert!(matches!(
        UntrustedJsonText::new(r#"{"amount":4,"extra":true}"#).decode_canonical::<Amount>(),
        Err(UntrustedJsonError::Decode(_))
    ));
    Ok(())
}

#[test]
fn bounds_and_utf8_are_checked_before_json_decoding() {
    assert!(matches!(
        UntrustedJsonText::from_wire(b"1234", 3),
        Err(UntrustedJsonError::TooLarge { bytes: 4, bound: 3 })
    ));
    assert!(matches!(
        UntrustedJsonText::from_wire(&[0xff], 1),
        Err(UntrustedJsonError::NotUtf8(_))
    ));
    assert_eq!(
        format!("{:?}", UntrustedJsonText::new("secret")),
        "UntrustedJsonText { bytes: 6 }"
    );
}
