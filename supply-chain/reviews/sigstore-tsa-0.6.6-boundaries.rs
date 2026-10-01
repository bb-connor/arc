use base64::{engine::general_purpose::STANDARD, Engine};
use cms::{content_info::ContentInfo, signed_data::SignedData};
use der::{asn1::OctetString, Any, Decode, Encode};
use rustls_pki_types::CertificateDer;
use sigstore_tsa::{verify_timestamp_response, VerifyOpts};

fn fixture() -> (Vec<u8>, Vec<u8>, VerifyOpts<'static>) {
    let bundle: serde_json::Value =
        serde_json::from_str(include_str!("test_data/timestamps/valid_bundle.json")).unwrap();
    let root: serde_json::Value =
        serde_json::from_str(include_str!("test_data/timestamps/valid_trusted_root.json")).unwrap();
    let token = STANDARD
        .decode(
            bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]
                ["signedTimestamp"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let signature = STANDARD
        .decode(bundle["messageSignature"]["signature"].as_str().unwrap())
        .unwrap();
    let certs: Vec<_> = root["timestampAuthorities"][0]["certChain"]["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            CertificateDer::from(
                STANDARD
                    .decode(entry["rawBytes"].as_str().unwrap())
                    .unwrap(),
            )
        })
        .collect();
    let opts = VerifyOpts::new()
        .with_root(certs.last().unwrap().clone())
        .with_intermediates(certs[..certs.len() - 1].to_vec());
    (token, signature, opts)
}

fn mutate_cms(token: &[u8], mutate: impl FnOnce(&mut SignedData)) -> Vec<u8> {
    let mut content = match sigstore_tsa::TimeStampResp::from_der(token) {
        Ok(response) => {
            ContentInfo::from_der(&response.time_stamp_token.unwrap().to_der().unwrap()).unwrap()
        }
        Err(_) => ContentInfo::from_der(token).unwrap(),
    };
    let mut signed = SignedData::from_der(&content.content.to_der().unwrap()).unwrap();
    mutate(&mut signed);
    content.content = Any::from_der(&signed.to_der().unwrap()).unwrap();
    content.to_der().unwrap()
}

#[test]
fn valid_timestamp_requires_the_configured_root_and_matching_imprint() {
    let (token, signature, opts) = fixture();
    assert!(verify_timestamp_response(&token, &signature, opts.clone()).is_ok());
    let mut wrong = opts.clone();
    wrong.roots = vec![CertificateDer::from(vec![0x30, 0])];
    assert!(verify_timestamp_response(&token, &signature, wrong).is_err());
    let unrelated: serde_json::Value = serde_json::from_str(include_str!(
        "test_data/timestamps/github_trusted_root.json"
    ))
    .unwrap();
    let unrelated_root = unrelated["timestampAuthorities"][0]["certChain"]["certificates"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["rawBytes"]
        .as_str()
        .unwrap();
    let mut wrong = opts.clone();
    wrong.roots = vec![CertificateDer::from(
        STANDARD.decode(unrelated_root).unwrap(),
    )];
    assert!(verify_timestamp_response(&token, &signature, wrong).is_err());
    let mut modified = signature;
    modified[0] ^= 1;
    assert!(verify_timestamp_response(&token, &modified, opts).is_err());
}

#[test]
fn timestamp_rejects_signed_content_and_signature_substitution() {
    let (token, signature, opts) = fixture();
    let modified = mutate_cms(&token, |signed| {
        let mut info = sigstore_tsa::TstInfo::from_der(
            signed.encap_content_info.econtent.as_ref().unwrap().value(),
        )
        .unwrap();
        info.gen_time = der::asn1::GeneralizedTime::from_unix_duration(
            std::time::Duration::from_secs(1_600_000_000),
        )
        .unwrap();
        let content = OctetString::new(info.to_der().unwrap()).unwrap();
        signed.encap_content_info.econtent =
            Some(Any::from_der(&content.to_der().unwrap()).unwrap());
    });
    assert!(verify_timestamp_response(&modified, &signature, opts.clone()).is_err());
    let modified = mutate_cms(&token, |signed| {
        let mut infos: Vec<_> = signed.signer_infos.0.iter().cloned().collect();
        let mut bytes = infos[0].signature.as_bytes().to_vec();
        bytes[0] ^= 1;
        infos[0].signature = OctetString::new(bytes).unwrap();
        signed.signer_infos.0 = infos.try_into().unwrap();
    });
    assert!(verify_timestamp_response(&modified, &signature, opts).is_err());
}

#[test]
fn empty_roots_are_explicitly_signature_only_and_require_a_caller_trust_check() {
    let (token, signature, _) = fixture();
    // This upstream mode deliberately skips chain and EKU validation. It cannot
    // by itself establish trusted time; the Chio wrapper must reject no authority.
    assert!(verify_timestamp_response(&token, &signature, VerifyOpts::new()).is_ok());
}

#[test]
fn request_nonce_extremes_round_trip_as_unsigned_canonical_der() {
    for nonce in [0, 1, 127, 128, u64::MAX] {
        let request =
            sigstore_tsa::TimeStampReq::new_without_nonce(sigstore_tsa::Asn1MessageImprint::new(
                sigstore_tsa::AlgorithmIdentifier::sha256(),
                vec![1; 32],
            ))
            .with_nonce(nonce);
        let bytes = request.to_der().unwrap();
        let parsed = sigstore_tsa::TimeStampReq::from_der(&bytes).unwrap();
        assert_eq!(parsed, request);
        assert_eq!(parsed.to_der().unwrap(), bytes);
    }
}
