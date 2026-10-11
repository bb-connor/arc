use cmpv2::body::PkiBody;
use cmpv2::status::{PkiFailureInfo, PkiFailureInfoValues};
use der::{Decode, Encode};

#[test]
fn failure_info_variants_use_rfc_4210_bit_masks() {
    let variants = [
        (PkiFailureInfoValues::BadAlg, 0),
        (PkiFailureInfoValues::BadMessageCheck, 1),
        (PkiFailureInfoValues::BadRequest, 2),
        (PkiFailureInfoValues::BadTime, 3),
        (PkiFailureInfoValues::BadCertId, 4),
        (PkiFailureInfoValues::BadDataFormat, 5),
        (PkiFailureInfoValues::WrongAuthority, 6),
        (PkiFailureInfoValues::IncorrectData, 7),
        (PkiFailureInfoValues::MissingTimeStamp, 8),
        (PkiFailureInfoValues::BadPOP, 9),
        (PkiFailureInfoValues::CertRevoked, 10),
        (PkiFailureInfoValues::CertConfirmed, 11),
        (PkiFailureInfoValues::WrongIntegrity, 12),
        (PkiFailureInfoValues::BadRecipientNonce, 13),
        (PkiFailureInfoValues::TimeNotAvailable, 14),
        (PkiFailureInfoValues::UnacceptedPolicy, 15),
        (PkiFailureInfoValues::UnacceptedExtension, 16),
        (PkiFailureInfoValues::AddInfoNotAvailable, 17),
        (PkiFailureInfoValues::BadSenderNonce, 18),
        (PkiFailureInfoValues::BadCertTemplate, 19),
        (PkiFailureInfoValues::SignerNotTrusted, 20),
        (PkiFailureInfoValues::TransactionIdInUse, 21),
        (PkiFailureInfoValues::UnsupportedVersion, 22),
        (PkiFailureInfoValues::NotAuthorized, 23),
        (PkiFailureInfoValues::SystemUnavail, 24),
        (PkiFailureInfoValues::SystemFailure, 25),
        (PkiFailureInfoValues::DuplicateCertReq, 26),
    ];

    for (variant, position) in variants {
        let failure_info = PkiFailureInfo::from(variant);
        assert_eq!(failure_info.bits(), 1_u32 << position);
        assert_eq!(
            PkiFailureInfo::from_der(&failure_info.to_der().unwrap()).unwrap(),
            failure_info
        );
    }

    let failure_info = PkiFailureInfo::from(PkiFailureInfoValues::BadTime);

    assert_eq!(failure_info.to_der().unwrap(), [0x03, 0x02, 0x04, 0x10]);
}

#[test]
fn poll_request_uses_its_distinct_tag_25_content() {
    let encoded = [0xb9, 0x07, 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x07];
    let body = PkiBody::from_der(&encoded).unwrap();

    let PkiBody::PollReq(content) = &body else {
        panic!("tag 25 did not decode as PollReq");
    };
    assert_eq!(content.cert_req_ids.len(), 1);
    assert_eq!(
        content.cert_req_ids[0].to_der().unwrap(),
        [0x02, 0x01, 0x07]
    );
    assert_eq!(body.to_der().unwrap(), encoded);
}
