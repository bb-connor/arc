use cmpv2::poll::{PollRepContent, PollRepContentInner};
use der::{asn1::Int, Encode};
use hex_literal::hex;

/// Verify that PollRepContent includes the required outer sequence.
#[test]
fn test_encoding() {
    let expected = hex!(
        "30 08
         30 06
         02 01 00
         02 01 3c"
    );
    let prc = PollRepContent(
        [PollRepContentInner {
            cert_req_id: Int::new(&[0]).unwrap(),
            check_after: 60,
            reason: None,
        }]
        .to_vec(),
    );

    let prc_encoded = prc.to_der().unwrap();
    assert_eq!(prc_encoded, expected);
}

#[test]
fn test_indexing() {
    let prc = PollRepContent(
        [PollRepContentInner {
            cert_req_id: Int::new(&[0]).unwrap(),
            check_after: 60,
            reason: None,
        }]
        .to_vec(),
    );
    assert_eq!(prc[0].check_after, 60);
}

#[test]
fn test_from_inner() {
    let inner_content_1 = PollRepContentInner {
        cert_req_id: Int::new(&[1]).unwrap(),
        check_after: 11,
        reason: None,
    };
    let inner_content_2 = PollRepContentInner {
        cert_req_id: Int::new(&[2]).unwrap(),
        check_after: 22,
        reason: None,
    };
    let prc = PollRepContent::from(vec![inner_content_1, inner_content_2]);
    assert_eq!(prc[0].check_after, 11);
    assert_eq!(prc[1].check_after, 22);
}
