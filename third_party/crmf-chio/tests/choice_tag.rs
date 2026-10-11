use crmf::pop::EncKeyWithIdChoice;
use der::{
    asn1::{Ia5String, OctetString, Utf8StringRef},
    Decode, Encode,
};
use x509_cert::{ext::pkix::name::GeneralName, name::Name};

#[test]
fn general_names_round_trip_with_their_wire_tags() {
    let cases = [
        (
            GeneralName::DnsName(Ia5String::new("audit.invalid").unwrap()),
            0x82,
        ),
        (
            GeneralName::Rfc822Name(Ia5String::new("audit@example.invalid").unwrap()),
            0x81,
        ),
        (
            GeneralName::UniformResourceIdentifier(
                Ia5String::new("https://example.invalid/").unwrap(),
            ),
            0x86,
        ),
        (
            GeneralName::IpAddress(OctetString::new([192, 0, 2, 1]).unwrap()),
            0x87,
        ),
        (
            GeneralName::DirectoryName("CN=Audit".parse::<Name>().unwrap()),
            0xa4,
        ),
    ];
    for (name, wire_tag) in cases {
        let choice = EncKeyWithIdChoice::GeneralName(name);
        let encoded = choice.to_der().unwrap();
        assert_eq!(encoded[0], wire_tag);
        assert_eq!(EncKeyWithIdChoice::from_der(&encoded).unwrap(), choice);
    }
}

#[test]
fn utf8_alternative_round_trips_and_unrelated_tag_rejects() {
    let choice = EncKeyWithIdChoice::String(Utf8StringRef::new("audit").unwrap());
    let encoded = choice.to_der().unwrap();
    assert_eq!(encoded, b"\x0c\x05audit");
    assert_eq!(EncKeyWithIdChoice::from_der(&encoded).unwrap(), choice);
    assert!(EncKeyWithIdChoice::from_der(b"\x02\x01\x01").is_err());
}
