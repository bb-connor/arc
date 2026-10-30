use crate::{
    AllowanceScheme, EgressAllowanceSet, PrivateNetworkAllowance, PrivateNetworkAllowanceError,
    MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES,
};

fn parse(text: &str) -> Result<EgressAllowanceSet, PrivateNetworkAllowanceError> {
    EgressAllowanceSet::from_toml_str(text)
}

fn allowance(host: &str, port: u16, scheme: AllowanceScheme, cidr: &str) -> PrivateNetworkAllowance {
    PrivateNetworkAllowance {
        host: host.to_string(),
        port,
        scheme,
        cidr: cidr.parse().expect("cidr"),
    }
}

#[test]
fn every_entry_is_parsed_and_the_scheme_defaults_to_https() {
    let parsed = parse(
        "[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"10.20.0.0/24\"\n\n\
         [[allow]]\nhost = \"10.20.0.5\"\nport = 8443\nscheme = \"http\"\ncidr = \"10.20.0.5/32\"\n",
    );
    let expected = EgressAllowanceSet::new([
        allowance("control.vpc.internal", 9443, AllowanceScheme::Https, "10.20.0.0/24"),
        allowance("10.20.0.5", 8443, AllowanceScheme::Http, "10.20.0.5/32"),
    ])
    .expect("set");
    assert_eq!(parsed, Ok(expected));
}

#[test]
fn an_empty_allow_list_is_the_empty_set() {
    assert_eq!(parse("allow = []\n"), Ok(EgressAllowanceSet::default()));
}

#[test]
fn unknown_keys_are_refused() {
    assert_eq!(
        parse("allowPrivate = true\nallow = []\n"),
        Err(PrivateNetworkAllowanceError::DocumentInvalid {
            reason: "unknown field `allowPrivate`, expected `allow`".to_string(),
        })
    );
    assert_eq!(
        parse(
            "[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"10.20.0.0/24\"\nproxy = \"x\"\n",
        ),
        Err(PrivateNetworkAllowanceError::DocumentInvalid {
            reason: "unknown field `proxy`, expected one of `host`, `port`, `cidr`, `scheme`"
                .to_string(),
        })
    );
}

#[test]
fn an_unnamed_scheme_is_refused() {
    let Err(PrivateNetworkAllowanceError::DocumentInvalid { .. }) = parse(
        "[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"10.20.0.0/24\"\nscheme = \"ftp\"\n",
    ) else {
        panic!("an unknown scheme must be refused");
    };
}

#[test]
fn a_document_without_an_allow_list_is_refused() {
    assert_eq!(
        parse(""),
        Err(PrivateNetworkAllowanceError::DocumentInvalid {
            reason: "missing field `allow`".to_string(),
        })
    );
}

#[test]
fn each_entry_is_validated_with_its_exact_refusal() {
    let entry = |cidr: &str| {
        format!("[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"{cidr}\"\n")
    };
    for (cidr, refusal) in [
        (
            "169.254.0.0/16",
            PrivateNetworkAllowanceError::CidrIncludesReservedAddress {
                cidr: "169.254.0.0/16".to_string(),
                reserved: "169.254.0.0/16".to_string(),
            },
        ),
        (
            "10.0.0.0/8",
            PrivateNetworkAllowanceError::CidrTooBroad {
                cidr: "10.0.0.0/8".to_string(),
                min_prefix: 16,
            },
        ),
        (
            "8.8.8.0/24",
            PrivateNetworkAllowanceError::CidrOutsidePrivateRanges {
                cidr: "8.8.8.0/24".to_string(),
            },
        ),
        (
            "10.20.0.0",
            PrivateNetworkAllowanceError::InvalidCidr {
                cidr: "10.20.0.0".to_string(),
            },
        ),
    ] {
        assert_eq!(parse(&entry(cidr)), Err(refusal), "{cidr}");
    }
    let duplicate = format!("{}{}", entry("10.20.0.0/24"), entry("10.21.0.0/24"));
    assert_eq!(
        parse(&duplicate),
        Err(PrivateNetworkAllowanceError::DuplicateAllowance {
            host: "control.vpc.internal".to_string(),
            port: 9443,
        })
    );
}

#[test]
fn a_document_over_the_ceiling_is_refused() {
    let padding = MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES - "allow = []".len();
    let at_ceiling = format!("allow = []{}", "\n".repeat(padding));
    assert_eq!(at_ceiling.len(), MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES);
    assert_eq!(parse(&at_ceiling), Ok(EgressAllowanceSet::default()));
    assert_eq!(
        parse(&format!("{at_ceiling}\n")),
        Err(PrivateNetworkAllowanceError::DocumentTooLarge {
            max_bytes: MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES,
        })
    );
}
