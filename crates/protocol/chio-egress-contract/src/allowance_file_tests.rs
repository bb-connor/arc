use std::io::Write;
use std::path::Path;

use crate::{
    EgressAllowanceSet, PrivateNetworkAllowance, PrivateNetworkAllowanceError,
    MAX_EGRESS_ALLOWANCE_FILE_BYTES,
};

fn written(text: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(text).expect("write");
    file.flush().expect("flush");
    file
}

fn load(
    text: &str,
) -> (
    Result<EgressAllowanceSet, PrivateNetworkAllowanceError>,
    String,
) {
    let file = written(text.as_bytes());
    let path = file.path().display().to_string();
    (EgressAllowanceSet::load_file(file.path()), path)
}

#[test]
fn allowance_file_loads_every_entry() {
    let (loaded, _) = load(
        "[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"10.20.0.0/24\"\n\n\
         [[allow]]\nhost = \"10.20.0.5\"\nport = 8443\ncidr = \"10.20.0.5/32\"\n",
    );
    let expected = EgressAllowanceSet::new([
        PrivateNetworkAllowance {
            host: "control.vpc.internal".to_string(),
            port: 9443,
            cidr: "10.20.0.0/24".parse().expect("cidr"),
        },
        PrivateNetworkAllowance {
            host: "10.20.0.5".to_string(),
            port: 8443,
            cidr: "10.20.0.5/32".parse().expect("cidr"),
        },
    ])
    .expect("set");
    assert_eq!(loaded, Ok(expected));
}

#[test]
fn empty_allow_list_loads_as_the_empty_set() {
    let (loaded, _) = load("allow = []\n");
    assert_eq!(loaded, Ok(EgressAllowanceSet::default()));
}

#[test]
fn unknown_keys_are_refused() {
    let (loaded, path) = load("allowPrivate = true\nallow = []\n");
    assert_eq!(
        loaded,
        Err(PrivateNetworkAllowanceError::FileInvalid {
            path,
            reason: "unknown field `allowPrivate`, expected `allow`".to_string(),
        })
    );
    let (loaded, path) = load(
        "[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"10.20.0.0/24\"\nscheme = \"http\"\n",
    );
    assert_eq!(
        loaded,
        Err(PrivateNetworkAllowanceError::FileInvalid {
            path,
            reason: "unknown field `scheme`, expected one of `host`, `port`, `cidr`".to_string(),
        })
    );
}

#[test]
fn a_file_without_an_allow_list_is_refused() {
    let (loaded, path) = load("");
    assert_eq!(
        loaded,
        Err(PrivateNetworkAllowanceError::FileInvalid {
            path,
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
        assert_eq!(load(&entry(cidr)).0, Err(refusal), "{cidr}");
    }
    let duplicate = format!("{}{}", entry("10.20.0.0/24"), entry("10.21.0.0/24"));
    assert_eq!(
        load(&duplicate).0,
        Err(PrivateNetworkAllowanceError::DuplicateAllowance {
            host: "control.vpc.internal".to_string(),
            port: 9443,
        })
    );
}

#[test]
fn a_file_over_the_ceiling_is_refused() {
    let padding =
        usize::try_from(MAX_EGRESS_ALLOWANCE_FILE_BYTES).expect("ceiling") - "allow = []".len();
    let at_ceiling = format!("allow = []{}", "\n".repeat(padding));
    assert_eq!(at_ceiling.len() as u64, MAX_EGRESS_ALLOWANCE_FILE_BYTES);
    assert_eq!(load(&at_ceiling).0, Ok(EgressAllowanceSet::default()));
    let over = format!("{at_ceiling}\n");
    let (loaded, path) = load(&over);
    assert_eq!(
        loaded,
        Err(PrivateNetworkAllowanceError::FileTooLarge {
            path,
            max_bytes: MAX_EGRESS_ALLOWANCE_FILE_BYTES,
        })
    );
}

#[test]
fn a_missing_file_or_a_directory_is_unreadable() {
    let directory = tempfile::tempdir().expect("dir");
    assert_eq!(
        EgressAllowanceSet::load_file(directory.path()),
        Err(PrivateNetworkAllowanceError::FileUnreadable {
            path: directory.path().display().to_string(),
            reason: "not a regular file".to_string(),
        })
    );
    let missing = directory.path().join("absent.toml");
    let Err(PrivateNetworkAllowanceError::FileUnreadable { path, .. }) =
        EgressAllowanceSet::load_file(&missing)
    else {
        panic!("a missing file must be unreadable");
    };
    assert_eq!(Path::new(&path), missing.as_path());
}

#[test]
fn non_utf8_text_is_unreadable() {
    let file = written(&[0xff, 0xfe, b'\n']);
    assert_eq!(
        EgressAllowanceSet::load_file(file.path()),
        Err(PrivateNetworkAllowanceError::FileUnreadable {
            path: file.path().display().to_string(),
            reason: "file is not UTF-8".to_string(),
        })
    );
}
