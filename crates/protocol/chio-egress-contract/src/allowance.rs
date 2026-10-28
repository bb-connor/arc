//! Operator-declared private network allowances.
//!
//! An allowance names one `host:port` and the CIDR its resolved addresses must
//! fall inside. It is the only way a contract reaches a private address, and
//! it never reaches link-local or cloud metadata addresses.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::{Host, Url};

use crate::HttpEgressError;

/// Schema tag bound into [`private_network_allowance_digest`].
pub const PRIVATE_NETWORK_ALLOWANCE_DIGEST_SCHEMA: &str =
    "chio.egress.private-network-allowance.v1";

/// Digest of an empty allowance set.
pub const EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST: &str =
    "a415a53243de0cb9bd018c68795dbb13cdc3f0efc3e1ef803b9103bb61a01d38";

/// Narrowest IPv4 prefix length an allowance may declare.
pub const MIN_IPV4_ALLOWANCE_PREFIX: u8 = 16;

/// Narrowest IPv6 prefix length an allowance may declare.
pub const MIN_IPV6_ALLOWANCE_PREFIX: u8 = 48;

/// An IP network in canonical form: host bits are zero and IPv4 networks are
/// written in dotted form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    #[must_use]
    pub fn network(&self) -> IpAddr {
        self.network
    }

    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `address` lies inside this network. An IPv4-mapped IPv6
    /// address is compared as its IPv4 address.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, canonical_ip(address)) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                masked_v4(address, self.prefix) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                masked_v6(address, self.prefix) == u128::from(network)
            }
            _ => false,
        }
    }

    fn is_within(&self, outer: &Self) -> bool {
        self.prefix >= outer.prefix && outer.contains(self.network)
    }

    fn intersects(&self, other: &Self) -> bool {
        self.is_within(other) || other.is_within(self)
    }

    fn is_host(&self) -> bool {
        match self.network {
            IpAddr::V4(_) => self.prefix == 32,
            IpAddr::V6(_) => self.prefix == 128,
        }
    }

    const fn v4(octets: [u8; 4], prefix: u8) -> Self {
        Self {
            network: IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
            prefix,
        }
    }

    const fn v6(segments: [u16; 8], prefix: u8) -> Self {
        Self {
            network: IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )),
            prefix,
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

impl FromStr for IpCidr {
    type Err = PrivateNetworkAllowanceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || PrivateNetworkAllowanceError::InvalidCidr {
            cidr: value.to_string(),
        };
        let (network, prefix) = value.split_once('/').ok_or_else(invalid)?;
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        if prefix.len() > 1 && prefix.starts_with('0') {
            return Err(invalid());
        }
        let prefix = prefix.parse::<u8>().map_err(|_| invalid())?;
        let network = network.parse::<IpAddr>().map_err(|_| invalid())?;
        let canonical = match network {
            IpAddr::V4(address) => {
                if prefix > 32 {
                    return Err(invalid());
                }
                masked_v4(address, prefix) == u32::from(address)
            }
            IpAddr::V6(address) => {
                if prefix > 128 {
                    return Err(invalid());
                }
                if address.to_ipv4_mapped().is_some() {
                    return Err(PrivateNetworkAllowanceError::MappedCidr {
                        cidr: value.to_string(),
                    });
                }
                masked_v6(address, prefix) == u128::from(address)
            }
        };
        if !canonical {
            return Err(PrivateNetworkAllowanceError::CidrHostBitsSet {
                cidr: value.to_string(),
            });
        }
        let parsed = Self { network, prefix };
        if parsed.to_string() != value {
            return Err(invalid());
        }
        Ok(parsed)
    }
}

impl Serialize for IpCidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IpCidr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// One declared private destination: requests to `host:port` may resolve
/// only into `cidr`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateNetworkAllowance {
    /// Lowercase DNS name without a trailing dot, or an IP literal (IPv6
    /// without brackets).
    pub host: String,
    pub port: u16,
    pub cidr: IpCidr,
}

/// Why a declared allowance is refused when its contract is loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivateNetworkAllowanceError {
    #[error("allowance host {host:?} is empty or a wildcard")]
    WildcardHost { host: String },
    #[error("allowance host {host:?} is not a normalized host")]
    HostNotNormalized { host: String },
    #[error("allowance {host}:{port} is not an authority of the contract")]
    HostNotInAuthoritySet { host: String, port: u16 },
    #[error("allowance for {host} declares port 0")]
    PortZero { host: String },
    #[error("allowance CIDR {cidr:?} is invalid")]
    InvalidCidr { cidr: String },
    #[error("allowance CIDR {cidr:?} has host bits set")]
    CidrHostBitsSet { cidr: String },
    #[error("allowance CIDR {cidr:?} is IPv4-mapped; write it as IPv4")]
    MappedCidr { cidr: String },
    #[error("allowance CIDR {cidr} is broader than /{min_prefix}")]
    CidrTooBroad { cidr: String, min_prefix: u8 },
    #[error("allowance CIDR {cidr} is not inside a private range")]
    CidrOutsidePrivateRanges { cidr: String },
    #[error("allowance CIDR {cidr} includes the reserved range {reserved}")]
    CidrIncludesReservedAddress { cidr: String, reserved: String },
    #[error("allowance for IP literal {host} must declare exactly {host}")]
    LiteralHostCidrMismatch { host: String, cidr: String },
    #[error("a contract with private network allowances must allow only https")]
    PlaintextScheme,
    #[error("more than one allowance declares {host}:{port}")]
    DuplicateAllowance { host: String, port: u16 },
}

/// Ranges an allowance may open: RFC 1918, RFC 6598 shared address space and
/// IPv6 unique-local.
const UNLOCKABLE_RANGES: [IpCidr; 5] = [
    IpCidr::v4([10, 0, 0, 0], 8),
    IpCidr::v4([172, 16, 0, 0], 12),
    IpCidr::v4([192, 168, 0, 0], 16),
    IpCidr::v4([100, 64, 0, 0], 10),
    IpCidr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
];

/// Ranges no contract reaches: cloud metadata services and link-local.
const RESERVED_RANGES: [IpCidr; 4] = [
    IpCidr::v4([169, 254, 0, 0], 16),
    IpCidr::v4([100, 100, 100, 200], 32),
    IpCidr::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    IpCidr::v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0], 32),
];

/// Cloud metadata endpoints, refused whatever the contract's address-class
/// flags say.
const METADATA_RANGES: [IpCidr; 3] = [
    IpCidr::v4([169, 254, 169, 254], 32),
    IpCidr::v4([100, 100, 100, 200], 32),
    IpCidr::v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0], 32),
];

pub(crate) fn is_metadata_address(address: IpAddr) -> bool {
    let address = canonical_ip(address);
    METADATA_RANGES.iter().any(|range| range.contains(address))
}

pub(crate) fn is_unlockable_address(address: IpAddr) -> bool {
    let address = canonical_ip(address);
    UNLOCKABLE_RANGES
        .iter()
        .any(|range| range.contains(address))
        && !RESERVED_RANGES.iter().any(|range| range.contains(address))
}

pub(crate) fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

/// Validate every allowance against its contract's schemes and authorities.
pub(crate) fn validate_allowances(
    allowances: &BTreeSet<PrivateNetworkAllowance>,
    allowed_schemes: &BTreeSet<String>,
    allowed_authority_set: &BTreeSet<String>,
) -> Result<(), PrivateNetworkAllowanceError> {
    if allowances.is_empty() {
        return Ok(());
    }
    if allowed_schemes.iter().any(|scheme| scheme != "https") {
        return Err(PrivateNetworkAllowanceError::PlaintextScheme);
    }
    let mut seen = BTreeSet::new();
    for allowance in allowances {
        validate_allowance(allowance)?;
        if !seen.insert((allowance.host.as_str(), allowance.port)) {
            return Err(PrivateNetworkAllowanceError::DuplicateAllowance {
                host: allowance.host.clone(),
                port: allowance.port,
            });
        }
        let authority_host = match allowance.host.parse::<Ipv6Addr>() {
            Ok(_) => format!("[{}]", allowance.host),
            Err(_) => allowance.host.clone(),
        };
        let admitted = allowed_authority_set
            .contains(&format!("{authority_host}:{}", allowance.port))
            || (allowance.port == 443 && allowed_authority_set.contains(&authority_host));
        if !admitted {
            return Err(PrivateNetworkAllowanceError::HostNotInAuthoritySet {
                host: allowance.host.clone(),
                port: allowance.port,
            });
        }
    }
    Ok(())
}

fn validate_allowance(
    allowance: &PrivateNetworkAllowance,
) -> Result<(), PrivateNetworkAllowanceError> {
    let host = allowance.host.as_str();
    if host.is_empty() || host.contains('*') || host.starts_with('.') {
        return Err(PrivateNetworkAllowanceError::WildcardHost {
            host: host.to_string(),
        });
    }
    let not_normalized = || PrivateNetworkAllowanceError::HostNotNormalized {
        host: host.to_string(),
    };
    match host.parse::<IpAddr>() {
        Ok(address) => {
            if canonical_ip(address) != address || address.to_string() != host {
                return Err(not_normalized());
            }
            if !(allowance.cidr.is_host() && allowance.cidr.network() == address) {
                return Err(PrivateNetworkAllowanceError::LiteralHostCidrMismatch {
                    host: host.to_string(),
                    cidr: allowance.cidr.to_string(),
                });
            }
        }
        Err(_) => {
            let parsed = Url::parse(&format!("https://{host}/")).map_err(|_| not_normalized())?;
            if parsed.host() != Some(Host::Domain(host)) || host.ends_with('.') {
                return Err(not_normalized());
            }
        }
    }
    if allowance.port == 0 {
        return Err(PrivateNetworkAllowanceError::PortZero {
            host: host.to_string(),
        });
    }
    validate_cidr(&allowance.cidr)
}

fn validate_cidr(cidr: &IpCidr) -> Result<(), PrivateNetworkAllowanceError> {
    let min_prefix = match cidr.network() {
        IpAddr::V4(_) => MIN_IPV4_ALLOWANCE_PREFIX,
        IpAddr::V6(_) => MIN_IPV6_ALLOWANCE_PREFIX,
    };
    if cidr.prefix() < min_prefix {
        return Err(PrivateNetworkAllowanceError::CidrTooBroad {
            cidr: cidr.to_string(),
            min_prefix,
        });
    }
    if let Some(reserved) = RESERVED_RANGES.iter().find(|range| range.intersects(cidr)) {
        return Err(PrivateNetworkAllowanceError::CidrIncludesReservedAddress {
            cidr: cidr.to_string(),
            reserved: reserved.to_string(),
        });
    }
    if !UNLOCKABLE_RANGES.iter().any(|range| cidr.is_within(range)) {
        return Err(PrivateNetworkAllowanceError::CidrOutsidePrivateRanges {
            cidr: cidr.to_string(),
        });
    }
    Ok(())
}

/// Normalized host form used to match an allowance: lowercase DNS name
/// without a trailing dot, dotted IPv4, or IPv6 without brackets.
pub(crate) fn allowance_host(host: &str) -> String {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(address) => canonical_ip(address).to_string(),
        Err(_) => host.trim_end_matches('.').to_ascii_lowercase(),
    }
}

/// SHA-256 over the canonical JSON of the sorted allowance set, tagged with
/// [`PRIVATE_NETWORK_ALLOWANCE_DIGEST_SCHEMA`].
pub fn private_network_allowance_digest(
    allowances: &BTreeSet<PrivateNetworkAllowance>,
) -> Result<String, HttpEgressError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema: &'static str,
        allowances: &'a BTreeSet<PrivateNetworkAllowance>,
    }
    let bytes = chio_core::canonical_json_bytes(&DigestInput {
        schema: PRIVATE_NETWORK_ALLOWANCE_DIGEST_SCHEMA,
        allowances,
    })
    .map_err(|error| {
        HttpEgressError::InvalidContract(format!(
            "private network allowances cannot be canonicalized: {error}"
        ))
    })?;
    Ok(chio_core::sha256_hex(&bytes))
}

fn masked_v4(address: Ipv4Addr, prefix: u8) -> u32 {
    let bits = u32::from(address);
    match prefix {
        0 => 0,
        1..=31 => bits & (u32::MAX << (32 - u32::from(prefix))),
        _ => bits,
    }
}

fn masked_v6(address: Ipv6Addr, prefix: u8) -> u128 {
    let bits = u128::from(address);
    match prefix {
        0 => 0,
        1..=127 => bits & (u128::MAX << (128 - u32::from(prefix))),
        _ => bits,
    }
}
