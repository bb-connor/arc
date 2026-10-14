//! Recovery's canonical intake and domain framing. No runtime or execution owner.
#![forbid(unsafe_code)]

mod decode;
mod domains;
mod explanation;
mod preflight;

pub use decode::{
    decode_contract, decode_contract_with_limits, decode_recovery_capability, RecoveryDecodeLimits,
};
pub use domains::{RecoveryDigestDomain, RECOVERY_DIGEST_DOMAINS};
pub use explanation::*;
mod semantic;
pub use semantic::*;
mod authority;
pub use authority::*;
mod disclosure_grant;
pub use disclosure_grant::SignedDisclosureGrant;

mod confinement;
mod knowledge;
pub use confinement::*;
pub use knowledge::*;
mod product;
pub use product::*;
