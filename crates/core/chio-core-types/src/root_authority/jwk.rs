//! Public JSON Web Keys and the admitted JWS algorithms.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::wire::{check_items, validated_struct, Base64Text, Base64UrlText, Identifier, Uri};
use super::RootAuthorityShapeError;

/// Asymmetric JWS algorithms. `none` and the HMAC algorithms are never admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum JwsAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    ES512,
    EdDSA,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwkKeyType {
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "EC")]
    Ec,
    #[serde(rename = "OKP")]
    Okp,
}

impl JwkKeyType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::Ec => "EC",
            Self::Okp => "OKP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwkCurve {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
    Ed25519,
}

/// The only admitted `use` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwkUse {
    #[serde(rename = "sig")]
    Sig,
}

validated_struct! {
    /// A public JSON Web Key. Private key members are not admitted.
    ///
    /// `RSA` keys carry `n` and `e` and no curve members; `EC` keys carry a
    /// NIST curve, `x` and `y`; `OKP` keys carry `Ed25519` and `x` only.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct Jwk {
        pub kid: Identifier,
        pub kty: JwkKeyType,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alg: Option<JwsAlgorithm>,
        #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
        pub key_use: Option<JwkUse>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub n: Option<Base64UrlText<1400>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub e: Option<Base64UrlText<16>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub crv: Option<JwkCurve>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub x: Option<Base64UrlText<128>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub y: Option<Base64UrlText<128>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub x5c: Option<Vec<Base64Text<16384>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub x5t: Option<Base64UrlText<64>>,
        #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
        pub x5t_s256: Option<Base64UrlText<64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<Uri>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cloud_instance_name: Option<Identifier>,
    }
}

impl Jwk {
    pub fn validate(&self) -> Result<(), RootAuthorityShapeError> {
        if let Some(chain) = &self.x5c {
            check_items("x5c", chain.len(), 0, 8)?;
        }
        let kind = self.kty.as_str();
        let required = |field: &'static str, present: bool| {
            if present {
                Ok(())
            } else {
                Err(RootAuthorityShapeError::RequiredFor { field, kind })
            }
        };
        let forbidden = |field: &'static str, present: bool| {
            if present {
                Err(RootAuthorityShapeError::ForbiddenFor { field, kind })
            } else {
                Ok(())
            }
        };
        let curve_admitted = |admitted: bool| {
            if admitted {
                Ok(())
            } else {
                Err(RootAuthorityShapeError::NotAdmittedFor { field: "crv", kind })
            }
        };
        match self.kty {
            JwkKeyType::Rsa => {
                required("n", self.n.is_some())?;
                required("e", self.e.is_some())?;
                forbidden("crv", self.crv.is_some())?;
                forbidden("x", self.x.is_some())?;
                forbidden("y", self.y.is_some())?;
            }
            JwkKeyType::Ec => {
                required("crv", self.crv.is_some())?;
                required("x", self.x.is_some())?;
                required("y", self.y.is_some())?;
                forbidden("n", self.n.is_some())?;
                forbidden("e", self.e.is_some())?;
                curve_admitted(self.crv != Some(JwkCurve::Ed25519))?;
            }
            JwkKeyType::Okp => {
                required("crv", self.crv.is_some())?;
                required("x", self.x.is_some())?;
                forbidden("n", self.n.is_some())?;
                forbidden("e", self.e.is_some())?;
                forbidden("y", self.y.is_some())?;
                curve_admitted(self.crv == Some(JwkCurve::Ed25519))?;
            }
        }
        Ok(())
    }
}
