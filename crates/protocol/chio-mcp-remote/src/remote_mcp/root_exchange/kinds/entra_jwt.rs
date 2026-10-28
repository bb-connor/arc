//! `entra_jwt`: a Microsoft Entra access token presented as a bearer at the
//! edge, or as an RFC 8693 `subject_token` of type
//! `urn:ietf:params:oauth:token-type:jwt`.
//!
//! Pinned to the Microsoft identity platform access token reference for v2
//! tokens: the issuer is `https://login.microsoftonline.com/{tid}/v2.0`
//! (or its sovereign-cloud equivalent), `oid`, `azp`, `appid` and `tid`
//! identify the principal, application and tenant, delegated permissions
//! are the space-delimited `scp` and application permissions the `roles`
//! array, and `uti` is the token identifier.
//!
//! The rule's provider record must name a tenant-specific Entra issuer; the
//! multi-tenant `common`, `organizations` and `consumers` issuers and the
//! `{tenantid}` template are refused when the exchange is built. The
//! principal is the claim the record's `subject_mapping.principal_source`
//! names (`oid` for Entra records). The replay key is `(entra_jwt, issuer,
//! uti)`, so one Entra token yields at most one root, and `uti` is required.
//! The token lifetime is the identity provider's, so no
//! `max_assertion_lifetime_secs` applies.

use chio_core::capability::anchor::AnchorKind;
use chio_core::root_authority::Sha256Digest;
use serde_json::{Map, Value};

use super::super::claims::{push_scope_token, push_space_delimited, required_string};
use super::super::error::RootExchangeError;
use super::super::evidence::AnchorEvidence;
use super::super::exchange::RootExchange;
use super::super::key_lookup::IdpKeyLookup;
use super::bearer_jws::{self, BearerJwsKind};

/// The Microsoft Entra authority hosts of every national cloud, closed: an
/// issuer on any other host is not Entra.
pub const ENTRA_AUTHORITY_HOSTS: [&str; 10] = [
    // Global.
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.windows.net",
    "sts.windows.net",
    // US Government.
    "login.microsoftonline.us",
    "login-us.microsoftonline.com",
    // China, operated by 21Vianet.
    "login.chinacloudapi.cn",
    "login.partner.microsoftonline.cn",
    "sts.chinacloudapi.cn",
    // Germany.
    "login.microsoftonline.de",
];

fn issuer_host(issuer: &str) -> Option<String> {
    url::Url::parse(issuer)
        .ok()?
        .host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
}

/// Whether `issuer` names a Microsoft Entra authority host.
#[must_use]
pub fn is_entra_issuer(issuer: &str) -> bool {
    issuer_host(issuer).is_some_and(|host| ENTRA_AUTHORITY_HOSTS.contains(&host.as_str()))
}

/// `8-4-4-4-12` hexadecimal digits.
fn is_guid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Whether `issuer` is an Entra issuer naming one tenant: its first path
/// segment is the tenant id GUID.
#[must_use]
pub fn is_tenant_specific_issuer(issuer: &str) -> bool {
    is_entra_issuer(issuer)
        && url::Url::parse(issuer).is_ok_and(|url| {
            url.path_segments()
                .and_then(|mut segments| segments.next())
                .is_some_and(is_guid)
        })
}

/// Delegated permissions (`scp`) then application permissions (`roles`).
fn scope_values(claims: &Map<String, Value>) -> Result<Vec<String>, RootExchangeError> {
    let mut values = Vec::new();
    push_space_delimited(claims, "scp", &mut values)?;
    match claims.get("roles") {
        None => {}
        Some(Value::Array(roles)) => {
            for role in roles {
                let role = role
                    .as_str()
                    .ok_or(RootExchangeError::ClaimInvalid("roles"))?;
                push_scope_token(role, "roles", &mut values)?;
            }
        }
        Some(_) => return Err(RootExchangeError::ClaimInvalid("roles")),
    }
    Ok(values)
}

fn replay_id(
    claims: &Map<String, Value>,
    _token_digest: &Sha256Digest,
) -> Result<String, RootExchangeError> {
    required_string(claims, "uti").map(str::to_owned)
}

const ENTRA_JWT: BearerJwsKind = BearerJwsKind {
    kind: AnchorKind::EntraJwt,
    scope_values,
    replay_id,
};

/// Verify the Entra `token` at `now` (Unix seconds).
pub async fn verify(
    exchange: &RootExchange,
    token: &str,
    now: u64,
    keys: &dyn IdpKeyLookup,
) -> Result<AnchorEvidence, RootExchangeError> {
    bearer_jws::verify(exchange, &ENTRA_JWT, token, now, keys).await
}
