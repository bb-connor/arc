//! Candidate decoy presentations carried in tool-call arguments.

use std::collections::BTreeSet;

use chio_security_types::ports::TripwireKind;
use serde_json::Value;

/// Most detector lookups one call's arguments may require. A call needing more
/// is refused rather than scanned partially.
pub(super) const MAX_ARGUMENT_LOOKUPS: usize = 4_096;
/// Longest string value scanned as a candidate.
const MAX_CANDIDATE_BYTES: usize = 4_096;
const SURFACES: [TripwireKind; 4] = [
    TripwireKind::CredentialArtifact,
    TripwireKind::FileMarker,
    TripwireKind::BrowserCookie,
    TripwireKind::InternalHostname,
];

/// Every argument string value whole, the token of a `scheme token` value
/// such as an Authorization header, each cookie pair and its value, and each
/// URL or bare host. Returns `None` when the arguments need more than
/// [`MAX_ARGUMENT_LOOKUPS`] lookups.
pub(super) fn argument_candidates(arguments: &Value) -> Option<Vec<(TripwireKind, Vec<u8>)>> {
    let mut candidates = BTreeSet::new();
    let mut pending = vec![arguments];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) => {
                string_candidates(text, &mut candidates);
                if candidates.len() > MAX_ARGUMENT_LOOKUPS {
                    return None;
                }
            }
            Value::Array(items) => pending.extend(items),
            Value::Object(fields) => pending.extend(fields.values()),
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Some(
        candidates
            .into_iter()
            .filter_map(|(surface, text)| {
                SURFACES.get(surface).map(|kind| (*kind, text.into_bytes()))
            })
            .collect(),
    )
}

fn string_candidates(text: &str, candidates: &mut BTreeSet<(usize, String)>) {
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_CANDIDATE_BYTES {
        return;
    }
    let mut add = |kind: TripwireKind, candidate: &str| {
        let candidate = candidate.trim();
        if let (false, Some(surface)) = (
            candidate.is_empty(),
            SURFACES.iter().position(|surface| *surface == kind),
        ) {
            candidates.insert((surface, candidate.to_owned()));
        }
    };
    add(TripwireKind::CredentialArtifact, text);
    add(TripwireKind::FileMarker, text);
    if let Some((scheme, token)) = text.split_once(' ') {
        if !scheme.is_empty()
            && scheme.bytes().all(|byte| byte.is_ascii_alphanumeric())
            && !token.trim().contains(char::is_whitespace)
        {
            add(TripwireKind::CredentialArtifact, token);
        }
    }
    if text.contains('=') {
        add(TripwireKind::BrowserCookie, text);
        for pair in text.split(';') {
            add(TripwireKind::BrowserCookie, pair);
            if let Some((_, value)) = pair.split_once('=') {
                add(TripwireKind::BrowserCookie, value);
            }
        }
    }
    if let Some(host) = url_host(text) {
        add(TripwireKind::InternalHostname, &host);
    } else if is_bare_host(text) {
        add(TripwireKind::InternalHostname, &text.to_ascii_lowercase());
    }
}

fn url_host(text: &str) -> Option<String> {
    let (_, rest) = text.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split(']').next()?
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => host,
            _ => host_port,
        }
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn is_bare_host(text: &str) -> bool {
    text.len() <= 253
        && text.contains('.')
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(candidates: &[(TripwireKind, Vec<u8>)], kind: TripwireKind, text: &str) -> bool {
        candidates
            .iter()
            .any(|(candidate_kind, bytes)| *candidate_kind == kind && bytes == text.as_bytes())
    }

    #[test]
    fn extraction_covers_headers_cookies_and_hosts() {
        let candidates = argument_candidates(&serde_json::json!({
            "auth": "Bearer secret-token",
            "cookie": "a=1; session=value-2",
            "url": "https://user@Build.Internal:8443/path?q=1",
            "host": "db.internal",
            "ipv6": "http://[fd00::1]:80/",
        }))
        .unwrap_or_default();
        assert!(contains(
            &candidates,
            TripwireKind::CredentialArtifact,
            "secret-token"
        ));
        assert!(contains(
            &candidates,
            TripwireKind::BrowserCookie,
            "value-2"
        ));
        assert!(contains(
            &candidates,
            TripwireKind::BrowserCookie,
            "session=value-2"
        ));
        assert!(contains(
            &candidates,
            TripwireKind::InternalHostname,
            "build.internal"
        ));
        assert!(contains(
            &candidates,
            TripwireKind::InternalHostname,
            "db.internal"
        ));
        assert!(contains(
            &candidates,
            TripwireKind::InternalHostname,
            "fd00::1"
        ));
    }

    #[test]
    fn arguments_beyond_the_lookup_bound_are_refused() {
        let values: Vec<Value> = (0..MAX_ARGUMENT_LOOKUPS)
            .map(|index| Value::String(format!("value-{index}")))
            .collect();
        assert!(argument_candidates(&Value::Array(values)).is_none());
    }
}
