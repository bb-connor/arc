//! Admit only paths with an unambiguous encoded and decoded route identity.
use super::*;
use std::borrow::Cow;

impl RequestEvaluator {
    pub(super) fn match_route_with_status(
        &self,
        method: HttpMethod,
        path: &str,
    ) -> (String, PolicyDecision, bool) {
        let denied = || (path.to_string(), PolicyDecision::DenyByDefault, false);
        let Some(decoded) = decoded_authority_path(path) else {
            return denied();
        };
        let Some(route) = select_route(&self.routes, method, path) else {
            return denied();
        };
        // Decoding an ordinary parameter is safe only if it still selects the
        // same authority. For example, %61dmin must not hide an exact deny route
        // behind a less restrictive parameter template.
        if !select_route(&self.routes, method, &decoded)
            .is_some_and(|decoded_route| std::ptr::eq(route, decoded_route))
        {
            return denied();
        }
        (route.pattern.clone(), route.policy, true)
    }
}

fn decoded_authority_path(path: &str) -> Option<Cow<'_, str>> {
    if !path.starts_with('/')
        || path.contains("//")
        || !url::Url::parse(&format!("http://chio.invalid{path}")).is_ok_and(|url| {
            url.path() == path && url.query().is_none() && url.fragment().is_none()
        })
    {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    // A remaining percent sign denotes malformed or nested encoding. Refuse
    // decoded separators, dot segments, controls and routing delimiters rather
    // than depend on an upstream's number of decoding/normalization passes.
    if path.bytes().filter(|byte| *byte == b'/').count()
        != decoded.bytes().filter(|byte| *byte == b'/').count()
        || decoded
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '%' | '?' | '#' | ';'))
        || decoded
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return None;
    }
    Some(decoded)
}

fn select_route<'a>(
    routes: &'a [RouteEntry],
    method: HttpMethod,
    path: &str,
) -> Option<&'a RouteEntry> {
    // Exact paths outrank templates. Equally specific overlapping templates
    // select the restrictive policy, independent of document order.
    routes
        .iter()
        .filter(|route| route.method == method && path_matches_pattern(path, &route.pattern))
        .max_by_key(|route| {
            (
                route
                    .pattern
                    .split('/')
                    .filter(|part| !(part.starts_with('{') && part.ends_with('}')))
                    .count(),
                route.policy == PolicyDecision::DenyByDefault,
                &route.pattern,
            )
        })
}
