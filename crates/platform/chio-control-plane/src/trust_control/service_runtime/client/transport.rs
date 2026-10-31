use chio_egress_contract::{BlockingContractAgent, BlockingContractStream, HttpEgressError};

use super::super::*;
use super::factory::{egress_refusal, is_transport_failure};
use super::should_retry_status;
use crate::ControlPlaneError;

const JSON: &str = "application/json";
const FORM: &str = "application/x-www-form-urlencoded";

fn json_body<B: Serialize>(body: &B) -> Result<Vec<u8>, CliError> {
    serde_json::to_vec(body).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to serialize trust control request: {error}"
        ))
    })
}

fn status_failure(status: u16, body: String) -> (CliError, bool) {
    (
        CliError::cli_other_error(format!(
            "trust control service request failed with {status}: {body}"
        )),
        !should_retry_status(status),
    )
}

impl TrustControlClient {
    pub(super) fn get_internal_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        self.request_internal_get_json(path, term)
    }

    pub(super) fn get_internal_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &Q,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
            CliError::cli_other_error(format!("failed to encode trust control query: {error}"))
        })?;
        let url = if encoded_query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{encoded_query}")
        };
        self.request_internal_get_json(&url, term)
    }

    pub(super) fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .get(url)?
                    .header(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call_streaming()
            },
            path,
        )
    }

    pub(super) fn public_get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, CliError> {
        self.request_json_without_service_auth(
            |client, url| client.get(url)?.call_streaming(),
            path,
        )
    }

    pub(super) fn public_get_text(&self, path: &str) -> Result<String, CliError> {
        self.request_text_without_service_auth(
            |client, url| client.get(url)?.call_streaming(),
            path,
        )
    }

    pub(super) fn get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<T, CliError> {
        let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
            CliError::cli_other_error(format!("failed to encode trust control query: {error}"))
        })?;
        let url = if encoded_query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{encoded_query}")
        };
        self.request_json(
            |client, base_url, token| {
                client
                    .get(&format!("{base_url}{url}"))?
                    .header(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call_streaming()
            },
            "",
        )
    }

    pub(crate) fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = json_body(body)?;
        self.request_json(
            |client, url, token| {
                client
                    .post(url)?
                    .header(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .header("Content-Type", JSON)
                    .send_bytes_streaming(&json)
            },
            path,
        )
    }

    pub(crate) fn post_json_capped<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
        response_limit: u64,
    ) -> Result<T, CliError> {
        let json = json_body(body)?;
        self.request_json_capped(
            |client, url, token| {
                client
                    .post(url)?
                    .header(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .header("Content-Type", JSON)
                    .send_bytes_streaming(&json)
            },
            path,
            response_limit,
        )
    }

    /// Forward an authority mutation to the leader with the caller's bearer
    /// and the authority term this follower observed.
    pub(crate) fn post_json_forwarding_authority_term<
        B: Serialize,
        T: for<'de> Deserialize<'de>,
    >(
        &self,
        path: &str,
        body: &B,
        term: u64,
    ) -> Result<T, CliError> {
        let json = json_body(body)?;
        let term = term.to_string();
        self.request_json(
            |client, url, token| {
                client
                    .post(url)?
                    .header(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .header(
                        super::super::super::report_validation::FORWARDED_AUTHORITY_TERM_HEADER,
                        &term,
                    )
                    .header("Content-Type", JSON)
                    .send_bytes_streaming(&json)
            },
            path,
        )
    }

    pub(super) fn public_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = json_body(body)?;
        self.request_json_without_service_auth(
            |client, url| {
                client
                    .post(url)?
                    .header("Content-Type", JSON)
                    .send_bytes_streaming(&json)
            },
            path,
        )
    }

    pub(super) fn public_post_form<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &[(&str, &str)],
    ) -> Result<T, CliError> {
        let form = UrlFormSerializer::new(String::new())
            .extend_pairs(body)
            .finish();
        self.request_json_without_service_auth(
            |client, url| {
                client
                    .post(url)?
                    .header("Content-Type", FORM)
                    .send_bytes_streaming(form.as_bytes())
            },
            path,
        )
    }

    pub(super) fn bearer_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        bearer_token: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = json_body(body)?;
        self.request_json_with_bearer(
            |client, url| {
                client
                    .post(url)?
                    .header(AUTHORIZATION.as_str(), &format!("Bearer {bearer_token}"))
                    .header("Content-Type", JSON)
                    .send_bytes_streaming(&json)
            },
            path,
        )
    }

    pub(super) fn put_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = json_body(body)?;
        self.request_json(
            |client, url, token| {
                client
                    .put(url)?
                    .header(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .header("Content-Type", JSON)
                    .send_bytes_streaming(&json)
            },
            path,
        )
    }

    pub(crate) fn delete_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .delete(url)?
                    .header(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call_streaming()
            },
            path,
        )
    }

    /// Try each endpoint in preference order and return the first response
    /// below 400. `on_status` maps an error response to the failure to report
    /// and whether it ends the walk; a transport or name-resolution failure
    /// moves to the next endpoint, and a contract refusal aborts the request.
    fn dispatch<F, S>(
        &self,
        request: F,
        path: &str,
        on_status: S,
        answered_outranks_unreachable: bool,
    ) -> Result<BlockingContractStream, CliError>
    where
        F: Fn(&BlockingContractAgent, &str) -> Result<BlockingContractStream, HttpEgressError>,
        S: Fn(u16, String) -> (CliError, bool),
    {
        let mut answered: Option<CliError> = None;
        let mut unreachable: Option<CliError> = None;
        for index in self.endpoint_order() {
            let url = format!(
                "{}{}",
                self.endpoints
                    .get(index)
                    .ok_or_else(|| CliError::cli_other_error(
                        "endpoint order contains an unknown endpoint".to_owned()
                    ))?,
                path
            );
            match request(&self.http, &url) {
                Ok(response) if response.status() < 400 => {
                    self.mark_preferred(index);
                    return Ok(response);
                }
                Ok(response) => {
                    let status = response.status();
                    let body = response
                        .read_all()
                        .map(|read| String::from_utf8_lossy(read.body()).into_owned())
                        .unwrap_or_default();
                    let (error, stop) = on_status(status, body);
                    if stop {
                        return Err(error);
                    }
                    answered = Some(error);
                }
                Err(error) if is_transport_failure(&error) => {
                    unreachable = Some(CliError::from(ControlPlaneError::Unreachable(
                        error.to_string(),
                    )));
                }
                Err(error) => return Err(egress_refusal(error)),
            }
        }
        let failure = if answered_outranks_unreachable {
            answered.or(unreachable)
        } else {
            unreachable.or(answered)
        };
        Err(failure.unwrap_or_else(|| {
            CliError::cli_other_error(
                "trust control service request failed with no endpoints".to_string(),
            )
        }))
    }

    fn request_internal_get_json<T>(
        &self,
        request_path: &str,
        term: Option<u64>,
    ) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let local = std::cell::RefCell::new(None);
        let response = self.dispatch(
            |client, url| match self.build_internal_get_request(client, url, request_path, term) {
                Ok(request) => request.call_streaming(),
                Err(error) => {
                    *local.borrow_mut() = Some(error);
                    Err(HttpEgressError::MissingAuthority)
                }
            },
            request_path,
            |_, body| (CliError::cli_other_error(body), false),
            false,
        );
        if let Some(error) = local.into_inner() {
            return Err(error);
        }
        let response = response?;
        read_capped_json(response.into_body(), MAX_PEER_RESPONSE_BYTES)
    }

    pub(crate) fn request_json<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(
            &BlockingContractAgent,
            &str,
            &str,
        ) -> Result<BlockingContractStream, HttpEgressError>,
    {
        self.request_json_capped(request, path, MAX_PEER_RESPONSE_BYTES)
    }

    fn request_json_capped<T, F>(
        &self,
        request: F,
        path: &str,
        response_limit: u64,
    ) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(
            &BlockingContractAgent,
            &str,
            &str,
        ) -> Result<BlockingContractStream, HttpEgressError>,
    {
        let response = self.dispatch(
            |client, url| request(client, url, &self.token),
            path,
            |status, body| {
                (
                    CliError::from(ControlPlaneError::from_status(status, body)),
                    !should_retry_status(status),
                )
            },
            true,
        )?;
        read_capped_json(response.into_body(), response_limit)
    }

    fn request_json_without_service_auth<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&BlockingContractAgent, &str) -> Result<BlockingContractStream, HttpEgressError>,
    {
        let response = self.dispatch(request, path, status_failure, false)?;
        read_capped_json(response.into_body(), MAX_PEER_RESPONSE_BYTES)
    }

    pub(crate) fn request_text_without_service_auth<F>(
        &self,
        request: F,
        path: &str,
    ) -> Result<String, CliError>
    where
        F: Fn(&BlockingContractAgent, &str) -> Result<BlockingContractStream, HttpEgressError>,
    {
        let response = self.dispatch(request, path, status_failure, false)?;
        let mut text = String::new();
        std::io::Read::read_to_string(&mut response.into_body(), &mut text).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to decode trust control text response body: {error}"
            ))
        })?;
        Ok(text)
    }

    fn request_json_with_bearer<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&BlockingContractAgent, &str) -> Result<BlockingContractStream, HttpEgressError>,
    {
        self.request_json_without_service_auth(request, path)
    }

    pub(crate) fn endpoint_order(&self) -> Vec<usize> {
        let preferred = match self.preferred_index.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        };
        let total = self.endpoints.len();
        (0..total)
            .map(|offset| (preferred + offset) % total)
            .collect()
    }

    pub(crate) fn mark_preferred(&self, index: usize) {
        match self.preferred_index.lock() {
            Ok(mut guard) => *guard = index,
            Err(poisoned) => *poisoned.into_inner() = index,
        }
    }
}

/// Read at most `cap` bytes from a peer response body and decode as JSON.
/// Reading `cap + 1` and rejecting on overflow bounds the buffer even for a
/// peer that streams forever.
fn read_capped_json<T>(reader: impl std::io::Read, cap: u64) -> Result<T, CliError>
where
    T: for<'de> Deserialize<'de>,
{
    let cap = usize::try_from(cap).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "JSON input bound exceeds platform range",
        )
    })?;
    crate::json_input::read(reader, cap)
}

#[cfg(test)]
mod transport_cap_tests {
    use super::{read_capped_json, MAX_PEER_RESPONSE_BYTES};

    #[test]
    fn read_capped_json_rejects_oversized_body() {
        // A small cap keeps the test cheap; a body one byte over is a typed
        // error, never buffered whole.
        let cap = 16u64;
        let oversized = vec![b' '; (cap + 1) as usize];
        let result: Result<serde_json::Value, _> =
            read_capped_json(std::io::Cursor::new(oversized), cap);
        let Err(error) = result else {
            panic!("oversized body must fail closed");
        };
        assert_eq!(
            error.report().code,
            "urn:chio:error:attest:signed-json-too-large"
        );
    }

    #[test]
    fn read_capped_json_decodes_within_cap() {
        let body = br#"{"ok":true}"#.to_vec();
        let Ok(value) = read_capped_json::<serde_json::Value>(
            std::io::Cursor::new(body),
            MAX_PEER_RESPONSE_BYTES,
        ) else {
            panic!("within-cap body must decode");
        };
        assert_eq!(value["ok"], serde_json::Value::Bool(true));
    }
}
