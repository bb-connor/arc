use super::super::super::caller_credentials::{
    PeerRequestTarget, CLUSTER_AUTH_BODY_SHA256_HEADER, CLUSTER_AUTH_NONCE_HEADER,
};
use chio_egress_contract::{BlockingContractAgent, BlockingContractRequest};

use super::super::*;
use super::factory::egress_refusal;

impl TrustControlClient {
    /// A GET to a peer's internal listener, signed with this node's key for
    /// that peer. `request_path` is the path and raw query exactly as sent.
    pub(super) fn build_internal_get_request(
        &self,
        client: &BlockingContractAgent,
        url: &str,
        request_path: &str,
        term: Option<u64>,
    ) -> Result<BlockingContractRequest, CliError> {
        let cluster_peer_auth = self.cluster_peer_auth.as_ref().ok_or_else(|| {
            CliError::cli_other_error(
                "internal trust-control routes require a cluster peer client".to_owned(),
            )
        })?;
        let (path, query) = request_path.split_once('?').unwrap_or((request_path, ""));
        let issued_at = i64::try_from(unix_timestamp_now()?).map_err(|_| {
            CliError::cli_other_error("clock exceeds signed timestamp field".to_owned())
        })?;
        let mut nonce = [0_u8; 32];
        rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, &mut nonce).map_err(|error| {
            CliError::cli_other_error(format!("cluster peer nonce generation failed: {error}"))
        })?;
        let target = PeerRequestTarget {
            method: "GET",
            path,
            query,
            body: b"",
        };
        let (node_id, signed) = cluster_peer_auth
            .access
            .sign_peer_request(
                &cluster_peer_auth.recipient,
                &target,
                &nonce,
                issued_at,
                term,
            )
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let mut request = client
            .get(url)
            .map_err(egress_refusal)?
            .header(CLUSTER_NODE_ID_HEADER, &node_id)
            .header(CLUSTER_AUTH_ISSUED_AT_HEADER, &issued_at.to_string())
            .header(CLUSTER_AUTH_SIGNATURE_HEADER, &signed.signature)
            .header(CLUSTER_AUTH_NONCE_HEADER, &signed.nonce)
            .header(CLUSTER_AUTH_BODY_SHA256_HEADER, &signed.body_sha256);
        if let Some(term) = term {
            request = request.header(CLUSTER_AUTH_TERM_HEADER, &term.to_string());
        }
        Ok(request)
    }
}
