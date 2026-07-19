use super::super::super::report_validation::cluster_peer_auth_signature;
use super::super::*;

impl TrustControlClient {
    pub(super) fn build_internal_get_request(
        &self,
        client: &Agent,
        url: &str,
        receiver_id: &str,
        endpoint: &str,
        term: Option<u64>,
        body_digest: &str,
    ) -> Result<ureq::Request, CliError> {
        let cluster_peer_auth = self.cluster_peer_auth.as_ref().ok_or_else(|| {
            CliError::cli_other_error(
                "internal cluster request requires node membership identity".to_string(),
            )
        })?;
        let issued_at = unix_timestamp_now() as i64;
        let nonce = uuid::Uuid::new_v4().to_string();
        let signature = cluster_peer_auth_signature(
            cluster_peer_auth.signing_key.as_ref(),
            cluster_peer_auth.node_id.as_ref(),
            receiver_id,
            "GET",
            endpoint,
            issued_at,
            &nonce,
            term,
            body_digest,
        )?;
        let mut request = client
            .get(url)
            .set(CLUSTER_NODE_ID_HEADER, cluster_peer_auth.node_id.as_ref())
            .set(CLUSTER_AUTH_METHOD_HEADER, "GET")
            .set(CLUSTER_AUTH_ISSUED_AT_HEADER, &issued_at.to_string())
            .set(CLUSTER_AUTH_NONCE_HEADER, &nonce)
            .set(CLUSTER_AUTH_BODY_DIGEST_HEADER, body_digest)
            .set(CLUSTER_AUTH_SIGNATURE_HEADER, &signature);
        if let Some(term) = term {
            request = request.set(CLUSTER_AUTH_TERM_HEADER, &term.to_string());
        }
        Ok(request)
    }

    pub(super) fn build_internal_post_request(
        &self,
        client: &Agent,
        url: &str,
        receiver_id: &str,
        endpoint: &str,
        term: Option<u64>,
        body_digest: &str,
    ) -> Result<ureq::Request, CliError> {
        let cluster_peer_auth = self.cluster_peer_auth.as_ref().ok_or_else(|| {
            CliError::cli_other_error(
                "internal cluster request requires node membership identity".to_string(),
            )
        })?;
        let issued_at = unix_timestamp_now() as i64;
        let nonce = uuid::Uuid::new_v4().to_string();
        let signature = cluster_peer_auth_signature(
            cluster_peer_auth.signing_key.as_ref(),
            cluster_peer_auth.node_id.as_ref(),
            receiver_id,
            "POST",
            endpoint,
            issued_at,
            &nonce,
            term,
            body_digest,
        )?;
        let mut request = client
            .post(url)
            .set(CLUSTER_NODE_ID_HEADER, cluster_peer_auth.node_id.as_ref())
            .set(CLUSTER_AUTH_METHOD_HEADER, "POST")
            .set(CLUSTER_AUTH_ISSUED_AT_HEADER, &issued_at.to_string())
            .set(CLUSTER_AUTH_NONCE_HEADER, &nonce)
            .set(CLUSTER_AUTH_BODY_DIGEST_HEADER, body_digest)
            .set(CLUSTER_AUTH_SIGNATURE_HEADER, &signature);
        if !self.token.is_empty() {
            request = request.set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token));
        }
        if let Some(term) = term {
            request = request.set(CLUSTER_AUTH_TERM_HEADER, &term.to_string());
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_control::report_validation::cluster_empty_body_digest;
    use chio_test_support::prelude::*;

    fn cluster_client(signing_key: Keypair, node_id: &str) -> TrustControlClient {
        TrustControlClient {
            endpoints: Arc::new(vec!["https://node-b.example".to_string()]),
            preferred_index: Arc::new(Mutex::new(0)),
            token: Arc::<str>::from(""),
            http: Agent::new(),
            cluster_peer_auth: Some(ClusterPeerClientAuth {
                node_id: Arc::<str>::from(node_id.to_string()),
                signing_key: Arc::new(signing_key),
            }),
        }
    }

    #[test]
    fn internal_client_signs_method_endpoint_body_term_freshness_and_unique_nonce() {
        let signing_key = Keypair::from_seed(&[0x61; 32]);
        let node_id = "https://node-a.example";
        let client = cluster_client(signing_key.clone(), node_id);
        let endpoint = INTERNAL_ADMISSION_PROPOSAL_PATH;
        let body_digest = sha256_hex(br#"{}"#);

        let first = client
            .build_internal_post_request(
                &client.http,
                "https://node-b.example/v1/internal/admission/proposal",
                "https://node-b.example",
                endpoint,
                Some(17),
                &body_digest,
            )
            .test_unwrap();
        let second = client
            .build_internal_post_request(
                &client.http,
                "https://node-b.example/v1/internal/admission/proposal",
                "https://node-b.example",
                endpoint,
                Some(17),
                &body_digest,
            )
            .test_unwrap();

        assert_eq!(first.header(CLUSTER_NODE_ID_HEADER), Some(node_id));
        assert_eq!(first.header(CLUSTER_AUTH_METHOD_HEADER), Some("POST"));
        assert_eq!(first.header(CLUSTER_AUTH_TERM_HEADER), Some("17"));
        assert_eq!(
            first.header(CLUSTER_AUTH_BODY_DIGEST_HEADER),
            Some(body_digest.as_str())
        );
        assert!(first.header("authorization").is_none());

        let issued_at = first
            .header(CLUSTER_AUTH_ISSUED_AT_HEADER)
            .test_unwrap()
            .parse::<i64>()
            .test_unwrap();
        let nonce = first.header(CLUSTER_AUTH_NONCE_HEADER).test_unwrap();
        let parsed_nonce = uuid::Uuid::parse_str(nonce).test_unwrap();
        assert_eq!(parsed_nonce.get_version_num(), 4);
        assert_ne!(second.header(CLUSTER_AUTH_NONCE_HEADER), Some(nonce));
        let expected_signature = cluster_peer_auth_signature(
            &signing_key,
            node_id,
            "https://node-b.example",
            "POST",
            endpoint,
            issued_at,
            nonce,
            Some(17),
            &body_digest,
        )
        .test_unwrap();
        assert_eq!(
            first.header(CLUSTER_AUTH_SIGNATURE_HEADER),
            Some(expected_signature.as_str())
        );
    }

    #[test]
    fn internal_client_requires_membership_identity() {
        let client = TrustControlClient {
            endpoints: Arc::new(vec!["https://node-b.example".to_string()]),
            preferred_index: Arc::new(Mutex::new(0)),
            token: Arc::<str>::from("leaked-service-bearer"),
            http: Agent::new(),
            cluster_peer_auth: None,
        };
        let error = client
            .build_internal_get_request(
                &client.http,
                "https://node-b.example/v1/internal/cluster/status",
                "https://node-b.example",
                INTERNAL_CLUSTER_STATUS_PATH,
                None,
                &cluster_empty_body_digest(),
            )
            .test_unwrap_err();
        assert!(error
            .to_string()
            .contains("requires node membership identity"));
    }
}
