use chio_core::{canonical_json_bytes, Keypair, PublicKey, Signature, SigningAlgorithm};
use serde::{Deserialize, Serialize};

use super::paths::AGGREGATE_FAMILY_ROOT_LOOKUP_PATH;

pub(crate) const AGGREGATE_FAMILY_ROOT_LOOKUP_SCHEMA: &str = "chio.aggregate-family-root.lookup.v1";
pub(crate) const AGGREGATE_FAMILY_ROOT_LOOKUP_ENVELOPE_SCHEMA: &str =
    "chio.aggregate-family-root.lookup-envelope.v1";
const AGGREGATE_FAMILY_ROOT_LOOKUP_SIGNATURE_DOMAIN: &str =
    "chio.aggregate-family-root.lookup-envelope.v1\0";
pub(crate) const AGGREGATE_FAMILY_ROOT_LOOKUP_MAX_TTL_SECS: u64 = 30;
// A nested JSON string expands by at most two bytes per canonical token byte.
pub(crate) const AGGREGATE_FAMILY_ROOT_LOOKUP_MAX_BYTES: u64 =
    (chio_store_sqlite::MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES as u64 * 2) + (64 * 1024);
pub(crate) const AGGREGATE_FAMILY_ROOT_ID_MAX_BYTES: usize =
    chio_core::capability::aggregate_budget::MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES;
const AGGREGATE_FAMILY_ROOT_NODE_ID_MAX_BYTES: usize = 4 * 1024;
const AGGREGATE_FAMILY_ROOT_LEASE_ID_MAX_BYTES: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AggregateFamilyRootLookupQuery {
    pub(crate) nonce: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum AggregateFamilyRootReadConsistency {
    Standalone,
    LeaderLocal {
        leader_url: String,
        election_term: u64,
        lease_id: String,
        lease_expires_at: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AggregateFamilyRootCorruptionCode {
    StoreIntegrity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum AggregateFamilyRootLookupOutcome {
    Found {
        source_seq: u64,
        canonical_token_json: String,
        token_digest: String,
    },
    Missing,
    Corrupt {
        code: AggregateFamilyRootCorruptionCode,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AggregateFamilyRootLookupBody {
    pub(crate) schema: String,
    pub(crate) endpoint: String,
    pub(crate) source_node_id: String,
    pub(crate) request_nonce: String,
    pub(crate) requested_root_capability_id: String,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) authority_generation: u64,
    pub(crate) authority_rotated_at: u64,
    pub(crate) consistency: AggregateFamilyRootReadConsistency,
    pub(crate) high_watermark: Option<u64>,
    pub(crate) outcome: AggregateFamilyRootLookupOutcome,
}

impl AggregateFamilyRootLookupBody {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema != AGGREGATE_FAMILY_ROOT_LOOKUP_SCHEMA {
            return Err("aggregate family-root lookup schema mismatch".to_string());
        }
        if self.endpoint != AGGREGATE_FAMILY_ROOT_LOOKUP_PATH {
            return Err("aggregate family-root lookup endpoint mismatch".to_string());
        }
        if self.source_node_id.trim().is_empty()
            || self.source_node_id.len() > AGGREGATE_FAMILY_ROOT_NODE_ID_MAX_BYTES
        {
            return Err(
                "aggregate family-root lookup source node is outside the supported bound"
                    .to_string(),
            );
        }
        validate_lookup_nonce(&self.request_nonce)?;
        if self.requested_root_capability_id.is_empty()
            || self.requested_root_capability_id.len() > AGGREGATE_FAMILY_ROOT_ID_MAX_BYTES
        {
            return Err(
                "aggregate family-root lookup identifier is outside the supported bound"
                    .to_string(),
            );
        }
        let ttl = self.expires_at.checked_sub(self.issued_at).ok_or_else(|| {
            "aggregate family-root lookup expiry is not later than issuance".to_string()
        })?;
        if ttl == 0 || ttl > AGGREGATE_FAMILY_ROOT_LOOKUP_MAX_TTL_SECS {
            return Err(
                "aggregate family-root lookup lifetime is outside the supported bound".to_string(),
            );
        }
        if self.authority_generation == 0 {
            return Err("aggregate family-root lookup authority generation is zero".to_string());
        }
        if let AggregateFamilyRootReadConsistency::LeaderLocal {
            leader_url,
            election_term,
            lease_id,
            lease_expires_at,
        } = &self.consistency
        {
            if leader_url.trim().is_empty()
                || leader_url.len() > AGGREGATE_FAMILY_ROOT_NODE_ID_MAX_BYTES
                || lease_id.trim().is_empty()
                || lease_id.len() > AGGREGATE_FAMILY_ROOT_LEASE_ID_MAX_BYTES
                || *election_term == 0
            {
                return Err("aggregate family-root leader context is incomplete".to_string());
            }
            if self.expires_at > *lease_expires_at {
                return Err("aggregate family-root lookup outlives the leader lease".to_string());
            }
        }
        match (&self.outcome, self.high_watermark) {
            (
                AggregateFamilyRootLookupOutcome::Found {
                    source_seq,
                    canonical_token_json,
                    token_digest,
                },
                Some(high_watermark),
            ) if *source_seq > 0
                && *source_seq <= high_watermark
                && !canonical_token_json.is_empty()
                && canonical_token_json.len()
                    <= chio_store_sqlite::MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES
                && token_digest.len() == 64
                && token_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) => {}
            (AggregateFamilyRootLookupOutcome::Missing, Some(_))
                if matches!(
                    self.consistency,
                    AggregateFamilyRootReadConsistency::Standalone
                ) => {}
            (AggregateFamilyRootLookupOutcome::Corrupt { .. }, _) => {}
            _ => {
                return Err(
                    "aggregate family-root lookup outcome and high-watermark are inconsistent"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignedAggregateFamilyRootLookup {
    pub(crate) schema: String,
    pub(crate) body: AggregateFamilyRootLookupBody,
    pub(crate) signer_public_key: PublicKey,
    pub(crate) algorithm: SigningAlgorithm,
    pub(crate) signature: Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AggregateFamilyRootLookupSigningPayload<'a> {
    schema: &'a str,
    body: &'a AggregateFamilyRootLookupBody,
    signer_public_key: &'a PublicKey,
    algorithm: SigningAlgorithm,
}

impl SignedAggregateFamilyRootLookup {
    pub(crate) fn sign(
        body: AggregateFamilyRootLookupBody,
        keypair: &Keypair,
    ) -> Result<Self, String> {
        body.validate()?;
        let signer_public_key = keypair.public_key();
        let algorithm = signer_public_key.algorithm();
        let signing_bytes =
            aggregate_family_root_lookup_signing_bytes(&body, &signer_public_key, algorithm)?;
        Ok(Self {
            schema: AGGREGATE_FAMILY_ROOT_LOOKUP_ENVELOPE_SCHEMA.to_string(),
            body,
            signer_public_key,
            algorithm,
            signature: keypair.sign(&signing_bytes),
        })
    }

    pub(crate) fn verify_signature(&self, expected_signer: &PublicKey) -> Result<(), String> {
        if self.schema != AGGREGATE_FAMILY_ROOT_LOOKUP_ENVELOPE_SCHEMA {
            return Err("aggregate family-root lookup envelope schema mismatch".to_string());
        }
        self.body.validate()?;
        if &self.signer_public_key != expected_signer {
            return Err(
                "aggregate family-root lookup signer is not the current authority".to_string(),
            );
        }
        if self.algorithm != self.signer_public_key.algorithm()
            || self.algorithm != self.signature.algorithm()
        {
            return Err("aggregate family-root lookup algorithm envelope mismatch".to_string());
        }
        let signing_bytes = aggregate_family_root_lookup_signing_bytes(
            &self.body,
            &self.signer_public_key,
            self.algorithm,
        )?;
        if !self
            .signer_public_key
            .verify(&signing_bytes, &self.signature)
        {
            return Err("aggregate family-root lookup signature is invalid".to_string());
        }
        Ok(())
    }
}

fn aggregate_family_root_lookup_signing_bytes(
    body: &AggregateFamilyRootLookupBody,
    signer_public_key: &PublicKey,
    algorithm: SigningAlgorithm,
) -> Result<Vec<u8>, String> {
    let payload = AggregateFamilyRootLookupSigningPayload {
        schema: AGGREGATE_FAMILY_ROOT_LOOKUP_ENVELOPE_SCHEMA,
        body,
        signer_public_key,
        algorithm,
    };
    let canonical = canonical_json_bytes(&payload).map_err(|error| error.to_string())?;
    let mut bytes =
        Vec::with_capacity(AGGREGATE_FAMILY_ROOT_LOOKUP_SIGNATURE_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(AGGREGATE_FAMILY_ROOT_LOOKUP_SIGNATURE_DOMAIN.as_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

pub(crate) fn validate_lookup_nonce(nonce: &str) -> Result<(), String> {
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "aggregate family-root lookup nonce must be 64 lowercase hex characters".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn lookup_body() -> AggregateFamilyRootLookupBody {
        AggregateFamilyRootLookupBody {
            schema: AGGREGATE_FAMILY_ROOT_LOOKUP_SCHEMA.to_string(),
            endpoint: AGGREGATE_FAMILY_ROOT_LOOKUP_PATH.to_string(),
            source_node_id: "https://trust.example".to_string(),
            request_nonce: "ab".repeat(32),
            requested_root_capability_id: "root-a".to_string(),
            issued_at: 1_000,
            expires_at: 1_030,
            authority_generation: 7,
            authority_rotated_at: 900,
            consistency: AggregateFamilyRootReadConsistency::Standalone,
            high_watermark: Some(4),
            outcome: AggregateFamilyRootLookupOutcome::Missing,
        }
    }

    #[test]
    fn aggregate_family_root_lookup_signature_binds_every_field() {
        let keypair = Keypair::generate();
        let signed = SignedAggregateFamilyRootLookup::sign(lookup_body(), &keypair).test_unwrap();
        signed.verify_signature(&keypair.public_key()).test_unwrap();

        let mut mutations = Vec::new();
        let mut nonce = signed.clone();
        nonce.body.request_nonce = "cd".repeat(32);
        mutations.push(nonce);
        let mut root_id = signed.clone();
        root_id.body.requested_root_capability_id = "root-b".to_string();
        mutations.push(root_id);
        let mut head = signed.clone();
        head.body.high_watermark = Some(5);
        mutations.push(head);
        let mut outcome = signed.clone();
        outcome.body.outcome = AggregateFamilyRootLookupOutcome::Corrupt {
            code: AggregateFamilyRootCorruptionCode::StoreIntegrity,
        };
        mutations.push(outcome);

        for mutation in mutations {
            assert!(mutation.verify_signature(&keypair.public_key()).is_err());
        }
    }

    #[test]
    fn aggregate_family_root_lookup_wire_rejects_unknown_fields() {
        let keypair = Keypair::generate();
        let signed = SignedAggregateFamilyRootLookup::sign(lookup_body(), &keypair).test_unwrap();
        let mut value = serde_json::to_value(signed).test_unwrap();
        value
            .as_object_mut()
            .test_unwrap()
            .insert("unknown".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<SignedAggregateFamilyRootLookup>(value).is_err());
    }

    #[test]
    fn aggregate_family_root_lookup_rejects_leader_local_missing() {
        let mut body = lookup_body();
        body.consistency = AggregateFamilyRootReadConsistency::LeaderLocal {
            leader_url: "https://leader.example".to_string(),
            election_term: 7,
            lease_id: "lease-7".to_string(),
            lease_expires_at: body.expires_at,
        };

        assert!(body.validate().is_err());
    }

    #[test]
    fn aggregate_family_root_lookup_bound_contains_worst_case_nested_token_escaping() {
        let keypair = Keypair::generate();
        let mut body = lookup_body();
        body.source_node_id = "s".repeat(AGGREGATE_FAMILY_ROOT_NODE_ID_MAX_BYTES);
        body.requested_root_capability_id = "r".repeat(AGGREGATE_FAMILY_ROOT_ID_MAX_BYTES);
        body.consistency = AggregateFamilyRootReadConsistency::LeaderLocal {
            leader_url: "l".repeat(AGGREGATE_FAMILY_ROOT_NODE_ID_MAX_BYTES),
            election_term: u64::MAX,
            lease_id: "i".repeat(AGGREGATE_FAMILY_ROOT_LEASE_ID_MAX_BYTES),
            lease_expires_at: body.expires_at,
        };
        body.high_watermark = Some(1);
        body.outcome = AggregateFamilyRootLookupOutcome::Found {
            source_seq: 1,
            canonical_token_json: "\\"
                .repeat(chio_store_sqlite::MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES),
            token_digest: "a".repeat(64),
        };

        let signed = SignedAggregateFamilyRootLookup::sign(body, &keypair).test_unwrap();
        let encoded = canonical_json_bytes(&signed).test_unwrap();
        assert!(encoded.len() as u64 <= AGGREGATE_FAMILY_ROOT_LOOKUP_MAX_BYTES);
    }
}
