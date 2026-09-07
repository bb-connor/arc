use alloc::string::ToString;
use alloc::vec::Vec;

use chio_security_types::DeclassificationGrantBody;
use serde::{Deserialize, Serialize};

use crate::crypto::{Ed25519Backend, Keypair};
use crate::{
    canonical_json_bytes, Error, PublicKey, Result, Signature, SigningAlgorithm, SigningBackend,
};

pub const DECLASSIFICATION_GRANT_SIGNATURE_DOMAIN: &str = "chio:declassification-grant:v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeclassificationGrant {
    body: DeclassificationGrantBody,
    authority_key: PublicKey,
    algorithm: SigningAlgorithm,
    signature: Signature,
}

impl SignedDeclassificationGrant {
    pub fn sign(body: DeclassificationGrantBody, keypair: &Keypair) -> Result<Self> {
        Self::sign_with_backend(body, &Ed25519Backend::new(keypair.clone()))
    }

    pub fn sign_with_backend(
        body: DeclassificationGrantBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        body.validate()
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        let outcome = backend.sign_bytes_with_identity(&signing_bytes(&body)?)?;
        let authority_key = outcome.public_key;
        let algorithm = outcome.algorithm;
        let signature = outcome.signature;
        if signature.algorithm() != algorithm {
            return Err(Error::InvalidSignature(
                "declassification signature algorithm mismatch".into(),
            ));
        }
        Ok(Self {
            body,
            authority_key,
            algorithm,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        self.body
            .validate()
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        if self.authority_key.algorithm() != self.algorithm
            || self.signature.algorithm() != self.algorithm
        {
            return Ok(false);
        }
        Ok(self
            .authority_key
            .verify(&signing_bytes(&self.body)?, &self.signature))
    }

    #[must_use]
    pub const fn body(&self) -> &DeclassificationGrantBody {
        &self.body
    }

    #[must_use]
    pub const fn authority_key(&self) -> &PublicKey {
        &self.authority_key
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(&self.body)
    }
}

fn signing_bytes(body: &DeclassificationGrantBody) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(body)?;
    let mut bytes =
        Vec::with_capacity(DECLASSIFICATION_GRANT_SIGNATURE_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(DECLASSIFICATION_GRANT_SIGNATURE_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};

    use chio_security_types::flow::{
        Compartment, DeclassificationPurpose, InformationLabel, PrincipalId,
    };
    use chio_security_types::ports::{
        DestinationId, Digest32, GrantId, RecordId, SessionId, TenantId,
    };
    use chio_security_types::{DeclassificationGrantBody, DeclassificationGrantClaims};

    use super::{SignedDeclassificationGrant, DECLASSIFICATION_GRANT_SIGNATURE_DOMAIN};
    use crate::Keypair;

    fn id(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("identifier: {error}"))
    }

    fn body() -> DeclassificationGrantBody {
        let owner =
            PrincipalId::new("owner-a").unwrap_or_else(|error| panic!("principal: {error}"));
        DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
            capability_id: id("capability-a"),
            tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
            subject_id: PrincipalId::new("subject-a")
                .unwrap_or_else(|error| panic!("subject: {error}")),
            agent_id: id("agent-a"),
            session_id: SessionId::new("session-a")
                .unwrap_or_else(|error| panic!("session: {error}")),
            source_label_hash: Digest32::new([1; 32]),
            target_label: InformationLabel::try_known(
                BTreeMap::from([(owner.clone(), BTreeSet::from([owner]))]),
                BTreeSet::from([
                    Compartment::new("pii").unwrap_or_else(|error| panic!("compartment: {error}"))
                ]),
            )
            .unwrap_or_else(|error| panic!("label: {error}")),
            destination_id: DestinationId::new("server-a")
                .unwrap_or_else(|error| panic!("destination: {error}")),
            tool_name: id("tool-a"),
            purpose: DeclassificationPurpose::new("support")
                .unwrap_or_else(|error| panic!("purpose: {error}")),
            request_hash: Digest32::new([2; 32]),
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            authority_key_id: id("authority-a"),
        })
        .unwrap_or_else(|error| panic!("body: {error}"))
    }

    #[test]
    fn domain_separated_signature_round_trips_strictly() {
        let grant = SignedDeclassificationGrant::sign(body(), &Keypair::from_seed(&[7; 32]))
            .unwrap_or_else(|error| panic!("sign: {error}"));
        assert!(grant
            .verify_signature()
            .unwrap_or_else(|error| panic!("verify: {error}")));
        assert!(grant
            .signing_bytes()
            .unwrap_or_else(|error| panic!("signing bytes: {error}"))
            .starts_with(DECLASSIFICATION_GRANT_SIGNATURE_DOMAIN.as_bytes()));
        assert_eq!(
            grant
                .signing_bytes()
                .unwrap_or_else(|error| panic!("signing bytes: {error}"))
                [DECLASSIFICATION_GRANT_SIGNATURE_DOMAIN.len()],
            0
        );
        let encoded =
            serde_json::to_vec(&grant).unwrap_or_else(|error| panic!("serialize grant: {error}"));
        let decoded: SignedDeclassificationGrant = serde_json::from_slice(&encoded)
            .unwrap_or_else(|error| panic!("deserialize grant: {error}"));
        assert_eq!(decoded, grant);
    }

    #[test]
    fn substituted_body_and_unknown_envelope_field_reject() {
        let key = Keypair::from_seed(&[7; 32]);
        let first = SignedDeclassificationGrant::sign(body(), &key)
            .unwrap_or_else(|error| panic!("sign first: {error}"));
        let mut second = SignedDeclassificationGrant::sign(body(), &key)
            .unwrap_or_else(|error| panic!("sign second: {error}"));
        second.signature = Keypair::from_seed(&[8; 32]).sign(
            &second
                .signing_bytes()
                .unwrap_or_else(|error| panic!("signing bytes: {error}")),
        );
        assert!(!second
            .verify_signature()
            .unwrap_or_else(|error| panic!("verify: {error}")));

        let mut value =
            serde_json::to_value(first).unwrap_or_else(|error| panic!("serialize grant: {error}"));
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SignedDeclassificationGrant>(value).is_err());
    }
}
