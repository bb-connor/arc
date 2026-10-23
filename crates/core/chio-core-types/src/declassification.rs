use alloc::string::ToString;

use chio_security_types::DeclassificationGrantBody;
use serde::{Deserialize, Serialize};

use crate::crypto::{verify_wrapped, wrapped_verdict, Ed25519Backend, Keypair};
use crate::{CanonicalBytes, Error, PublicKey, Result, Signature, SigningBackend};

/// Signing-wrapper schema id of a signed declassification grant.
pub const CHIO_DECLASSIFICATION_GRANT_SCHEMA: &str = "chio.declassification-grant.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeclassificationGrant {
    body: DeclassificationGrantBody,
    authority_key: PublicKey,
    signature: Signature,
}

impl SignedDeclassificationGrant {
    pub(crate) fn from_untrusted_parts(
        body: DeclassificationGrantBody,
        authority_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            body,
            authority_key,
            signature,
        }
    }
    pub fn sign(body: DeclassificationGrantBody, keypair: &Keypair) -> Result<Self> {
        Self::sign_with_backend(body, &Ed25519Backend::new(keypair.clone()))
    }

    pub fn sign_with_backend(
        body: DeclassificationGrantBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        body.validate()
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        let outcome = backend.sign_wrapped(
            CHIO_DECLASSIFICATION_GRANT_SCHEMA,
            &CanonicalBytes::from_serializable(&body)?,
        )?;
        Ok(Self {
            body,
            authority_key: outcome.public_key,
            signature: outcome.signature,
        })
    }

    /// Verifies integrity under the embedded key; the caller must bind that key
    /// to a trusted source before acting on the result.
    pub fn verify_integrity_embedded_key(&self) -> Result<bool> {
        self.body
            .validate()
            .map_err(|error| Error::InvalidSignature(error.to_string()))?;
        wrapped_verdict(verify_wrapped(
            &self.authority_key,
            CHIO_DECLASSIFICATION_GRANT_SCHEMA,
            &self.body,
            &self.signature,
        ))
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
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
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

    use super::{SignedDeclassificationGrant, CHIO_DECLASSIFICATION_GRANT_SCHEMA};
    use crate::{CanonicalBytes, Keypair};

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
    fn wrapped_signature_round_trips_strictly() {
        let grant = SignedDeclassificationGrant::sign(body(), &Keypair::from_seed(&[7; 32]))
            .unwrap_or_else(|error| panic!("sign: {error}"));
        assert!(grant
            .verify_integrity_embedded_key()
            .unwrap_or_else(|error| panic!("verify: {error}")));
        let encoded =
            serde_json::to_vec(&grant).unwrap_or_else(|error| panic!("serialize grant: {error}"));
        let decoded: SignedDeclassificationGrant = serde_json::from_slice(&encoded)
            .unwrap_or_else(|error| panic!("deserialize grant: {error}"));
        assert_eq!(decoded, grant);
    }

    #[test]
    fn substituted_signer_algorithm_member_and_unknown_field_reject() {
        let key = Keypair::from_seed(&[7; 32]);
        let first = SignedDeclassificationGrant::sign(body(), &key)
            .unwrap_or_else(|error| panic!("sign first: {error}"));
        let mut second = SignedDeclassificationGrant::sign(body(), &key)
            .unwrap_or_else(|error| panic!("sign second: {error}"));
        second.signature = Keypair::from_seed(&[8; 32])
            .sign_wrapped(
                CHIO_DECLASSIFICATION_GRANT_SCHEMA,
                &CanonicalBytes::from_serializable(&second.body)
                    .unwrap_or_else(|error| panic!("canonical: {error}")),
            )
            .unwrap_or_else(|error| panic!("sign other: {error}"));
        assert!(!second
            .verify_integrity_embedded_key()
            .unwrap_or_else(|error| panic!("verify: {error}")));

        for member in ["unknown", "algorithm"] {
            let mut value = serde_json::to_value(&first)
                .unwrap_or_else(|error| panic!("serialize grant: {error}"));
            value[member] = serde_json::json!("ed25519");
            assert!(serde_json::from_value::<SignedDeclassificationGrant>(value).is_err());
        }
    }
}
