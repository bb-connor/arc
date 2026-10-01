use core::fmt;

use serde::{Deserialize, Serialize};

use crate::flow::{DeclassificationPurpose, InformationLabel, PrincipalId};
use crate::ports::{DestinationId, Digest32, GrantId, RecordId, SessionId, TenantId};

pub const DECLASSIFICATION_GRANT_DOMAIN_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclassificationGrantClaims {
    pub grant_id: GrantId,
    pub capability_id: RecordId,
    pub tenant_id: TenantId,
    pub subject_id: PrincipalId,
    pub agent_id: RecordId,
    pub session_id: SessionId,
    pub source_label_hash: Digest32,
    pub target_label: InformationLabel,
    pub destination_id: DestinationId,
    pub tool_name: RecordId,
    pub purpose: DeclassificationPurpose,
    pub request_hash: Digest32,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub authority_key_id: RecordId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationGrantBody {
    domain_version: u16,
    grant_id: GrantId,
    capability_id: RecordId,
    tenant_id: TenantId,
    subject_id: PrincipalId,
    agent_id: RecordId,
    session_id: SessionId,
    source_label_hash: Digest32,
    target_label: InformationLabel,
    destination_id: DestinationId,
    tool_name: RecordId,
    purpose: DeclassificationPurpose,
    request_hash: Digest32,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    authority_key_id: RecordId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclassificationGrantValidationError {
    UnsupportedDomainVersion,
    InvalidTimeWindow,
    TopTarget,
}

impl fmt::Display for DeclassificationGrantValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedDomainVersion => "declassification grant version is unsupported",
            Self::InvalidTimeWindow => "declassification grant time window is invalid",
            Self::TopTarget => "declassification target cannot be top",
        })
    }
}

impl core::error::Error for DeclassificationGrantValidationError {}

impl DeclassificationGrantBody {
    pub fn new(
        claims: DeclassificationGrantClaims,
    ) -> Result<Self, DeclassificationGrantValidationError> {
        let body = Self {
            domain_version: DECLASSIFICATION_GRANT_DOMAIN_VERSION,
            grant_id: claims.grant_id,
            capability_id: claims.capability_id,
            tenant_id: claims.tenant_id,
            subject_id: claims.subject_id,
            agent_id: claims.agent_id,
            session_id: claims.session_id,
            source_label_hash: claims.source_label_hash,
            target_label: claims.target_label,
            destination_id: claims.destination_id,
            tool_name: claims.tool_name,
            purpose: claims.purpose,
            request_hash: claims.request_hash,
            issued_at_unix_seconds: claims.issued_at_unix_seconds,
            expires_at_unix_seconds: claims.expires_at_unix_seconds,
            authority_key_id: claims.authority_key_id,
        };
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), DeclassificationGrantValidationError> {
        if self.domain_version != DECLASSIFICATION_GRANT_DOMAIN_VERSION {
            return Err(DeclassificationGrantValidationError::UnsupportedDomainVersion);
        }
        if self.issued_at_unix_seconds >= self.expires_at_unix_seconds {
            return Err(DeclassificationGrantValidationError::InvalidTimeWindow);
        }
        if matches!(self.target_label, InformationLabel::Top) {
            return Err(DeclassificationGrantValidationError::TopTarget);
        }
        Ok(())
    }

    #[must_use]
    pub const fn domain_version(&self) -> u16 {
        self.domain_version
    }

    #[must_use]
    pub const fn grant_id(&self) -> &GrantId {
        &self.grant_id
    }

    #[must_use]
    pub const fn capability_id(&self) -> &RecordId {
        &self.capability_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn subject_id(&self) -> &PrincipalId {
        &self.subject_id
    }

    #[must_use]
    pub const fn agent_id(&self) -> &RecordId {
        &self.agent_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn source_label_hash(&self) -> Digest32 {
        self.source_label_hash
    }

    #[must_use]
    pub const fn target_label(&self) -> &InformationLabel {
        &self.target_label
    }

    #[must_use]
    pub const fn destination_id(&self) -> &DestinationId {
        &self.destination_id
    }

    #[must_use]
    pub const fn tool_name(&self) -> &RecordId {
        &self.tool_name
    }

    #[must_use]
    pub const fn purpose(&self) -> &DeclassificationPurpose {
        &self.purpose
    }

    #[must_use]
    pub const fn request_hash(&self) -> Digest32 {
        self.request_hash
    }

    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    #[must_use]
    pub const fn authority_key_id(&self) -> &RecordId {
        &self.authority_key_id
    }
}

impl<'de> Deserialize<'de> for DeclassificationGrantBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            domain_version: u16,
            grant_id: GrantId,
            capability_id: RecordId,
            tenant_id: TenantId,
            subject_id: PrincipalId,
            agent_id: RecordId,
            session_id: SessionId,
            source_label_hash: Digest32,
            target_label: InformationLabel,
            destination_id: DestinationId,
            tool_name: RecordId,
            purpose: DeclassificationPurpose,
            request_hash: Digest32,
            issued_at_unix_seconds: u64,
            expires_at_unix_seconds: u64,
            authority_key_id: RecordId,
        }

        let wire = Wire::deserialize(deserializer)?;
        let body = Self {
            domain_version: wire.domain_version,
            grant_id: wire.grant_id,
            capability_id: wire.capability_id,
            tenant_id: wire.tenant_id,
            subject_id: wire.subject_id,
            agent_id: wire.agent_id,
            session_id: wire.session_id,
            source_label_hash: wire.source_label_hash,
            target_label: wire.target_label,
            destination_id: wire.destination_id,
            tool_name: wire.tool_name,
            purpose: wire.purpose,
            request_hash: wire.request_hash,
            issued_at_unix_seconds: wire.issued_at_unix_seconds,
            expires_at_unix_seconds: wire.expires_at_unix_seconds,
            authority_key_id: wire.authority_key_id,
        };
        body.validate().map_err(serde::de::Error::custom)?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};

    use super::{
        DeclassificationGrantBody, DeclassificationGrantClaims,
        DeclassificationGrantValidationError,
    };
    use crate::flow::{Compartment, DeclassificationPurpose, InformationLabel, PrincipalId};
    use crate::ports::{DestinationId, Digest32, GrantId, RecordId, SessionId, TenantId};

    fn id(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("identifier: {error}"))
    }

    fn claims() -> DeclassificationGrantClaims {
        let owner =
            PrincipalId::new("owner-a").unwrap_or_else(|error| panic!("principal: {error}"));
        DeclassificationGrantClaims {
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
        }
    }

    #[test]
    fn validated_body_round_trips_strictly() {
        let body = DeclassificationGrantBody::new(claims())
            .unwrap_or_else(|error| panic!("body: {error}"));
        let encoded =
            serde_json::to_vec(&body).unwrap_or_else(|error| panic!("serialize body: {error}"));
        assert_eq!(
            serde_json::from_slice::<DeclassificationGrantBody>(&encoded)
                .unwrap_or_else(|error| panic!("deserialize body: {error}")),
            body
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&encoded).unwrap_or_else(|error| panic!("parse body: {error}"));
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DeclassificationGrantBody>(value).is_err());
    }

    #[test]
    fn invalid_time_and_top_target_reject_before_signing() {
        let mut invalid_time = claims();
        invalid_time.expires_at_unix_seconds = invalid_time.issued_at_unix_seconds;
        assert_eq!(
            DeclassificationGrantBody::new(invalid_time),
            Err(DeclassificationGrantValidationError::InvalidTimeWindow)
        );
        let mut top = claims();
        top.target_label = InformationLabel::Top;
        assert_eq!(
            DeclassificationGrantBody::new(top),
            Err(DeclassificationGrantValidationError::TopTarget)
        );

        let body = DeclassificationGrantBody::new(claims())
            .unwrap_or_else(|error| panic!("body: {error}"));
        let mut unsupported =
            serde_json::to_value(body).unwrap_or_else(|error| panic!("serialize body: {error}"));
        unsupported["domain_version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<DeclassificationGrantBody>(unsupported).is_err());
    }
}
