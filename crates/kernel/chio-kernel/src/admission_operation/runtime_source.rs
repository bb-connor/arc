use super::{AdmissionDigest, AdmissionIdentifier, AdmissionOperationStoreError};
use chio_core::canonical::{canonical_json_bytes, UntrustedJsonText};
use chio_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};

pub const MAX_RUNTIME_SOURCE_BYTES: usize = 4096;
use chio_core_types::runtime_source::{
    RUNTIME_SOURCE_QUALIFICATION_DOMAIN as SOURCE_DOMAIN,
    RUNTIME_SOURCE_QUALIFICATION_SCHEMA as SOURCE_SCHEMA,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceBody {
    schema: String,
    source_id: AdmissionIdentifier,
    runtime_authority_id: AdmissionIdentifier,
    destination_authority_id: AdmissionIdentifier,
    device: String,
    inode: String,
    link_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceEvidence {
    body: SourceBody,
    qualification_sha256: AdmissionDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSourceQualificationV1 {
    evidence: SourceEvidence,
    canonical: Vec<u8>,
    device: u64,
    inode: u64,
}

impl RuntimeSourceQualificationV1 {
    pub fn new(
        source_id: AdmissionIdentifier,
        runtime_authority_id: AdmissionIdentifier,
        destination_authority_id: AdmissionIdentifier,
        device: u64,
        inode: u64,
        link_count: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let body = SourceBody {
            schema: SOURCE_SCHEMA.into(),
            source_id,
            runtime_authority_id,
            destination_authority_id,
            device: device.to_string(),
            inode: inode.to_string(),
            link_count,
        };
        let evidence = SourceEvidence {
            qualification_sha256: AdmissionDigest::try_new("qualification_sha256", digest(&body)?)?,
            body,
        };
        Self::from_canonical_bytes(&encode(&evidence)?)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AdmissionOperationStoreError> {
        let evidence: SourceEvidence =
            UntrustedJsonText::from_wire(bytes, MAX_RUNTIME_SOURCE_BYTES)
                .and_then(|input| input.decode_canonical())
                .map_err(AdmissionOperationStoreError::from)?;
        let body = &evidence.body;
        if body.schema != SOURCE_SCHEMA || body.link_count != 1 {
            return Err(invalid("invalid source qualification schema or link count"));
        }
        let device = identity_number(&body.device)?;
        let inode = identity_number(&body.inode)?;
        if digest(body)? != evidence.qualification_sha256.as_str() {
            return Err(invalid("source qualification digest mismatch"));
        }
        Ok(Self {
            evidence,
            canonical: bytes.to_vec(),
            device,
            inode,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn source_id(&self) -> &str {
        self.evidence.body.source_id.as_str()
    }
    pub fn runtime_authority_id(&self) -> &str {
        self.evidence.body.runtime_authority_id.as_str()
    }
    pub fn destination_authority_id(&self) -> &str {
        self.evidence.body.destination_authority_id.as_str()
    }
    pub fn qualification_sha256(&self) -> &str {
        self.evidence.qualification_sha256.as_str()
    }
    pub fn device(&self) -> u64 {
        self.device
    }
    pub fn inode(&self) -> u64 {
        self.inode
    }
    pub fn link_count(&self) -> u64 {
        self.evidence.body.link_count
    }
}

pub trait RuntimeSourcePort: Send + Sync {
    fn qualify(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        destination_authority_id: &AdmissionIdentifier,
    ) -> Result<RuntimeSourceQualificationV1, AdmissionOperationStoreError>;

    fn verify_exact(
        &self,
        expected: &RuntimeSourceQualificationV1,
    ) -> Result<(), AdmissionOperationStoreError>;
}

fn identity_number(value: &str) -> Result<u64, AdmissionOperationStoreError> {
    let number = value
        .parse::<u64>()
        .map_err(|_| invalid("invalid source file identity"))?;
    if number.to_string() != value {
        return Err(invalid("source file identity is not canonical decimal"));
    }
    Ok(number)
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    canonical_json_bytes(value).map_err(|error| invalid(&error.to_string()))
}

fn digest(body: &SourceBody) -> Result<String, AdmissionOperationStoreError> {
    let mut bytes = SOURCE_DOMAIN.to_vec();
    bytes.extend_from_slice(&encode(body)?);
    Ok(sha256_hex(&bytes))
}

fn invalid(detail: &str) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(format!("runtime source qualification: {detail}"))
}
