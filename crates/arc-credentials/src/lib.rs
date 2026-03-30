//! Portable reputation credentials and Agent Passport verification for ARC.
//!
//! The native ARC passport format remains intentionally simple:
//! - credentials are canonically JSON-signed with Ed25519
//! - issuer and subject identities currently remain `did:arc` identifiers
//! - a passport is an unsigned bundle of independently verifiable credentials
//! - verification is pure and requires no kernel or storage dependency
//!
//! ARC also ships a narrower standards-native projection lane for external
//! OID4VCI-style issuance. That path remains derived from the native passport
//! artifact rather than replacing it as the source of truth.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use arc_core::{
    canonical_json_bytes,
    session::{ArcIdentityAssertion, EnterpriseFederationMethod, EnterpriseIdentityContext},
    sha256_hex, ArcPortableClaimCatalog, ArcPortableIdentityBinding, Keypair, PublicKey, Signature,
};
use arc_did::{DidArc, DidError};
use arc_reputation::{LocalReputationScorecard, MetricValue};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use serde::{Deserialize, Serialize};

const VC_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";
const ARC_CREDENTIAL_CONTEXT_V1: &str = "https://arc.dev/credentials/v1";
const VC_TYPE: &str = "VerifiableCredential";
const REPUTATION_ATTESTATION_TYPE: &str = "ArcReputationAttestation";
const PASSPORT_SCHEMA: &str = "arc.agent-passport.v1";
const LEGACY_PASSPORT_SCHEMA: &str = "arc.agent-passport.v1";
const PASSPORT_VERIFIER_POLICY_SCHEMA: &str = "arc.passport-verifier-policy.v1";
const LEGACY_PASSPORT_VERIFIER_POLICY_SCHEMA: &str = "arc.passport-verifier-policy.v1";
const PASSPORT_PRESENTATION_CHALLENGE_SCHEMA: &str = "arc.agent-passport-presentation-challenge.v1";
const LEGACY_PASSPORT_PRESENTATION_CHALLENGE_SCHEMA: &str =
    "arc.agent-passport-presentation-challenge.v1";
const PASSPORT_PRESENTATION_RESPONSE_SCHEMA: &str = "arc.agent-passport-presentation-response.v1";
const LEGACY_PASSPORT_PRESENTATION_RESPONSE_SCHEMA: &str =
    "arc.agent-passport-presentation-response.v1";
const PROOF_TYPE: &str = "Ed25519Signature2020";
const PROOF_PURPOSE: &str = "assertionMethod";
const PRESENTATION_PROOF_PURPOSE: &str = "authentication";

fn is_supported_passport_schema(schema: &str) -> bool {
    schema == PASSPORT_SCHEMA || schema == LEGACY_PASSPORT_SCHEMA
}

fn is_supported_passport_verifier_policy_schema(schema: &str) -> bool {
    schema == PASSPORT_VERIFIER_POLICY_SCHEMA || schema == LEGACY_PASSPORT_VERIFIER_POLICY_SCHEMA
}

fn is_supported_passport_presentation_challenge_schema(schema: &str) -> bool {
    schema == PASSPORT_PRESENTATION_CHALLENGE_SCHEMA
        || schema == LEGACY_PASSPORT_PRESENTATION_CHALLENGE_SCHEMA
}

fn is_supported_passport_presentation_response_schema(schema: &str) -> bool {
    schema == PASSPORT_PRESENTATION_RESPONSE_SCHEMA
        || schema == LEGACY_PASSPORT_PRESENTATION_RESPONSE_SCHEMA
}

include!("artifact.rs");
include!("passport.rs");
include!("portable_sd_jwt.rs");
include!("portable_jwt_vc.rs");
include!("challenge.rs");
include!("registry.rs");
include!("presentation.rs");
include!("policy.rs");
include!("oid4vci.rs");
include!("oid4vp.rs");
include!("tests.rs");
