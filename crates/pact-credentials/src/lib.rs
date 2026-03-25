//! Portable reputation credentials and Agent Passport verification for PACT.
//!
//! The alpha format is intentionally simple:
//! - credentials are canonically JSON-signed with Ed25519
//! - issuer and subject identities are `did:pact` identifiers
//! - a passport is an unsigned bundle of independently verifiable credentials
//! - verification is pure and requires no kernel or storage dependency

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::BTreeSet;
use std::str::FromStr;

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use pact_core::{canonical_json_bytes, Keypair, PublicKey, Signature};
use pact_did::{DidError, DidPact};
use pact_reputation::{LocalReputationScorecard, MetricValue};
use serde::{Deserialize, Serialize};

const VC_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";
const PACT_CREDENTIAL_CONTEXT_V1: &str = "https://pact.dev/credentials/v1";
const VC_TYPE: &str = "VerifiableCredential";
const REPUTATION_ATTESTATION_TYPE: &str = "PactReputationAttestation";
const PASSPORT_SCHEMA: &str = "pact.agent-passport.v1";
const PASSPORT_VERIFIER_POLICY_SCHEMA: &str = "pact.passport-verifier-policy.v1";
const PASSPORT_PRESENTATION_CHALLENGE_SCHEMA: &str =
    "pact.agent-passport-presentation-challenge.v1";
const PASSPORT_PRESENTATION_RESPONSE_SCHEMA: &str = "pact.agent-passport-presentation-response.v1";
const PROOF_TYPE: &str = "Ed25519Signature2020";
const PROOF_PURPOSE: &str = "assertionMethod";
const PRESENTATION_PROOF_PURPOSE: &str = "authentication";

include!("artifact.rs");
include!("passport.rs");
include!("challenge.rs");
include!("registry.rs");
include!("presentation.rs");
include!("policy.rs");
include!("tests.rs");
