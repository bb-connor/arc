// owned-by: M02 (fuzz lane); target authored under M02.P1.T1.b.
//
//! libFuzzer harness for `chio_credentials::verify_oid4vp_direct_post_response`.
//!
//! OID4VP (OpenID for Verifiable Presentations) routes a holder's signed
//! `direct_post.jwt` response through a strict parse pipeline: three
//! base64url segments, a JSON header (with a fixed `typ`), a JSON payload
//! deserialised into [`Oid4vpDirectPostResponseClaims`], an embedded SD-JWT
//! VC carried by the `vp_token` claim, a presentation-submission descriptor,
//! and finally a holder-binding signature check against the credential's
//! `cnf.jwk`. Every step is fail-closed (see
//! `crates/chio-credentials/src/oid4vp.rs`): arbitrary bytes must surface as
//! `Err(CredentialError::InvalidOid4vp{Request,Response,...})` rather than a
//! panic, abort, or `Ok(_)`.
//!
//! Input layout: bytes are interpreted as a UTF-8 compact-JWT string and
//! forwarded to the credentials-side fuzz entry point
//! `chio_credentials::fuzz::fuzz_oid4vp_presentation`, which pairs them with
//! a constant `Oid4vpRequestObject` fixture (fixed client_id, nonce, state,
//! response_uri, validity window). The seed corpus under
//! `corpus/oid4vp_presentation/` mixes empty input, random bytes, JWT-prefix
//! garbage, and a near-valid VP-JWT-shaped string with a bogus signature so
//! libFuzzer has a head start on both the decode path and the post-decode
//! audience/nonce/state validation paths.

#![no_main]

use chio_credentials::fuzz::fuzz_oid4vp_presentation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_oid4vp_presentation(data);
});
