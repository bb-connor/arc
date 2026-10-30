use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use chio_core::root_authority::{
    EnterpriseProviderIdentity, EnterpriseProviderIdentityFields, HttpsUrl, Identifier,
    IdpKeySnapshot, IdpKeySnapshotSignatureError, InlineJwks, Jwk, JwsAlgorithm, KeySnapshotSource,
    ProviderRecordKind, RootAuthorityShapeError, SubjectMapping, Uri,
    CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA, CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
};
use chio_egress_contract::{HttpEgressContract, HttpEgressError};
use serde::Deserialize;
use serde_json::{json, Value};

use super::*;
use crate::root_exchange::signer::ExchangeSigner;
use crate::root_exchange::{IdpKeyLookup, RootExchangeError};

const ISSUER: &str = "https://idp.example";
const JWKS_URL: &str = "https://idp.example/oauth2/v1/keys";
const T0: u64 = 1_792_230_000;

#[derive(Default)]
struct StubFetcher {
    responses: Mutex<VecDeque<Result<Vec<u8>, JwksFetchError>>>,
    calls: AtomicUsize,
    hang: AtomicBool,
}

impl StubFetcher {
    fn push(&self, response: Result<Vec<u8>, JwksFetchError>) {
        self.responses.lock().unwrap().push_back(response);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl JwksFetcher for StubFetcher {
    async fn fetch(&self, url: &HttpsUrl) -> Result<Vec<u8>, JwksFetchError> {
        assert_eq!(url.as_str(), JWKS_URL);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(JwksFetchError::Status(503)))
    }
}

#[derive(Default)]
struct RecordingSink {
    snapshots: Mutex<Vec<IdpKeySnapshot>>,
    refuse: AtomicBool,
}

impl RecordingSink {
    fn snapshots(&self) -> Vec<IdpKeySnapshot> {
        self.snapshots.lock().unwrap().clone()
    }

    fn kids(&self, index: usize) -> Vec<String> {
        self.snapshots()[index]
            .keys
            .iter()
            .map(|key| key.kid.as_str().to_owned())
            .collect()
    }
}

#[async_trait::async_trait]
impl KeySnapshotSink for RecordingSink {
    async fn record(&self, snapshot: &IdpKeySnapshot) -> Result<(), SnapshotNotRecorded> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(SnapshotNotRecorded);
        }
        self.snapshots.lock().unwrap().push(snapshot.clone());
        Ok(())
    }
}

struct Harness {
    keys: PinnedIdpKeys,
    fetcher: Arc<StubFetcher>,
    sink: Arc<RecordingSink>,
    now: AtomicU64,
}

impl Harness {
    fn set_now(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }

    async fn resolve(
        &self,
        alg: JwsAlgorithm,
        kid: &str,
    ) -> Result<ResolvedIdpKey, KeyResolutionError> {
        self.keys
            .resolve(kid, alg, self.now.load(Ordering::SeqCst))
            .await
    }

    async fn refresh_if_due(&self) -> Result<(), KeyResolutionError> {
        self.keys
            .refresh_if_due(self.now.load(Ordering::SeqCst))
            .await
    }
}

fn exchange_keypair() -> Keypair {
    Keypair::from_seed(&[42; 32])
}

fn exchange_key() -> PublicKey {
    exchange_keypair().public_key()
}

fn exchange_signer() -> ExchangeSigner {
    ExchangeSigner::new(Arc::new(Ed25519Backend::new(exchange_keypair()))).unwrap()
}

fn harness_for(identity: &EnterpriseProviderIdentity) -> Result<Harness, IdpKeySourceError> {
    harness_signed_by(identity, exchange_signer())
}

fn harness_signed_by(
    identity: &EnterpriseProviderIdentity,
    signer: ExchangeSigner,
) -> Result<Harness, IdpKeySourceError> {
    let fetcher = Arc::new(StubFetcher::default());
    let sink = Arc::new(RecordingSink::default());
    let keys = PinnedIdpKeys::from_provider(
        identity,
        fetcher.clone(),
        signer,
        sink.clone(),
        RefreshPolicy::default(),
    )?;
    Ok(Harness {
        keys,
        fetcher,
        sink,
        now: AtomicU64::new(T0),
    })
}

fn fetched_harness() -> Harness {
    harness_for(&identity(Some(JWKS_URL), None)).unwrap()
}

fn identity(jwks_url: Option<&str>, jwks: Option<Vec<Value>>) -> EnterpriseProviderIdentity {
    identity_with(jwks_url, jwks, |_| {})
}

fn identity_with(
    jwks_url: Option<&str>,
    jwks: Option<Vec<Value>>,
    edit: impl FnOnce(&mut EnterpriseProviderIdentityFields),
) -> EnterpriseProviderIdentity {
    let mut fields = EnterpriseProviderIdentityFields {
        schema: CHIO_ENTERPRISE_PROVIDER_IDENTITY_SCHEMA.to_owned(),
        provider_id: Identifier::new("acme-okta").unwrap(),
        kind: ProviderRecordKind::OidcJwks,
        issuer: Uri::new(ISSUER).unwrap(),
        jwks_url: jwks_url.map(|url| HttpsUrl::new(url).unwrap()),
        jwks: jwks.map(|keys| InlineJwks {
            keys: keys
                .iter()
                .map(|key| <Jwk as Deserialize>::deserialize(key).unwrap())
                .collect(),
        }),
        introspection_url: None,
        audiences: Vec::new(),
        subject_mapping: SubjectMapping {
            principal_source: Identifier::new("sub").unwrap(),
            tenant_id_field: Identifier::new("iss").unwrap(),
        },
        trust_material_ref: Identifier::new("acme-okta-trust").unwrap(),
    };
    edit(&mut fields);
    EnterpriseProviderIdentity::new(fields).unwrap()
}

fn edited(
    record: &EnterpriseProviderIdentity,
    edit: impl FnOnce(&mut EnterpriseProviderIdentityFields),
) -> EnterpriseProviderIdentity {
    let mut fields = record.clone().into_fields();
    edit(&mut fields);
    EnterpriseProviderIdentity::new(fields).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn modulus(bits: usize) -> String {
    let mut bytes = vec![0x01_u8; bits.div_ceil(8)];
    bytes[0] = 1 << ((bits - 1) % 8);
    b64(&bytes)
}

fn rsa_key(kid: &str, bits: usize) -> Value {
    json!({ "kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": modulus(bits), "e": "AQAB" })
}

fn ec_key(kid: &str) -> Value {
    let point = p256::ecdsa::SigningKey::from_slice(&[1; 32])
        .unwrap()
        .verifying_key()
        .to_encoded_point(false);
    json!({
        "kid": kid,
        "kty": "EC",
        "crv": "P-256",
        "x": b64(point.x().unwrap()),
        "y": b64(point.y().unwrap()),
    })
}

fn jwks(keys: &[Value]) -> Vec<u8> {
    serde_json::to_vec(&json!({ "keys": keys })).unwrap()
}

fn kids(keys: &[Jwk]) -> Vec<&str> {
    keys.iter().map(|key| key.kid.as_str()).collect()
}

#[test]
fn document_drops_encryption_keys() {
    let mut enc = rsa_key("enc", 2048);
    enc["use"] = json!("enc");
    let keys = admit_jwks_document(&jwks(&[enc, rsa_key("sig", 2048)])).unwrap();
    assert_eq!(kids(&keys), ["sig"]);
}

#[test]
fn document_drops_rsa_moduli_below_2048_bits() {
    let keys = admit_jwks_document(&jwks(&[
        rsa_key("rsa-1024", 1024),
        rsa_key("rsa-2047", 2047),
        rsa_key("rsa-2048", 2048),
    ]))
    .unwrap();
    assert_eq!(kids(&keys), ["rsa-2048"]);
}

#[test]
fn document_drops_incoherent_private_and_duplicate_keys() {
    let mut wrong_alg = rsa_key("wrong-alg", 2048);
    wrong_alg["alg"] = json!("ES256");
    let mut private = rsa_key("private", 2048);
    private["d"] = json!(b64(&[1; 32]));
    let mut rsa_with_curve = rsa_key("rsa-with-curve", 2048);
    rsa_with_curve["crv"] = json!("P-256");
    let keys = admit_jwks_document(&jwks(&[
        wrong_alg,
        private,
        rsa_with_curve,
        ec_key("twice"),
        ec_key("twice"),
        ec_key("b"),
        ec_key("a"),
    ]))
    .unwrap();
    assert_eq!(kids(&keys), ["a", "b"]);
}

#[test]
fn document_drops_a_kid_shared_with_an_inadmissible_key() {
    let mut private = rsa_key("k", 2048);
    private["d"] = json!(b64(&[1; 32]));
    let mut encryption = rsa_key("k", 2048);
    encryption["use"] = json!("enc");
    for shadow in [rsa_key("k", 1024), private, encryption] {
        for keys in [
            [rsa_key("k", 2048), shadow.clone(), ec_key("other")],
            [shadow.clone(), rsa_key("k", 2048), ec_key("other")],
        ] {
            let admitted = admit_jwks_document(&jwks(&keys)).unwrap();
            assert_eq!(kids(&admitted), ["other"], "{shadow}");
        }
    }
}

#[test]
fn inline_keys_drop_a_kid_shared_with_an_inadmissible_key() {
    let decode = |value: Value| -> Jwk { serde_json::from_value(value).unwrap() };
    let admitted = super::document::admit_keys(vec![
        decode(rsa_key("k", 2048)),
        decode(rsa_key("k", 1024)),
        decode(ec_key("other")),
    ])
    .unwrap();
    assert_eq!(kids(&admitted), ["other"]);
}

#[test]
fn document_admits_signing_keys_that_carry_key_ops_or_x5u() {
    let mut verify_ops = rsa_key("verify-ops", 2048);
    verify_ops["key_ops"] = json!(["verify"]);
    let mut x5u = ec_key("x5u");
    x5u["x5u"] = json!("https://idp.example/certs/x5u.pem");
    let mut encrypt_ops = rsa_key("encrypt-ops", 2048);
    encrypt_ops["key_ops"] = json!(["encrypt", "wrapKey"]);
    let mut scalar_ops = rsa_key("scalar-ops", 2048);
    scalar_ops["key_ops"] = json!("verify");
    let mut repeated_ops = rsa_key("repeated-ops", 2048);
    repeated_ops["key_ops"] = json!(["verify", "verify"]);
    let mut numeric_x5u = ec_key("numeric-x5u");
    numeric_x5u["x5u"] = json!(7);
    let mut private_ops = rsa_key("private-ops", 2048);
    private_ops["key_ops"] = json!(["verify"]);
    private_ops["d"] = json!(b64(&[1; 32]));
    let keys = admit_jwks_document(&jwks(&[
        verify_ops,
        x5u,
        encrypt_ops,
        scalar_ops,
        repeated_ops,
        numeric_x5u,
        private_ops,
    ]))
    .unwrap();
    assert_eq!(kids(&keys), ["verify-ops", "x5u"]);
    assert_eq!(
        keys[0],
        serde_json::from_value(rsa_key("verify-ops", 2048)).unwrap()
    );
    assert_eq!(keys[1], serde_json::from_value(ec_key("x5u")).unwrap());
}

#[test]
fn document_without_usable_keys_rejects() {
    assert_eq!(
        admit_jwks_document(&jwks(&[rsa_key("weak", 1024)])),
        Err(JwksDocumentError::NoUsableKeys),
    );
    assert_eq!(
        admit_jwks_document(&jwks(&[])),
        Err(JwksDocumentError::NoUsableKeys),
    );
}

#[test]
fn document_shape_errors_reject() {
    for bytes in [
        b"not json".to_vec(),
        b"{}".to_vec(),
        br#"{"keys":{}}"#.to_vec(),
        br#"{"keys":[],"keys":[]}"#.to_vec(),
        vec![0xff, 0xfe],
    ] {
        assert_eq!(
            admit_jwks_document(&bytes),
            Err(JwksDocumentError::Malformed)
        );
    }
}

#[test]
fn oversized_document_rejects() {
    let padding = "x".repeat(MAX_JWKS_DOCUMENT_BYTES);
    let bytes = serde_json::to_vec(&json!({ "keys": [ec_key("a")], "pad": padding })).unwrap();
    assert_eq!(
        admit_jwks_document(&bytes),
        Err(JwksDocumentError::TooLarge { bytes: bytes.len() }),
    );
}

#[test]
fn document_with_too_many_keys_rejects() {
    let keys: Vec<Value> = (0..=MAX_ADMITTED_KEYS)
        .map(|index| ec_key(&format!("k{index:03}")))
        .collect();
    assert_eq!(
        admit_jwks_document(&jwks(&keys)),
        Err(JwksDocumentError::TooManyKeys {
            count: MAX_ADMITTED_KEYS + 1
        }),
    );
}

#[test]
fn refresh_policy_bounds() {
    assert_eq!(
        RefreshPolicy::new(59, 900),
        Err(RefreshPolicyError::FetchIntervalTooShort(59)),
    );
    assert_eq!(
        RefreshPolicy::new(120, 119),
        Err(RefreshPolicyError::ScheduledRefreshOutOfRange(119)),
    );
    assert_eq!(
        RefreshPolicy::new(60, 86_401),
        Err(RefreshPolicyError::ScheduledRefreshOutOfRange(86_401)),
    );
    let policy = RefreshPolicy::default();
    assert_eq!(
        RefreshPolicy::new(
            DEFAULT_MIN_FETCH_INTERVAL_SECS,
            DEFAULT_SCHEDULED_REFRESH_SECS
        ),
        Ok(policy),
    );
    assert_eq!(
        (
            policy.min_fetch_interval_secs(),
            policy.scheduled_refresh_secs()
        ),
        (60, 900)
    );
}

#[tokio::test]
async fn first_resolution_fetches_and_records_a_snapshot() {
    let harness = fetched_harness();
    harness
        .fetcher
        .push(Ok(jwks(&[rsa_key("k2", 2048), rsa_key("k1", 2048)])));
    let resolved = harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    assert_eq!(resolved.key.kid.as_str(), "k1");
    assert_eq!(resolved.snapshot.observed_at, T0);
    let snapshots = harness.sink.snapshots();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].issuer.as_str(), ISSUER);
    assert_eq!(
        snapshots[0].source,
        KeySnapshotSource::JwksUrl(HttpsUrl::new(JWKS_URL).unwrap())
    );
    assert_eq!(snapshots[0].observed_at, T0);
    assert_eq!(harness.sink.kids(0), ["k1", "k2"]);

    harness.set_now(T0 + 30);
    harness.resolve(JwsAlgorithm::RS256, "k2").await.unwrap();
    assert_eq!(harness.fetcher.calls(), 1);
    assert_eq!(harness.sink.snapshots().len(), 1);
}

#[tokio::test]
async fn unknown_kid_refreshes_once_and_finds_the_rotated_key() {
    let harness = fetched_harness();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness
        .fetcher
        .push(Ok(jwks(&[rsa_key("k1", 2048), rsa_key("k2", 2048)])));
    harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    harness.set_now(T0 + 61);
    let resolved = harness.resolve(JwsAlgorithm::RS256, "k2").await.unwrap();
    assert_eq!(resolved.snapshot.observed_at, T0 + 61);
    assert_eq!(harness.fetcher.calls(), 2);
    assert_eq!(harness.sink.snapshots().len(), 2);
    assert_eq!(harness.sink.kids(1), ["k1", "k2"]);
}

#[tokio::test]
async fn unknown_kid_inside_the_rate_limit_denies_without_fetching() {
    let harness = fetched_harness();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    for offset in [0, 10, 59] {
        harness.set_now(T0 + offset);
        assert_eq!(
            harness.resolve(JwsAlgorithm::RS256, "attacker").await,
            Err(KeyResolutionError::UnknownKid),
        );
    }
    assert_eq!(harness.fetcher.calls(), 1);

    harness.set_now(T0 + 60);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "attacker").await,
        Err(KeyResolutionError::UnknownKid),
    );
    assert_eq!(harness.fetcher.calls(), 2);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "attacker").await,
        Err(KeyResolutionError::UnknownKid),
    );
    assert_eq!(harness.fetcher.calls(), 2);
    assert_eq!(harness.sink.snapshots().len(), 1);
}

#[tokio::test]
async fn scheduled_refresh_removes_a_withdrawn_key() {
    let harness = fetched_harness();
    harness
        .fetcher
        .push(Ok(jwks(&[rsa_key("k1", 2048), rsa_key("k2", 2048)])));
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness.resolve(JwsAlgorithm::RS256, "k2").await.unwrap();
    harness.set_now(T0 + 899);
    harness.resolve(JwsAlgorithm::RS256, "k2").await.unwrap();
    assert_eq!(harness.fetcher.calls(), 1);

    harness.set_now(T0 + 900);
    let resolved = harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    assert_eq!(resolved.snapshot.observed_at, T0 + 900);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k2").await,
        Err(KeyResolutionError::UnknownKid),
    );
    assert_eq!(harness.fetcher.calls(), 2);
    assert_eq!(harness.sink.kids(1), ["k1"]);
}

#[tokio::test]
async fn unchanged_refresh_records_no_snapshot() {
    let harness = fetched_harness();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    harness.set_now(T0 + 900);
    let resolved = harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    assert_eq!(resolved.snapshot.observed_at, T0);
    harness.set_now(T0 + 1_799);
    harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    assert_eq!(harness.fetcher.calls(), 2);
    assert_eq!(harness.sink.snapshots().len(), 1);
}

#[tokio::test]
async fn refresh_if_due_runs_only_when_the_set_is_stale() {
    let harness = fetched_harness();
    harness
        .fetcher
        .push(Ok(jwks(&[rsa_key("k1", 2048), rsa_key("k2", 2048)])));
    harness.fetcher.push(Ok(jwks(&[rsa_key("k2", 2048)])));
    assert_eq!(harness.refresh_if_due().await, Ok(()));
    assert_eq!(harness.fetcher.calls(), 1);
    harness.set_now(T0 + 899);
    assert_eq!(harness.refresh_if_due().await, Ok(()));
    assert_eq!(harness.fetcher.calls(), 1);
    harness.set_now(T0 + 900);
    assert_eq!(harness.refresh_if_due().await, Ok(()));
    assert_eq!(harness.fetcher.calls(), 2);
    assert_eq!(harness.sink.kids(1), ["k2"]);
}

#[tokio::test]
async fn unreachable_jwks_denies_and_holds_the_rate_limit() {
    let harness = fetched_harness();
    harness.fetcher.push(Err(JwksFetchError::Status(503)));
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::Fetch(JwksFetchError::Status(503))),
    );
    harness.set_now(T0 + 59);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::KeySetUnavailable),
    );
    assert_eq!(
        harness.refresh_if_due().await,
        Err(KeyResolutionError::KeySetUnavailable),
    );
    assert_eq!(harness.fetcher.calls(), 1);
    harness.set_now(T0 + 60);
    harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    assert_eq!(harness.fetcher.calls(), 2);
}

#[tokio::test]
async fn failed_scheduled_refresh_denies_known_keys() {
    let harness = fetched_harness();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness.fetcher.push(Ok(b"not json".to_vec()));
    harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    harness.set_now(T0 + 900);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::Document(JwksDocumentError::Malformed)),
    );
    harness.set_now(T0 + 901);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::KeySetUnavailable),
    );
}

#[tokio::test]
async fn oversized_jwks_denies_the_exchange() {
    let harness = fetched_harness();
    harness
        .fetcher
        .push(Ok(vec![b' '; MAX_JWKS_DOCUMENT_BYTES + 1]));
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::Document(JwksDocumentError::TooLarge {
            bytes: MAX_JWKS_DOCUMENT_BYTES + 1
        })),
    );
    assert!(harness.sink.snapshots().is_empty());
}

#[tokio::test]
async fn key_must_carry_the_token_alg() {
    let harness = fetched_harness();
    harness
        .fetcher
        .push(Ok(jwks(&[rsa_key("rsa", 2048), ec_key("ec")])));
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS384, "rsa").await,
        Err(KeyResolutionError::KeyAlgorithmMismatch),
    );
    assert_eq!(
        harness.resolve(JwsAlgorithm::ES384, "ec").await,
        Err(KeyResolutionError::KeyTypeMismatch),
    );
    harness.resolve(JwsAlgorithm::ES256, "ec").await.unwrap();
}

#[tokio::test]
async fn unrecorded_snapshot_keeps_the_new_set_out_of_use() {
    let harness = fetched_harness();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness.sink.refuse.store(true, Ordering::SeqCst);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::SnapshotNotRecorded(SnapshotNotRecorded)),
    );
    harness.sink.refuse.store(false, Ordering::SeqCst);
    harness.set_now(T0 + 1);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::KeySetUnavailable),
    );
}

#[tokio::test]
async fn inline_keys_never_fetch() {
    let harness = harness_for(&identity(
        None,
        Some(vec![rsa_key("k1", 2048), rsa_key("weak", 1024)]),
    ))
    .unwrap();
    let resolved = harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    assert_eq!(resolved.snapshot.observed_at, T0);
    harness.set_now(T0 + 100_000);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "weak").await,
        Err(KeyResolutionError::UnknownKid),
    );
    assert_eq!(harness.fetcher.calls(), 0);
    let snapshots = harness.sink.snapshots();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(
        snapshots[0].source,
        KeySnapshotSource::Registry("acme-okta".to_owned())
    );
    assert_eq!(harness.sink.kids(0), ["k1"]);
}

#[test]
fn provider_records_without_one_key_source_reject() {
    assert_eq!(
        harness_for(&identity(None, Some(vec![rsa_key("weak", 1024)]))).err(),
        Some(IdpKeySourceError::Document(JwksDocumentError::NoUsableKeys)),
    );
    let introspection = identity_with(None, None, |fields| {
        fields.kind = ProviderRecordKind::OauthIntrospection;
        fields.introspection_url = Some(HttpsUrl::new("https://idp.example/introspect").unwrap());
    });
    assert_eq!(
        harness_for(&introspection).err(),
        Some(IdpKeySourceError::NotAJwksRecord),
    );
}

#[test]
fn inline_provider_id_outside_the_snapshot_source_grammar_rejects() {
    let record = identity_with(None, Some(vec![rsa_key("k1", 2048)]), |fields| {
        fields.provider_id = Identifier::new("acme okta").unwrap();
    });
    assert_eq!(
        harness_for(&record).err(),
        Some(IdpKeySourceError::UnrepresentableProviderId(
            RootAuthorityShapeError::Pattern {
                field: "source",
                expected: "registry:<1 to 128 characters without NUL or whitespace>",
            }
        )),
    );
}

#[tokio::test]
async fn recorded_snapshots_are_signed_by_the_exchange_key() {
    let harness = fetched_harness();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    let resolved = harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    let recorded = harness.sink.snapshots();
    assert_eq!(recorded.len(), 1);
    assert_eq!(*resolved.snapshot, recorded[0]);
    let snapshot = &recorded[0];
    assert_eq!(snapshot.schema, CHIO_IDP_KEY_SNAPSHOT_SCHEMA);
    assert_eq!(snapshot.exchange_key, exchange_key());
    assert_eq!(snapshot.verify_signature(&exchange_key()), Ok(()));
    assert_eq!(
        snapshot.verify_signature(&Keypair::from_seed(&[43; 32]).public_key()),
        Err(IdpKeySnapshotSignatureError::ExchangeKeyNotPinned),
    );
    let decoded: IdpKeySnapshot =
        serde_json::from_slice(&serde_json::to_vec(snapshot).unwrap()).unwrap();
    assert_eq!(&decoded, snapshot);
}

#[tokio::test]
async fn unsignable_snapshot_keeps_the_new_set_out_of_use() {
    let harness = harness_signed_by(
        &identity(Some(JWKS_URL), None),
        ExchangeSigner::new(Arc::new(SwitchableBackend {
            exchange: Ed25519Backend::new(exchange_keypair()),
            other: Ed25519Backend::new(Keypair::from_seed(&[43; 32])),
            fail: AtomicBool::new(true),
        }))
        .unwrap(),
    )
    .unwrap();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::SnapshotNotSigned(SnapshotNotSigned)),
    );
    assert!(harness.sink.snapshots().is_empty());
    harness.set_now(T0 + 1);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::KeySetUnavailable),
    );
}

#[test]
fn contract_fetcher_requires_an_https_contract() {
    let mut contract = HttpEgressContract::permissive_for_tests("idp.example");
    contract.allowed_schemes = BTreeSet::from(["http".to_owned()]);
    assert_eq!(
        ContractJwksFetcher::new(contract).err(),
        Some(JwksFetchError::Egress(HttpEgressError::InvalidContract(
            "allowed_schemes must be non-empty".to_owned()
        ))),
    );
}

#[tokio::test]
async fn contract_fetcher_refuses_an_authority_outside_the_contract() {
    let fetcher =
        ContractJwksFetcher::new(HttpEgressContract::permissive_for_tests("idp.example")).unwrap();
    let url = HttpsUrl::new("https://other.example/keys").unwrap();
    assert_eq!(
        fetcher.fetch(&url).await,
        Err(JwksFetchError::Egress(HttpEgressError::AuthorityDenied {
            authority: "other.example".to_owned()
        })),
    );
}

#[tokio::test]
async fn an_earlier_now_never_moves_the_source_backwards() {
    let harness = fetched_harness();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness
        .fetcher
        .push(Ok(jwks(&[rsa_key("k1", 2048), rsa_key("k2", 2048)])));
    harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    harness.set_now(T0 - 120);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k2").await,
        Err(KeyResolutionError::UnknownKid),
    );
    assert_eq!(harness.fetcher.calls(), 1);
    harness.set_now(T0 + 60);
    let resolved = harness.resolve(JwsAlgorithm::RS256, "k2").await.unwrap();
    assert_eq!(resolved.snapshot.observed_at, T0 + 60);
    assert_eq!(harness.fetcher.calls(), 2);
}

struct Sources {
    sources: IdpKeySources,
    fetcher: Arc<StubFetcher>,
    sink: Arc<RecordingSink>,
}

fn sources_for(identities: &[EnterpriseProviderIdentity]) -> Result<Sources, IdpKeySourcesError> {
    let fetcher = Arc::new(StubFetcher::default());
    let sink = Arc::new(RecordingSink::default());
    let sources = IdpKeySources::from_providers(
        identities,
        fetcher.clone(),
        &exchange_signer(),
        sink.clone(),
        RefreshPolicy::default(),
    )?;
    Ok(Sources {
        sources,
        fetcher,
        sink,
    })
}

#[tokio::test]
async fn lookup_returns_the_key_and_the_recorded_snapshot_digest() {
    let record = identity(Some(JWKS_URL), None);
    let sources = sources_for(std::slice::from_ref(&record)).unwrap();
    sources.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    let key = sources
        .sources
        .resolve(&record, "k1", JwsAlgorithm::RS256, T0)
        .await
        .unwrap();
    assert_eq!(key.jwk.kid.as_str(), "k1");
    let recorded = sources.sink.snapshots();
    assert_eq!(recorded.len(), 1);
    assert_eq!(key.snapshot_digest, recorded[0].digest().unwrap());
    assert!(sources.sources.get("acme-okta").is_some());
}

#[tokio::test]
async fn lookup_maps_resolution_errors() {
    let record = identity(Some(JWKS_URL), None);
    let sources = sources_for(std::slice::from_ref(&record)).unwrap();
    sources.fetcher.push(Err(JwksFetchError::Status(503)));
    assert_eq!(
        sources
            .sources
            .resolve(&record, "k1", JwsAlgorithm::RS256, T0)
            .await
            .err(),
        Some(RootExchangeError::KeysUnavailable(
            KeyResolutionError::Fetch(JwksFetchError::Status(503)).to_string()
        )),
    );
    sources.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    assert_eq!(
        sources
            .sources
            .resolve(&record, "k2", JwsAlgorithm::RS256, T0 + 60)
            .await
            .err(),
        Some(RootExchangeError::UnknownKid),
    );
    assert_eq!(
        sources
            .sources
            .resolve(&record, "k1", JwsAlgorithm::RS384, T0 + 60)
            .await
            .err(),
        Some(RootExchangeError::KeyAlgorithmMismatch),
    );
    assert_eq!(
        sources
            .sources
            .resolve(&record, "k1", JwsAlgorithm::ES256, T0 + 60)
            .await
            .err(),
        Some(RootExchangeError::KeyAlgorithmMismatch),
    );
}

#[tokio::test]
async fn lookup_refuses_unpinned_or_altered_provider_records() {
    let record = identity(Some(JWKS_URL), None);
    let sources = sources_for(std::slice::from_ref(&record)).unwrap();
    let other = edited(&record, |fields| {
        fields.provider_id = Identifier::new("other-okta").unwrap();
    });
    assert_eq!(
        sources
            .sources
            .resolve(&other, "k1", JwsAlgorithm::RS256, T0)
            .await
            .err(),
        Some(RootExchangeError::ProviderRecordMissing(
            "other-okta".to_owned()
        )),
    );
    let altered = edited(&record, |fields| {
        fields.trust_material_ref = Identifier::new("swapped").unwrap();
    });
    assert_eq!(
        sources
            .sources
            .resolve(&altered, "k1", JwsAlgorithm::RS256, T0)
            .await
            .err(),
        Some(RootExchangeError::ProviderIdentityMismatch(
            "acme-okta".to_owned()
        )),
    );
    assert_eq!(sources.fetcher.calls(), 0);
}

#[test]
fn sources_pin_each_provider_and_issuer_once() {
    let record = identity(Some(JWKS_URL), None);
    assert_eq!(
        sources_for(&[record.clone(), record.clone()]).err(),
        Some(IdpKeySourcesError::DuplicateProvider(
            "acme-okta".to_owned()
        )),
    );
    let same_issuer = edited(&record, |fields| {
        fields.provider_id = Identifier::new("acme-okta-2").unwrap();
    });
    assert_eq!(
        sources_for(&[record.clone(), same_issuer]).err(),
        Some(IdpKeySourcesError::DuplicateIssuer(ISSUER.to_owned())),
    );
    let weak = identity(None, Some(vec![rsa_key("weak", 1024)]));
    assert_eq!(
        sources_for(&[weak]).err(),
        Some(IdpKeySourcesError::Source {
            provider: "acme-okta".to_owned(),
            error: IdpKeySourceError::Document(JwksDocumentError::NoUsableKeys),
        }),
    );
}

#[test]
fn document_drops_keys_without_usable_verification_material() {
    let mut off_curve = ec_key("off-curve");
    off_curve["x"] = json!(b64(&[7; 32]));
    off_curve["y"] = json!(b64(&[9; 32]));
    let p521 = json!({
        "kid": "p521",
        "kty": "EC",
        "crv": "P-521",
        "x": b64(&[7; 66]),
        "y": b64(&[9; 66]),
    });
    let keys =
        admit_jwks_document(&jwks(&[off_curve.clone(), p521.clone(), ec_key("p256")])).unwrap();
    assert_eq!(kids(&keys), ["p256"]);
    assert_eq!(
        admit_jwks_document(&jwks(&[off_curve])),
        Err(JwksDocumentError::NoUsableKeys),
    );
    assert_eq!(
        admit_jwks_document(&jwks(&[p521])),
        Err(JwksDocumentError::NoUsableKeys),
    );
}

/// Signs as the exchange key, or with another key while `fail` is set, which
/// the identity check refuses.
struct SwitchableBackend {
    exchange: Ed25519Backend,
    other: Ed25519Backend,
    fail: AtomicBool,
}

impl SigningBackend for SwitchableBackend {
    fn public_key(&self) -> chio_core::error::Result<PublicKey> {
        self.exchange.public_key()
    }

    fn sign_bytes(
        &self,
        message: chio_core::crypto::SigningMessage<'_>,
    ) -> chio_core::error::Result<Signature> {
        if self.fail.load(Ordering::SeqCst) {
            self.other.sign_bytes(message)
        } else {
            self.exchange.sign_bytes(message)
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RefreshFailure {
    Http,
    Document,
    Sign,
    Sink,
}

/// k1 is installed at T0; at T0 + 60 an unknown `kid` refresh fails along
/// `path` (the sign and sink paths fetch a set that withdraws k1). Until a
/// refresh succeeds and is recorded, known k1 is refused; at T0 + 120 the
/// recorded refresh installs {k2}.
async fn failed_refresh_refuses_known_keys_until_recovery(path: RefreshFailure) {
    let backend = Arc::new(SwitchableBackend {
        exchange: Ed25519Backend::new(exchange_keypair()),
        other: Ed25519Backend::new(Keypair::from_seed(&[43; 32])),
        fail: AtomicBool::new(false),
    });
    let harness = harness_signed_by(
        &identity(Some(JWKS_URL), None),
        ExchangeSigner::new(backend.clone()).unwrap(),
    )
    .unwrap();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();

    harness.set_now(T0 + 60);
    let expected = match path {
        RefreshFailure::Http => {
            harness.fetcher.push(Err(JwksFetchError::Status(503)));
            KeyResolutionError::Fetch(JwksFetchError::Status(503))
        }
        RefreshFailure::Document => {
            harness.fetcher.push(Ok(b"not json".to_vec()));
            KeyResolutionError::Document(JwksDocumentError::Malformed)
        }
        RefreshFailure::Sign => {
            harness.fetcher.push(Ok(jwks(&[rsa_key("k2", 2048)])));
            backend.fail.store(true, Ordering::SeqCst);
            KeyResolutionError::SnapshotNotSigned(SnapshotNotSigned)
        }
        RefreshFailure::Sink => {
            harness.fetcher.push(Ok(jwks(&[rsa_key("k2", 2048)])));
            harness.sink.refuse.store(true, Ordering::SeqCst);
            KeyResolutionError::SnapshotNotRecorded(SnapshotNotRecorded)
        }
    };
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k2").await,
        Err(expected),
        "{path:?}"
    );

    for now in [T0 + 61, T0 + 119] {
        harness.set_now(now);
        assert_eq!(
            harness.resolve(JwsAlgorithm::RS256, "k1").await,
            Err(KeyResolutionError::KeySetUnavailable),
            "{path:?}"
        );
        assert_eq!(
            harness.refresh_if_due().await,
            Err(KeyResolutionError::KeySetUnavailable),
            "{path:?}"
        );
    }
    assert_eq!(harness.fetcher.calls(), 2, "{path:?}");
    assert_eq!(harness.sink.snapshots().len(), 1, "{path:?}");

    backend.fail.store(false, Ordering::SeqCst);
    harness.sink.refuse.store(false, Ordering::SeqCst);
    harness.fetcher.push(Ok(jwks(&[rsa_key("k2", 2048)])));
    harness.set_now(T0 + 120);
    let resolved = harness.resolve(JwsAlgorithm::RS256, "k2").await.unwrap();
    assert_eq!(resolved.snapshot.observed_at, T0 + 120, "{path:?}");
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::UnknownKid),
        "{path:?}"
    );
    assert_eq!(harness.fetcher.calls(), 3, "{path:?}");
    assert_eq!(harness.sink.snapshots().len(), 2, "{path:?}");
    assert_eq!(harness.sink.kids(1), ["k2"], "{path:?}");
}

#[tokio::test]
async fn failed_http_refresh_refuses_known_keys_until_recovery() {
    failed_refresh_refuses_known_keys_until_recovery(RefreshFailure::Http).await;
}

#[tokio::test]
async fn failed_document_refresh_refuses_known_keys_until_recovery() {
    failed_refresh_refuses_known_keys_until_recovery(RefreshFailure::Document).await;
}

#[tokio::test]
async fn failed_signing_refresh_refuses_known_keys_until_recovery() {
    failed_refresh_refuses_known_keys_until_recovery(RefreshFailure::Sign).await;
}

#[tokio::test]
async fn failed_recording_refresh_refuses_known_keys_until_recovery() {
    failed_refresh_refuses_known_keys_until_recovery(RefreshFailure::Sink).await;
}

#[tokio::test]
async fn cancelled_refresh_refuses_known_keys() {
    let harness = fetched_harness();
    harness.fetcher.push(Ok(jwks(&[rsa_key("k1", 2048)])));
    harness.resolve(JwsAlgorithm::RS256, "k1").await.unwrap();
    harness.set_now(T0 + 60);
    harness.fetcher.hang.store(true, Ordering::SeqCst);
    let cancelled = tokio::select! {
        biased;
        _ = harness.resolve(JwsAlgorithm::RS256, "k2") => false,
        () = std::future::ready(()) => true,
    };
    assert!(cancelled);
    assert_eq!(harness.fetcher.calls(), 2);
    harness.fetcher.hang.store(false, Ordering::SeqCst);
    harness.set_now(T0 + 61);
    assert_eq!(
        harness.resolve(JwsAlgorithm::RS256, "k1").await,
        Err(KeyResolutionError::KeySetUnavailable),
    );
}
