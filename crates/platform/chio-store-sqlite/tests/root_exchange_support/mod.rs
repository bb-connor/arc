#![allow(dead_code)]

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_core::root_authority::{
    DelegationContext, EnterpriseProviderIdentity, IdpKeySnapshot, LoadedRootPolicy, RootPolicy,
    SaltRef, Sha256Digest,
};
use chio_core::tenant_index::KeyedIndexValue;
use chio_core::StoreMutationFence;
use chio_store_sqlite::root_exchange_store::{
    BearerMapping, ContextOpening, MintOutcome, MintReplayNamespace, MintRequest,
    MintRevocationCheck, MintRevocationRefusal, RevocationCandidate, RootExchangeIntegrityError,
    RootExchangeStoreError, RootTags, SqliteRootExchangeStore,
};
use chio_store_sqlite::serving_owner::SqliteServingOwnerError;
use chio_store_sqlite::SqliteAuthorityStore;
use rusqlite::Transaction;
use serde_json::{json, Value};

#[path = "../work_authority_support/serving.rs"]
pub mod serving;
pub use serving::{Fixture, TestResult};

pub const NOW: u64 = 1_792_234_800;
pub const ID_JAG_RULE: &str = "okta-crm-agents";
pub const STATIC_RULE: &str = "dev-static";
pub const LOCAL_AS_RULE: &str = "local-as";
pub const OPERATOR_KEY_RULE: &str = "operator-key";
pub const CLIENT: &str = "mcp-client-claude";

const IDENTITY: &str = include_str!(
    "../../../../../spec/schemas/chio-wire/v1/root_authority/examples/valid/enterprise-provider-identity.spec-5-6-4.json"
);
const SNAPSHOT: &str = include_str!(
    "../../../../../spec/schemas/chio-wire/v1/root_authority/examples/valid/idp-key-snapshot.spec-5-6-4.json"
);

pub fn ms(seconds: u64) -> u64 {
    seconds * 1000
}

pub fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

pub fn policy_keypair() -> Keypair {
    Keypair::from_seed(&[1; 32])
}

pub fn exchange_keypair() -> Keypair {
    Keypair::from_seed(&[2; 32])
}

pub fn holder_keypair() -> Keypair {
    Keypair::from_seed(&[3; 32])
}

pub fn identity() -> TestResult<EnterpriseProviderIdentity> {
    Ok(serde_json::from_str(IDENTITY)?)
}

pub fn snapshot() -> TestResult<IdpKeySnapshot> {
    Ok(serde_json::from_str(SNAPSHOT)?)
}

fn grant(tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: "crm".into(),
        tool_name: tool.into(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

pub fn scope(tools: &[&str]) -> ChioScope {
    ChioScope {
        grants: tools.iter().map(|tool| grant(tool)).collect(),
        ..ChioScope::default()
    }
}

/// A signed, loaded root policy with one ID-JAG rule and one static bearer
/// rule. `policy_id` varies the digest.
pub fn loaded_policy(policy_id: &str) -> TestResult<LoadedRootPolicy> {
    let identity_digest = identity()?.digest()?;
    let ceiling = scope(&["search", "get", "update"]);
    let value = json!({
        "schema": "chio.root-policy.v1",
        "policy_id": policy_id,
        "policy_key": policy_keypair().public_key(),
        "exchange_keys": [exchange_keypair().public_key()],
        "rules": [
            {
                "rule_id": ID_JAG_RULE,
                "match": {
                    "anchor_kind": "oauth_id_jag",
                    "provider_record_id": "acme-okta",
                    "provider_identity_digest": identity_digest,
                    "allowed_algs": ["RS256"],
                    "claims": { "client_id": [CLIENT] }
                },
                "idp_scope_projection": { "crm.read": ["crm/search", "crm/get"] },
                "ceiling_scope": ceiling,
                "ceiling_scope_hash": Sha256Digest::of_scope(&ceiling)?,
                "recorded_claims": { "client_id": "plain" },
                "holder_classes": ["edge_session", "caller"],
                "capability_ttl_secs": 300,
                "max_assertion_lifetime_secs": 300,
                "max_clock_skew_secs": 30
            },
            {
                "rule_id": STATIC_RULE,
                "match": { "anchor_kind": "operator_static_bearer" },
                "ceiling_scope": scope(&["search"]),
                "ceiling_scope_hash": Sha256Digest::of_scope(&scope(&["search"]))?,
                "recorded_claims": {},
                "holder_classes": ["edge_session"],
                "principal": "dev:alice",
                "tenant_value": "dev"
            },
            {
                "rule_id": LOCAL_AS_RULE,
                "match": { "anchor_kind": "chio_local_as" },
                "ceiling_scope": scope(&["search"]),
                "ceiling_scope_hash": Sha256Digest::of_scope(&scope(&["search"]))?,
                "recorded_claims": {},
                "holder_classes": ["edge_session", "caller"]
            },
            {
                "rule_id": OPERATOR_KEY_RULE,
                "match": { "anchor_kind": "chio_operator_key" },
                "ceiling_scope": scope(&["search"]),
                "ceiling_scope_hash": Sha256Digest::of_scope(&scope(&["search"]))?,
                "recorded_claims": {},
                "holder_classes": ["edge_session", "caller"]
            }
        ],
        "disclosure": { "default": "committed" },
        "valid_from": NOW - 1_000,
        "valid_until": NOW + 100_000,
        "signature": "00".repeat(64)
    });
    let unsigned: RootPolicy = serde_json::from_value(value)?;
    let signature = policy_keypair().sign_canonical(&unsigned.signing_body())?.0;
    let mut fields = unsigned.into_fields();
    fields.signature = signature;
    let policy = RootPolicy::new(fields)?;
    Ok(policy.load(&policy_keypair().public_key(), NOW)?)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    IdJag,
    StaticBearer,
    LocalAs,
    OperatorKey,
}

/// One mint's inputs, owned, with knobs for every member a test varies.
pub struct Case {
    pub kind: Kind,
    pub capability_id: String,
    pub replay: u8,
    pub request: u8,
    pub artifact: u8,
    pub client_id: String,
    pub expires_at: u64,
    pub replay_retain_until: u64,
    pub namespace: MintReplayNamespace,
    pub tags: RootTags,
    pub candidates: Vec<RootTags>,
    pub bearer: Option<BearerMapping>,
    pub policy: LoadedRootPolicy,
    pub signer: Keypair,
    pub tools: Vec<&'static str>,
    pub with_identity: bool,
    pub with_snapshot: bool,
    pub openings: Vec<(String, [u8; 32])>,
    pub edit_context: fn(&mut Value),
}

pub fn tags(generation: u8) -> RootTags {
    let key_id = digest(0xa0 + generation);
    RootTags {
        subject: KeyedIndexValue {
            key_id,
            value: digest(0xb0 + generation),
        },
        tenant: KeyedIndexValue {
            key_id,
            value: digest(0xc0 + generation),
        },
    }
}

fn no_edit(_: &mut Value) {}

impl Case {
    pub fn id_jag(capability_id: &str) -> TestResult<Self> {
        Ok(Self {
            kind: Kind::IdJag,
            capability_id: capability_id.into(),
            replay: 0x11,
            request: 0x12,
            artifact: 0x13,
            client_id: CLIENT.into(),
            expires_at: NOW + 290,
            replay_retain_until: NOW + 360,
            namespace: MintReplayNamespace::AnchorKind,
            tags: tags(1),
            candidates: vec![tags(1)],
            bearer: None,
            policy: loaded_policy("rp_acme_prod")?,
            signer: exchange_keypair(),
            tools: vec!["search"],
            with_identity: true,
            with_snapshot: true,
            openings: vec![
                ("anchor.sub".into(), [7; 32]),
                ("anchor.tenant".into(), [8; 32]),
            ],
            edit_context: no_edit,
        })
    }

    pub fn static_bearer(capability_id: &str) -> TestResult<Self> {
        Ok(Self {
            kind: Kind::StaticBearer,
            client_id: "bearer_intake".into(),
            with_identity: false,
            with_snapshot: false,
            bearer: Some(BearerMapping {
                token_digest: digest(0x44),
                retain_until: NOW + 400,
            }),
            ..Self::id_jag(capability_id)?
        })
    }

    /// A root of a kind that is neither provider backed nor JWS verified and
    /// carries no bearer mapping.
    pub fn non_jws(kind: Kind, capability_id: &str) -> TestResult<Self> {
        Ok(Self {
            kind,
            with_identity: false,
            with_snapshot: false,
            ..Self::id_jag(capability_id)?
        })
    }

    pub fn root(&self) -> TestResult<CapabilityToken> {
        Ok(CapabilityToken::sign(
            CapabilityTokenBody {
                id: self.capability_id.clone(),
                issuer: self.signer.public_key(),
                subject: holder_keypair().public_key(),
                scope: scope(&self.tools),
                issued_at: NOW - 5,
                expires_at: self.expires_at,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &self.signer,
        )?)
    }

    pub fn context(&self) -> TestResult<DelegationContext> {
        let root_scope = scope(&self.tools);
        let mut value = match self.kind {
            Kind::IdJag => json!({
                "schema": "chio.delegation-context.v1",
                "anchor": {
                    "kind": "oauth_id_jag",
                    "issuer": "https://acme.okta.com",
                    "provider_record_id": "acme-okta",
                    "provider_identity_digest": identity()?.digest()?,
                    "key_snapshot_digest": snapshot()?.digest()?,
                    "kid": "k-okta-1",
                    "alg": "RS256",
                    "artifact_digest": digest(self.artifact),
                    "artifact_retained": false,
                    "replay_key_digest": digest(self.replay),
                    "token_iat": self.expires_at - 300,
                    "token_exp": self.expires_at,
                    "subject": { "commit": digest(0x21), "salt_ref": "anchor.sub" },
                    "tenant": { "commit": digest(0x22), "salt_ref": "anchor.tenant" },
                    "claims": { "client_id": CLIENT }
                },
                "exchange": {
                    "exchange_key": exchange_keypair().public_key(),
                    "exchanged_at": NOW - 5,
                    "request_digest": digest(self.request),
                    "holder": "edge_session"
                },
                "root_policy_rule_id": ID_JAG_RULE,
                "effective_root_scope_hash": Sha256Digest::of_scope(&root_scope)?
            }),
            Kind::StaticBearer | Kind::LocalAs | Kind::OperatorKey => json!({
                "schema": "chio.delegation-context.v1",
                "anchor": {
                    "kind": self.kind_name(),
                    "issuer": self.issuer(),
                    "artifact_retained": false,
                    "replay_key_digest": digest(self.replay),
                    "token_iat": NOW - 5,
                    "token_exp": self.expires_at,
                    "subject": { "commit": digest(0x21), "salt_ref": "anchor.sub" },
                    "tenant": { "commit": digest(0x22), "salt_ref": "anchor.tenant" },
                    "claims": {}
                },
                "exchange": {
                    "exchange_key": exchange_keypair().public_key(),
                    "exchanged_at": NOW - 5,
                    "request_digest": digest(self.request),
                    "holder": "edge_session"
                },
                "root_policy_rule_id": self.rule_id(),
                "effective_root_scope_hash": Sha256Digest::of_scope(&root_scope)?
            }),
        };
        (self.edit_context)(&mut value);
        Ok(serde_json::from_value(value)?)
    }

    fn kind_name(&self) -> &'static str {
        match self.kind {
            Kind::IdJag => "oauth_id_jag",
            Kind::StaticBearer => "operator_static_bearer",
            Kind::LocalAs => "chio_local_as",
            Kind::OperatorKey => "chio_operator_key",
        }
    }

    fn issuer(&self) -> &'static str {
        match self.kind {
            Kind::IdJag => "https://acme.okta.com",
            Kind::StaticBearer => "urn:chio:operator",
            Kind::LocalAs => "urn:chio:local-as",
            Kind::OperatorKey => "urn:chio:operator-key",
        }
    }

    fn rule_id(&self) -> &'static str {
        match self.kind {
            Kind::IdJag => ID_JAG_RULE,
            Kind::StaticBearer => STATIC_RULE,
            Kind::LocalAs => LOCAL_AS_RULE,
            Kind::OperatorKey => OPERATOR_KEY_RULE,
        }
    }

    pub fn build(&self) -> TestResult<Built> {
        Ok(Built {
            root: self.root()?,
            context: self.context()?,
            identity: if self.with_identity {
                Some(identity()?)
            } else {
                None
            },
            snapshot: if self.with_snapshot {
                Some(snapshot()?)
            } else {
                None
            },
            openings: self
                .openings
                .iter()
                .map(|(salt_ref, salt)| {
                    Ok(ContextOpening {
                        salt_ref: serde_json::from_value::<SaltRef>(json!(salt_ref))?,
                        salt: *salt,
                    })
                })
                .collect::<TestResult<Vec<_>>>()?,
        })
    }
}

pub struct Built {
    pub root: CapabilityToken,
    pub context: DelegationContext,
    pub identity: Option<EnterpriseProviderIdentity>,
    pub snapshot: Option<IdpKeySnapshot>,
    pub openings: Vec<ContextOpening>,
}

impl Built {
    pub fn request<'a>(&'a self, case: &'a Case) -> MintRequest<'a> {
        MintRequest {
            root: &self.root,
            context: &self.context,
            root_policy: &case.policy,
            provider_identity: self.identity.as_ref(),
            key_snapshot: self.snapshot.as_ref(),
            tags: case.tags,
            tag_candidates: &case.candidates,
            client_id: &case.client_id,
            artifact_digest: digest(case.artifact),
            replay_namespace: case.namespace,
            replay_retain_until: case.replay_retain_until,
            openings: &self.openings,
            bearer: case.bearer,
        }
    }
}

pub struct Admit;

impl MintRevocationCheck for Admit {
    fn refuse_revoked_root(
        &self,
        _: &Transaction<'_>,
        _: &RevocationCandidate<'_>,
    ) -> Result<(), MintRevocationRefusal> {
        Ok(())
    }
}

/// Refuses a candidate whose tag candidates contain `tag` under its key id,
/// as revocation entries match `(key_id, value)`.
pub struct RevokedTenant(pub RootTags);

impl MintRevocationCheck for RevokedTenant {
    fn refuse_revoked_root(
        &self,
        _: &Transaction<'_>,
        candidate: &RevocationCandidate<'_>,
    ) -> Result<(), MintRevocationRefusal> {
        if candidate
            .tag_candidates
            .iter()
            .any(|tags| tags.tenant == self.0.tenant)
        {
            return Err(MintRevocationRefusal::Revoked {
                entry_id: "rev-tenant-1".into(),
            });
        }
        Ok(())
    }
}

pub struct Failing;

impl MintRevocationCheck for Failing {
    fn refuse_revoked_root(
        &self,
        _: &Transaction<'_>,
        _: &RevocationCandidate<'_>,
    ) -> Result<(), MintRevocationRefusal> {
        Err(MintRevocationRefusal::Unavailable(
            "revocation store offline".into(),
        ))
    }
}

pub struct Env {
    pub fixture: Fixture,
    pub owner: SqliteAuthorityStore,
    pub store: SqliteRootExchangeStore,
    pub fence: StoreMutationFence,
}

impl Env {
    pub fn new() -> TestResult<Self> {
        let fixture = Fixture::new(ms(NOW))?;
        let owner = fixture.open()?;
        let store = owner.root_exchange_store();
        let fence = store.mutation_fence();
        Ok(Self {
            fixture,
            owner,
            store,
            fence,
        })
    }

    pub fn at(&self, seconds: u64) -> u64 {
        self.fixture.at(ms(seconds))
    }

    pub fn mint(
        &self,
        case: &Case,
        check: &dyn MintRevocationCheck,
        seconds: u64,
    ) -> TestResult<Result<MintOutcome, RootExchangeStoreError>> {
        let built = case.build()?;
        Ok(self.store.mint_anchored_root(
            &built.request(case),
            check,
            &self.fence,
            self.at(seconds),
        ))
    }

    /// Mint that must succeed, returning the capability id of the outcome
    /// and whether it was recovered.
    pub fn minted(
        &self,
        case: &Case,
        check: &dyn MintRevocationCheck,
        seconds: u64,
    ) -> TestResult<(String, bool)> {
        Ok(match self.mint(case, check, seconds)?? {
            MintOutcome::Minted(root) => (root.capability.id, false),
            MintOutcome::Recovered(root) => (root.capability.id, true),
        })
    }

    pub fn refused(
        &self,
        case: &Case,
        check: &dyn MintRevocationCheck,
        seconds: u64,
    ) -> TestResult<RootExchangeStoreError> {
        match self.mint(case, check, seconds)? {
            Ok(outcome) => Err(format!("mint unexpectedly succeeded: {outcome:?}").into()),
            Err(error) => Ok(error),
        }
    }

    /// Every replay binding as `(namespace, capability_id)`, ordered by
    /// namespace.
    pub fn replay_bindings(&self) -> TestResult<Vec<(String, Option<String>)>> {
        let raw = self.fixture.raw()?;
        let mut statement = raw.prepare(
            "SELECT namespace, capability_id FROM root_exchange_replay ORDER BY namespace",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Close the serving owner, edit the database with the named trigger
    /// dropped and recreated byte for byte, and return the reopen result.
    pub fn tamper_and_reopen(
        self,
        trigger: Option<&str>,
        sql: &str,
    ) -> TestResult<(Fixture, RootExchangeIntegrityError)> {
        let fixture = self.fixture;
        drop(self.store);
        drop(self.owner);
        let raw = fixture.raw()?;
        match trigger {
            Some(name) => {
                let definition: String = raw.query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [name],
                    |row| row.get(0),
                )?;
                raw.execute_batch(&format!("DROP TRIGGER {name};"))?;
                raw.execute_batch(sql)?;
                raw.execute_batch(&format!("{definition};"))?;
            }
            None => raw.execute_batch(sql)?,
        }
        drop(raw);
        let refusal = open_refusal(&fixture)?;
        Ok((fixture, refusal))
    }
}

/// The typed integrity refusal of a serving open that must fail.
pub fn open_refusal(fixture: &Fixture) -> TestResult<RootExchangeIntegrityError> {
    let error = match fixture.open() {
        Ok(_) => return Err("open unexpectedly succeeded".into()),
        Err(error) => error,
    };
    match error.downcast::<SqliteServingOwnerError>() {
        Ok(owner) => match *owner {
            SqliteServingOwnerError::RootExchange(refusal) => Ok(refusal),
            other => Err(format!("unexpected open refusal: {other}").into()),
        },
        Err(other) => Err(other),
    }
}
