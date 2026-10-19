use std::sync::{Arc, Mutex};

use chio_core::capability::attenuation::{scope_hash, DelegationLink, DelegationLinkBody};
use chio_core::capability::caveat::{
    CapabilitySecurityBinding, CAPABILITY_SECURITY_BINDING_SCHEMA,
};
use chio_core::capability::scope::{ChioScope, Operation, ResourceGrant, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
use chio_core::{Keypair, PublicKey, ResourceContent, ResourceDefinition, SessionId};
use chio_kernel::capability_lineage::CapabilitySnapshot;
use chio_kernel::{
    CapabilityIssuanceAdmissionAuthority, ChioKernel, KernelConfig, KernelError,
    MemoryBudgetConfig, ReceiptStore, ReceiptStoreError, ResourceProvider,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_security_types::ports::{IssuanceFreezeAdmissionQuery, PortError, PortResult};
use chio_store_sqlite::SqliteReceiptStore;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const TENANT: &str = "tenant-delegation";
pub const FROZEN: &str = "lineage-frozen";
pub const SIBLING: &str = "lineage-sibling";
pub const SESSION: &str = "session-delegation";
pub const URI: &str = "repo://docs/roadmap";
pub const SERVER: &str = "srv";

#[derive(Default)]
pub struct FreezeAuthority {
    queries: Mutex<Vec<IssuanceFreezeAdmissionQuery>>,
}

impl FreezeAuthority {
    pub fn queries(&self) -> TestResult<Vec<IssuanceFreezeAdmissionQuery>> {
        Ok(self
            .queries
            .lock()
            .map_err(|_| "freeze query lock poisoned")?
            .clone())
    }
}

impl CapabilityIssuanceAdmissionAuthority for FreezeAuthority {
    fn ensure_ready(&self) -> PortResult<()> {
        Ok(())
    }
    fn authorize(&self, query: &IssuanceFreezeAdmissionQuery) -> PortResult<()> {
        self.queries
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push(query.clone());
        if query.tenant_id.as_str() == TENANT && query.lineage_id.as_str() == FROZEN {
            return Err(PortError::conflict());
        }
        Ok(())
    }
}

struct DocsResourceProvider;

struct MissingAncestorEvidenceStore(Arc<SqliteReceiptStore>);

impl ReceiptStore for MissingAncestorEvidenceStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.0.append_chio_receipt(receipt)
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        self.0.append_child_receipt(receipt)
    }

    fn get_capability_snapshot(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, ReceiptStoreError> {
        let mut snapshot = self.0.get_capability_snapshot(capability_id)?;
        if let Some(snapshot) = &mut snapshot {
            snapshot.signed_capability = None;
        }
        Ok(snapshot)
    }
}

impl ResourceProvider for DocsResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        vec![ResourceDefinition {
            uri: URI.into(),
            name: "Roadmap".into(),
            title: None,
            description: None,
            mime_type: Some("text/markdown".into()),
            size: None,
            annotations: None,
            icons: None,
        }]
    }
    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        Ok((uri == URI).then(|| {
            vec![ResourceContent {
                uri: URI.into(),
                mime_type: Some("text/markdown".into()),
                text: Some("# Roadmap".into()),
                blob: None,
                annotations: None,
            }]
        }))
    }
}

pub struct Fixture {
    pub kernel: ChioKernel,
    pub issuer: Keypair,
    pub root: CapabilityToken,
    root_holder: Keypair,
    pub store: Arc<SqliteReceiptStore>,
    _directory: tempfile::TempDir,
    _clock: chio_test_support::clock::ClockScope,
}

impl Fixture {
    pub fn new() -> TestResult<Self> {
        let clock = chio_test_support::clock::scope_unix_secs(1_800_000_000);
        let issuer = Keypair::generate();
        let mut kernel = ChioKernel::new_with_clock(
            KernelConfig {
                keypair: issuer.clone(),
                ca_public_keys: Vec::new(),
                max_delegation_depth: 5,
                policy_hash: "a".repeat(64),
                allow_sampling: false,
                allow_sampling_tool_use: false,
                allow_elicitation: false,
                max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
                max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
                require_web3_evidence: false,
                allow_ephemeral_receipt_log: true,
                allow_ephemeral_revocation_store: true,
                checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
                retention_config: None,
                memory_budget: MemoryBudgetConfig::defaults(),
                deadlines: Default::default(),
            },
            chio_test_support::clock::clock(),
        );
        kernel.register_resource_provider(Box::new(DocsResourceProvider));
        let root_holder = Keypair::generate();
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: SERVER.into(),
                tool_name: "echo".into(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".into(),
                operations: vec![Operation::Read, Operation::Subscribe, Operation::Delegate],
            }],
            ..ChioScope::default()
        };
        let root = kernel.issue_capability(&root_holder.public_key(), scope.clone(), 300)?;
        let directory = tempfile::tempdir()?;
        let store = Arc::new(SqliteReceiptStore::open(
            directory.path().join("receipts.sqlite3"),
        )?);
        store.record_capability_snapshot(&root, None)?;
        kernel.set_receipt_store_handle(store.clone())?;
        let _ = kernel.set_capability_trust_root(issuer.public_key(), scope_hash(&scope)?);
        Ok(Self {
            kernel,
            issuer,
            root,
            root_holder,
            store,
            _directory: directory,
            _clock: clock,
        })
    }

    pub fn binding(&self, subject: &PublicKey, lineage: &str) -> CapabilitySecurityBinding {
        CapabilitySecurityBinding {
            schema: CAPABILITY_SECURITY_BINDING_SCHEMA.into(),
            tenant_id: TENANT.into(),
            lineage_id: lineage.into(),
            session_id: SESSION.into(),
            principal_id: subject.to_hex(),
            isolation_epoch_id: "epoch-delegation".into(),
            context_generation: 1,
            workload_id: "workload-delegation".into(),
            server_id: SERVER.into(),
            workload_signer_public_key: self.issuer.public_key().to_hex(),
        }
    }

    pub fn delegated(&self, id: &str, lineage: Option<&str>) -> TestResult<CapabilityToken> {
        self.delegated_from(&self.root, id, lineage)
    }

    /// The parent must share the root holder as its subject.
    pub fn delegated_from(
        &self,
        parent: &CapabilityToken,
        id: &str,
        lineage: Option<&str>,
    ) -> TestResult<CapabilityToken> {
        let child_holder = Keypair::generate();
        let link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent.id.clone(),
                delegator: parent.subject.clone(),
                delegatee: child_holder.public_key(),
                attenuations: Vec::new(),
                timestamp: parent.issued_at,
                scope_hash: Some(scope_hash(&parent.scope)?),
                aggregate_budget: None,
                cumulative_approval: None,
            },
            &self.root_holder,
        )?;
        let body = CapabilityTokenBody {
            id: id.into(),
            issuer: self.issuer.public_key(),
            subject: child_holder.public_key(),
            scope: parent.scope.clone(),
            issued_at: parent.issued_at,
            expires_at: parent.expires_at,
            delegation_chain: vec![link],
            aggregate_invocation_budget: None,
        };
        let token = match lineage {
            Some(lineage) => CapabilityToken::sign_with_security_binding(
                body,
                self.binding(&child_holder.public_key(), lineage),
                &self.issuer,
            )?,
            None => CapabilityToken::sign(body, &self.issuer)?,
        };
        assert!(token.verify_signature_at(parent.issued_at)?);
        Ok(token)
    }

    pub fn bound_root(&self) -> TestResult<CapabilityToken> {
        let mut body = self.root.body();
        body.id = "root-bound-public".into();
        Ok(CapabilityToken::sign_with_security_binding(
            body,
            self.binding(&self.root.subject, FROZEN),
            &self.issuer,
        )?)
    }

    /// A bound root whose signed snapshot is retained as a delegation parent.
    pub fn recorded_bound_root(&self, lineage: &str) -> TestResult<CapabilityToken> {
        let mut body = self.root.body();
        body.id = format!("root-bound-{lineage}");
        let root = CapabilityToken::sign_with_security_binding(
            body,
            self.binding(&self.root.subject, lineage),
            &self.issuer,
        )?;
        self.store.record_capability_snapshot(&root, None)?;
        Ok(root)
    }

    pub fn install(&mut self) -> TestResult<Arc<FreezeAuthority>> {
        let authority = Arc::new(FreezeAuthority::default());
        self.kernel
            .set_capability_issuance_admission_authority(authority.clone())?;
        Ok(authority)
    }

    pub fn omit_ancestor_evidence(&mut self) -> TestResult {
        self.kernel
            .set_receipt_store_handle(Arc::new(MissingAncestorEvidenceStore(self.store.clone())))?;
        Ok(())
    }

    pub fn open_for(&self, token: &CapabilityToken) -> TestResult<SessionId> {
        let session = self.kernel.open_session_with_id(
            SessionId::new(SESSION),
            token.subject.to_hex(),
            vec![token.clone()],
        )?;
        self.kernel.activate_session(&session)?;
        assert!(!self
            .kernel
            .session_has_resource_subscription(&session, URI)?);
        Ok(session)
    }
}
