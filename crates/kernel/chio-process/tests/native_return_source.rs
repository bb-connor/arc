//! Real Process source entry against the production library and real native
//! stores. It cannot fabricate a funding or capture role.
mod support;

use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_kernel::runtime::ToolServerConnection;
use chio_kernel::{ChioKernel, KernelError, NestedFlowBridge};
use chio_process::admission_test_support::{
    AdmissionCallBinding, AdmissionJournalWriter, AdmissionPreparedSource,
    AdmissionReturnSourceRequest, MAX_PREPARED_SOURCE_BYTES,
};
use chio_process::{ProcessError, ProcessLimits, ProcessRuntime};
use serde_json::Value;
use std::sync::Arc;
use support::{kernel, Result};

struct Server;

#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".into(), "read".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Ok(arguments)
    }
}

type TestResult = Result<()>;

fn append_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "tools".into(),
            tool_name: "append".into(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..Default::default()
    }
}

struct SourceFixture {
    _directory: tempfile::TempDir,
    runtime: ProcessRuntime,
    request: chio_kernel::ToolCallRequest,
    binding: AdmissionCallBinding,
    authority: String,
    kernel_key: String,
}

fn admitted_source_fixture() -> Result<SourceFixture> {
    let directory = tempfile::tempdir()?;
    let kernel: Arc<ChioKernel> = kernel(directory.path(), Box::new(Server))?;
    // This source test enters no Kernel dispatch and grants no native funding.
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    let capability = kernel.issue_capability(
        &Keypair::from_seed(&[30; 32]).public_key(),
        append_scope(),
        3600,
    )?;
    runtime.create_root(
        "root",
        &capability,
        ProcessLimits {
            max_processes: 2,
            max_depth: 1,
            max_calls: 2,
            state: Default::default(),
        },
    )?;
    let request = runtime.tool_request(
        "root",
        "publish",
        "tools",
        "append",
        serde_json::json!({"value": 1}),
    )?;
    let binding = runtime.admission_derive_call_binding("root", "publish", &request, false)?;
    runtime.admission_inspect(|store| {
        store.admit("root", "publish", &request, binding.binding_hash())
    })?;
    Ok(SourceFixture {
        _directory: directory,
        runtime,
        request,
        binding,
        authority: kernel
            .durable_admission_store_uuid()
            .ok_or("native authority absent")?
            .to_owned(),
        kernel_key: kernel.public_key().to_hex(),
    })
}

impl SourceFixture {
    fn prepare(&self) -> std::result::Result<AdmissionPreparedSource, ProcessError> {
        self.runtime.admission_inspect(|store| {
            store.prepare_native_return_source(
                &self.runtime,
                &AdmissionReturnSourceRequest {
                    process_id: "root",
                    operation_key: "publish",
                    request: &self.request,
                    binding: &self.binding,
                    known_outcome_only: false,
                    security_context: None,
                },
            )
        })
    }
}

#[test]
fn admitted_call_prepares_its_actual_process_return_source() -> TestResult {
    let fixture = admitted_source_fixture()?;
    let result = fixture.prepare();
    assert!(
        result.is_ok(),
        "the actual admitted source was not prepared: {:?}",
        result.as_ref().err()
    );
    let source = result?;
    assert_eq!(source.data().process_id, "root");
    assert_eq!(source.data().operation_key, "publish");
    assert_eq!(source.data().attempt, 1);
    assert_eq!(
        source.data().call_binding_digest,
        fixture.binding.binding_hash()
    );
    assert_eq!(fixture.runtime.process("root")?.tree_calls, 1);
    assert_eq!(
        source.data().journal_namespace,
        fixture.runtime.admission_namespace()
    );
    assert!(source.canonical_bytes().len() <= MAX_PREPARED_SOURCE_BYTES);
    Ok(())
}

#[test]
fn prepared_source_binds_the_actual_journal_cut_and_profile() -> TestResult {
    let fixture = admitted_source_fixture()?;
    let source = fixture.prepare()?;
    let data = source.data();
    assert_eq!(data.root_process_id, "root");
    assert_eq!(data.request_id, fixture.request.request_id);
    assert_eq!(data.current_request_digest, fixture.binding.request_hash());
    assert!(!data.known_outcome_only);
    assert!(data.original_nonce_pending);
    assert_eq!(data.original_nonce_digest, None);
    assert_eq!(data.host_route_digest, None);
    assert_eq!(data.host_profile_digest, None);
    assert_eq!(data.launch_receipt_digest, None);
    assert_eq!(data.security_context_digest, None);
    assert!(data.file_inode != 0);
    for value in [
        &data.kernel_key_digest,
        &data.catalog_digest,
        &data.cut_digest,
        &data.logical_request_digest,
        &data.call_binding_digest,
        &data.current_request_digest,
        &data.capability_digest,
    ] {
        assert_eq!(value.len(), 64, "source digest is not sha256 hex");
        assert!(!value.bytes().any(|byte| byte.is_ascii_uppercase()));
    }
    // The canonical bytes are exactly the validated source encoding.
    assert_eq!(
        chio_kernel::process_return_custody::canonical_process_return_source_data(data)?,
        source.canonical_bytes()
    );
    // Preparing the same admitted call again reproduces the identical cut.
    let replay = fixture.prepare()?;
    assert_eq!(replay.data(), data);
    assert_eq!(replay.canonical_bytes(), source.canonical_bytes());
    Ok(())
}

#[test]
fn unadmitted_call_has_no_actual_process_return_source() -> TestResult {
    let fixture = admitted_source_fixture()?;
    let request = fixture.runtime.tool_request(
        "root",
        "unadmitted",
        "tools",
        "append",
        serde_json::json!({"value": 1}),
    )?;
    let binding =
        fixture
            .runtime
            .admission_derive_call_binding("root", "unadmitted", &request, false)?;
    let result = fixture.runtime.admission_inspect(|store| {
        store.prepare_native_return_source(
            &fixture.runtime,
            &AdmissionReturnSourceRequest {
                process_id: "root",
                operation_key: "unadmitted",
                request: &request,
                binding: &binding,
                known_outcome_only: false,
                security_context: None,
            },
        )
    });
    assert!(matches!(
        result,
        Err(ProcessError::Sqlite(rusqlite::Error::QueryReturnedNoRows))
    ));
    Ok(())
}

#[test]
fn first_enrollment_is_priced_without_installing_or_crediting_a_bank() -> TestResult {
    let fixture = admitted_source_fixture()?;
    let source = fixture.prepare()?;
    let digest = sha256_hex(b"uninstalled native return account");
    let (prices, inventory, account) = fixture.runtime.admission_inspect(|store| {
        Ok((
            store.inspect_original_return_finishing_prices(&source),
            store.native_return_inventory(),
            store.load_native_return_account(&digest),
        ))
    })?;
    // The authenticated source can describe its first enrollment, including
    // the complete catalog activation. A price is not funding or installation.
    prices?;
    let Err(ProcessError::Configuration(message)) = account else {
        panic!("an absent bank produced an account instead of refusing");
    };
    assert_eq!(
        message,
        "Process complete original return bank has not been installed"
    );
    // The bank readback's inventory authenticates the exact supported
    // predecessor layout and reports its proven zeros as measured DATA for
    // the native owner to verify against its whole inverse.
    let inventory = inventory?;
    assert_eq!(inventory.account_count, 0);
    assert_eq!(inventory.phase_count, 0);
    assert_eq!(inventory.history_sequence, 0);
    assert_eq!(inventory.root_count, 1);
    assert_eq!(inventory.process_count, 1);
    if inventory.validate_data().is_err() {
        return Err("the predecessor inventory is not valid DATA".into());
    }
    Ok(())
}

#[test]
fn predecessor_enrollment_stream_is_authenticated_and_empty() -> TestResult {
    let fixture = admitted_source_fixture()?;
    let (counted, calls) = fixture.runtime.admission_inspect(|store| {
        let inventory = store.native_return_inventory()?;
        let mut calls = 0_u64;
        let counted = store.verify_retained_enrollments(&inventory, |_, _, _, _, _| {
            calls += 1;
            Ok(())
        });
        Ok((counted, calls))
    })?;
    assert!(matches!(counted, Ok(0)));
    assert_eq!(calls, 0);
    Ok(())
}

#[test]
fn reopening_the_compiled_layout_writes_no_schema() -> TestResult {
    let fixture = admitted_source_fixture()?;
    let path = fixture._directory.path().join("process.db");
    let cookie = |path: &std::path::Path| -> Result<i64> {
        let connection = rusqlite::Connection::open(path)?;
        Ok(connection.query_row("PRAGMA schema_version", [], |row| row.get(0))?)
    };
    let before = cookie(&path)?;
    let reopened = AdmissionJournalWriter::open(&path, &fixture.authority, &fixture.kernel_key)?;
    assert!(!reopened.startup_pending());
    drop(reopened);
    assert_eq!(
        cookie(&path)?,
        before,
        "opening a journal in the compiled layout rewrote its schema"
    );
    Ok(())
}
