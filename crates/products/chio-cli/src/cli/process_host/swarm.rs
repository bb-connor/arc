//! Bounded process fan-out using the existing live runtime admission authority.
//! Source activation happens once at initialization, never during recovery.

#[path = "swarm/graph.rs"]
mod graph;
#[path = "swarm/plan.rs"]
mod plan;
#[path = "swarm/requests.rs"]
mod requests;

use plan::{Graph, Plan};

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::{DurableAdmissionRuntime, PreparedPrivateDirectory};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, Signature};
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use chio_kernel::admission_operation::{AdmissionIdentifier, RuntimeReplaySourcePort};
use chio_kernel::ChioKernel;
use chio_process::{ProcessRoute, ProcessRuntime};
use chio_runtime_core::{
    ChioRuntimeAdmissionHook, RuntimeAdmissionProfile, SqliteRuntimeOrchestrationStore,
    CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::state::{error, identifier, read_json, write_secret, Record};
use crate::CliError;

const PROFILE: &str = "swarm-profile.json";
const SOURCE: &str = "swarm-runtime.db";
const SCHEMA: &str = "chio.process.swarm-profile.v1";

pub(super) fn bootstrap_host(
    directory: &PreparedPrivateDirectory,
    record: &Record,
    runtime: &ProcessRuntime,
    issuer: &Keypair,
) -> Result<(), CliError> {
    let receipt =
        requests::bootstrap(runtime, record, issuer, now_ms()?, "provision_process_host")?;
    write_secret(
        directory,
        std::ffi::OsStr::new("process-bootstrap.json"),
        &canonical_json_bytes(&receipt).map_err(error)?,
    )
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    bridge: String,
    protocol_target: String,
    selected_route: String,
    manifest_sha256: String,
}

impl Route {
    fn process_route(&self) -> Result<ProcessRoute, CliError> {
        ProcessRoute::new(&self.bridge, &self.protocol_target, &self.selected_route).map_err(error)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileBody {
    schema: String,
    runtime_id: String,
    record_sha256: String,
    admission: RuntimeAdmissionProfile,
    binding: RuntimeParticipantAuthorityBindingV1,
    routes: BTreeMap<String, Route>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedProfile {
    body: ProfileBody,
    signature: Signature,
}

fn hash<T: Serialize>(value: &T) -> Result<String, CliError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(error)
}

fn now_ms() -> Result<u64, CliError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(error)?
            .as_millis(),
    )
    .map_err(error)
}

pub(super) fn load_plan(path: &Path) -> Result<Plan, CliError> {
    plan::load(path)
}

fn routes(record: &Record) -> Result<BTreeMap<String, Route>, CliError> {
    let mut routes = BTreeMap::new();
    for manifest in &record.manifests {
        let manifest_sha256 = hash(manifest)?;
        let (bridge, identity) = if let Some(server) = record
            .config
            .servers
            .iter()
            .find(|s| s.id == manifest.server_id)
        {
            let launch = std::fs::read(
                server
                    .launch_policy
                    .as_ref()
                    .ok_or_else(|| error("missing launch policy"))?,
            )?;
            (
                "mcp",
                hash(&(server, &manifest_sha256, sha256_hex(&launch)))?,
            )
        } else {
            ("chio", hash(&(&manifest_sha256, &record.config.mailboxes))?)
        };
        routes.insert(
            manifest.server_id.clone(),
            Route {
                bridge: bridge.into(),
                protocol_target: format!("{bridge}://sha256/{identity}"),
                selected_route: format!("{bridge}:{}", manifest.server_id),
                manifest_sha256,
            },
        );
    }
    Ok(routes)
}

pub(super) fn provision(
    directory: &PreparedPrivateDirectory,
    record: &Record,
    runtime: &ProcessRuntime,
    issuer: &Keypair,
    authority: &DurableAdmissionRuntime,
    plan: Plan,
) -> Result<(), CliError> {
    if !record.config.spawn_templates.is_empty()
        || record.config.children.iter().any(|c| c.parent != "root")
    {
        return Err(error(
            "this swarm profile requires a fixed direct-child topology",
        ));
    }
    let now = now_ms()?;
    let root = runtime.process("root").map_err(error)?;
    let budget = root
        .capability
        .aggregate_invocation_budget
        .as_ref()
        .ok_or_else(|| error("swarm host needs a shared aggregate invocation budget"))?;
    let expires = root
        .capability
        .expires_at
        .checked_mul(1000)
        .ok_or_else(|| error("expiry overflow"))?;
    if expires <= now {
        return Err(error("root capability expired during initialization"));
    }
    let routes = routes(record)?;
    let bootstrap = requests::bootstrap(runtime, record, issuer, now, "provision_swarm")?;
    let mut bundles = Vec::new();
    for graph in &plan.graphs {
        let bundle = graph::build(
            graph,
            runtime,
            record,
            &routes,
            issuer,
            &bootstrap.id,
            now,
            expires,
            budget.max_invocations,
        )?;
        chio_swarm_authority::verify_swarm_authority_for_admission(&bundle, &[issuer.public_key()])
            .map_err(error)?;
        bundles.push(bundle);
    }
    let admission = RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.into(),
        profile_id: format!("process-{}", plan.profile_id),
        local_kernel_id: format!("kernel:{}", issuer.public_key().to_hex()),
        verifier_id: format!("did:chio:{}", issuer.public_key().to_hex()),
        issued_at_unix_ms: now,
        expires_at_unix_ms: expires,
    };
    let source =
        SqliteRuntimeOrchestrationStore::open(directory.path().join(SOURCE)).map_err(error)?;
    let mut calls = Vec::new();
    for (graph, bundle) in plan.graphs.iter().zip(&bundles) {
        calls.extend(requests::prepare(
            graph, bundle, runtime, record, &admission, &source,
        )?);
        source
            .insert_swarm_authority_bundle(bundle.clone())
            .map_err(error)?;
    }
    let calls = serde_json::json!({
        "schema": "chio.process.swarm-calls.v1", "runtime_id": runtime.runtime_id(), "calls": calls,
    });
    let (store, fence) = authority
        .local_runtime_participant()
        .ok_or_else(|| error("swarm source requires a local qualified authority"))?;
    let source_id =
        AdmissionIdentifier::try_new("source_id", format!("process-{}", plan.profile_id))
            .map_err(error)?;
    let runtime_id = AdmissionIdentifier::try_new("runtime_id", runtime.runtime_id().to_owned())
        .map_err(error)?;
    let expected = store
        .expect_runtime_replay_source(&source_id, &runtime_id, &source, &fence, now_ms()?)
        .map_err(error)?;
    store
        .import_runtime_replay_source(
            &runtime_id,
            expected.expectation_id(),
            &source,
            &fence,
            now_ms()?,
        )
        .map_err(error)?;
    let binding =
        RuntimeParticipantAuthorityBindingV1::new(runtime_id, expected.expectation_id().clone());
    store
        .activate_runtime_replay_source(&binding, &source, &fence, now_ms()?)
        .map_err(error)?;
    let body = ProfileBody {
        schema: SCHEMA.into(),
        runtime_id: runtime.runtime_id().into(),
        record_sha256: hash(record)?,
        admission,
        binding,
        routes,
    };
    let (signature, _) = issuer.sign_canonical(&body).map_err(error)?;
    let (bundle_name, bundle_bytes) =
        if let [bundle] = bundles.as_slice() {
            (
                "swarm-bundle.json",
                canonical_json_bytes(bundle).map_err(error)?,
            )
        } else {
            ("swarm-bundles.json", canonical_json_bytes(&serde_json::json!({
            "schema": "chio.process.swarm-authorities.v1", "runtime_id": runtime.runtime_id(),
            "graphs": bundles,
        })).map_err(error)?)
        };
    for (name, bytes) in [
        (
            "swarm-bootstrap.json",
            canonical_json_bytes(&bootstrap).map_err(error)?,
        ),
        (bundle_name, bundle_bytes),
        (
            "swarm-calls.json",
            canonical_json_bytes(&calls).map_err(error)?,
        ),
        (
            PROFILE,
            canonical_json_bytes(&SignedProfile { body, signature }).map_err(error)?,
        ),
    ] {
        write_secret(directory, std::ffi::OsStr::new(name), &bytes)?;
    }
    Ok(())
}

fn load(directory: &Path, issuer: &Keypair) -> Result<SignedProfile, CliError> {
    let signed: SignedProfile = read_json(&directory.join(PROFILE))?;
    if signed.body.schema != SCHEMA
        || !issuer
            .public_key()
            .verify_canonical(&signed.body, &signed.signature)
            .map_err(error)?
    {
        return Err(error("invalid process swarm profile signature or schema"));
    }
    Ok(signed)
}

pub(super) fn install(
    directory: &Path,
    authority: &DurableAdmissionRuntime,
    kernel: &mut ChioKernel,
) -> Result<(), CliError> {
    let key = authority.kernel_keypair();
    let signed = load(directory, &key)?;
    let record = super::state::read_current_record(&directory.join("host.json"))?;
    if signed.body.record_sha256 != hash(&record)? {
        return Err(error("swarm profile does not match the initialized host"));
    }
    let source = SqliteRuntimeOrchestrationStore::open(directory.join(SOURCE)).map_err(error)?;
    let (store, fence) = authority
        .local_runtime_participant()
        .ok_or_else(|| error("swarm source requires a local qualified authority"))?;
    let active = store
        .load_runtime_replay_migration(
            signed.body.binding.runtime_authority_id(),
            &fence,
            now_ms()?,
        )
        .map_err(error)?
        .ok_or_else(|| error("missing activated swarm source"))?;
    if !active.is_active() || active.expectation_id() != signed.body.binding.expectation_id() {
        return Err(error("swarm source generation is not active"));
    }
    source.verify_exact(active.snapshot()).map_err(error)?;
    kernel.set_federation_local_kernel_id(&signed.body.admission.local_kernel_id);
    kernel.set_runtime_admission_hook(Arc::new(
        ChioRuntimeAdmissionHook::new(signed.body.admission, source)
            .with_operation_owned_runtime_replay(signed.body.binding)
            .with_swarm_witness_keys(vec![key.public_key()]),
    ));
    kernel.require_swarm_admission();
    Ok(())
}

pub(super) fn host_routes(
    directory: &Path,
    record: &Record,
    kernel: &ChioKernel,
    issuer: &Keypair,
) -> Result<BTreeMap<String, ProcessRoute>, CliError> {
    // Ordinary hosts retain their pre-existing operation bindings. A governed
    // host requires its signed profile through the pinned policy above.
    if !directory.join(PROFILE).try_exists()? {
        return Ok(BTreeMap::new());
    }
    let signed = load(directory, issuer)?;
    let registry =
        chio_process::ProcessRegistry::open(directory.join("process.db"), kernel).map_err(error)?;
    if registry.runtime_id() != signed.body.runtime_id {
        return Err(error("swarm process namespace changed"));
    }
    if signed.body.record_sha256 != hash(record)?
        || hash(&signed.body.routes)? != hash(&routes(record)?)?
    {
        return Err(error(
            "connected tool routes differ from the signed swarm profile",
        ));
    }
    signed
        .body
        .routes
        .into_iter()
        .map(|(id, route)| Ok((id, route.process_route()?)))
        .collect()
}

#[cfg(test)]
mod plan_tests {
    use super::*;
    use serde_json::json;

    fn graph(id: &str, processes: &[&str]) -> Value {
        json!({
            "graph_id": id,
            "calls": processes.iter().map(|process| json!({
                "process": process, "operation_key": "publish",
                "server_id": "chio-ipc", "tool_name": "send_jobs",
                "arguments": {"message_key": process, "payload": {"from": process}},
            })).collect::<Vec<_>>(),
        })
    }

    fn read_plan(value: Value) -> Result<Plan, CliError> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("plan.json");
        std::fs::write(&path, serde_json::to_vec(&value).map_err(error)?)?;
        load_plan(&path)
    }

    #[test]
    fn independent_graphs_can_share_one_process_family() {
        let result = read_plan(json!({
            "schema": "chio.process.swarm-plan.v2", "profile_id": "shared-family",
            "graphs": [graph("first", &["alice", "bob"]), graph("second", &["carol", "dave"])],
        }));
        match result {
            Ok(plan) => {
                assert_eq!(plan.profile_id, "shared-family");
                assert_eq!(plan.graphs.len(), 2);
                assert_eq!(plan.graphs[0].graph_id, "first");
                assert_eq!(plan.graphs[1].calls[0].process, "carol");
            }
            Err(error) => panic!("valid independent graphs were rejected: {error}"),
        }
    }

    #[test]
    fn shared_family_plan_rejects_ambiguous_or_unbounded_graphs() {
        for graphs in [
            vec![],
            vec![graph("first", &["alice", "bob"])],
            vec![
                graph("same", &["alice", "bob"]),
                graph("same", &["carol", "dave"]),
            ],
            vec![
                graph("first", &["alice", "bob"]),
                graph("second", &["alice", "dave"]),
            ],
            vec![
                graph("first", &["alice", "bob"]),
                graph("second", &["root", "dave"]),
            ],
            vec![
                graph("first", &["alice", "bob"]),
                graph("second", &["carol"]),
            ],
        ] {
            assert!(read_plan(json!({
                "schema": "chio.process.swarm-plan.v2", "profile_id": "shared-family", "graphs": graphs,
            })).is_err());
        }
        let mut legacy = graph("legacy", &["alice", "bob"]);
        legacy["schema"] = json!("chio.process.swarm-plan.v1");
        assert!(read_plan(legacy.clone()).is_ok());
        legacy["graphs"] = json!([]);
        assert!(read_plan(legacy).is_err());
        let graphs = (0..9)
            .map(|index| {
                graph(
                    &format!("graph-{index}"),
                    &[&format!("worker-{index}-a"), &format!("worker-{index}-b")],
                )
            })
            .collect::<Vec<_>>();
        assert!(read_plan(json!({
            "schema": "chio.process.swarm-plan.v2", "profile_id": "too-many-graphs", "graphs": graphs,
        })).is_err());
        let children = (0..31)
            .map(|index| format!("worker-{index}"))
            .collect::<Vec<_>>();
        let children = children.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(read_plan(json!({
            "schema": "chio.process.swarm-plan.v2", "profile_id": "too-many-children",
            "graphs": [graph("first", &children), graph("second", &["alice", "bob"])],
        }))
        .is_err());
    }
}
