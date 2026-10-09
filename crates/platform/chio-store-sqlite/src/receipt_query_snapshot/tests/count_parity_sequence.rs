//! A deterministic-seed campaign over the published service. A fixed seed
//! interleaves signed appends across tenants, tools, outcomes and costs,
//! rotations into the archive, capability lineage refreshes, invalidations and
//! rebuilds. Every state a walker hold commits to a published lineage, so
//! every generation including each refresh, keeps its maintained counts equal
//! to `GROUP BY` over its own rows, compared inside that hold before any reader
//! can see it. Once settled, a version answers every page, total and point read
//! the campaign makes as the per-call authenticated path does, and a lineage
//! that was dropped never serves again.
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::receipt_query::{
    ReceiptQuery, ReceiptQuerySnapshotError, ReceiptReadContext, ReceiptSnapshotWatermark,
    MAX_QUERY_LIMIT,
};
use chio_kernel::{ReceiptStoreError, StoredToolReceipt};

use super::super::service::{
    GateAction, GatePoint, GenerationObserver, ReceiptQuerySnapshotConfig,
    ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
};
use super::query::{count_rows, grouped_counts_sql, grouped_rows, MAINTAINED_COUNTS_SQL};
use super::support::{keypair, other_keypair, per_call, substitute, Fixture, Spec};
use crate::receipt_store::support::{
    extract_receipt_attribution, receipt_cost_projection, receipt_decision_kind,
};

/// Seed of the default campaign; a failure reports it with the step.
const SEED: u64 = 0x6A09_E667_F3BC_C908;
const EPOCHS: usize = 5;
const LONG_SEED: u64 = 0xBB67_AE85_84CA_A73B;
const LONG_EPOCHS: usize = 30;
/// Operations per epoch. Each epoch owns a fresh store, which keeps the
/// per-call oracle's cost bounded.
const EPOCH_STEPS: usize = 40;
/// Claim entries per background checkpoint.
const BATCH: u64 = 8;
/// Tool receipts per epoch. The per-call listing of them all is one page.
const MAX_TOOL_RECEIPTS: usize = 48;
const TENANTS: [&str; 3] = ["tenant-a", "tenant-b", "tenant-c"];
const SERVERS: [&str; 3] = ["shell", "web", "files"];
const TOOLS: [&str; 3] = ["bash", "fetch", "read"];
const SIGNED_SUBJECTS: [&str; 3] = ["subject-0", "subject-1", "subject-2"];
const DEADLINE: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_millis(5);

fn config() -> ReceiptQuerySnapshotConfig {
    ReceiptQuerySnapshotConfig {
        step_rows: 3,
        insert_rows: 2,
        checkpoint_page: 2,
        // A page is never served from a version behind the observed head.
        head_wait: Duration::from_millis(100),
        max_staleness: Duration::ZERO,
        extension_tick: TICK,
        invalid_retry_backoff: Duration::from_millis(20),
        walker_busy_timeout: Duration::from_millis(50),
        ..ReceiptQuerySnapshotConfig::default()
    }
}

/// splitmix64: one seed replays one operation sequence.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    fn index(&mut self, len: usize) -> usize {
        usize::try_from(self.below(u64::try_from(len).unwrap())).unwrap()
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.index(items.len())]
    }

    fn percent(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    Append,
    AppendChild,
    Rotate,
    SignedLineage,
    UnsignedLineage,
    UpgradeLineage,
    Latch,
    ProjectionTamper,
    CustodyFailure,
    WriterPoison,
    CheckpointedSubstitution,
    VerifiedThenChanged,
    InterruptedCycle,
    MalformedLineage,
}

const WEIGHTS: [(Op, u64); 14] = [
    (Op::Append, 40),
    (Op::AppendChild, 4),
    (Op::Rotate, 8),
    (Op::SignedLineage, 6),
    (Op::UnsignedLineage, 6),
    (Op::UpgradeLineage, 3),
    (Op::Latch, 1),
    (Op::ProjectionTamper, 1),
    (Op::CustodyFailure, 1),
    (Op::WriterPoison, 1),
    (Op::CheckpointedSubstitution, 2),
    (Op::VerifiedThenChanged, 2),
    (Op::InterruptedCycle, 2),
    (Op::MalformedLineage, 2),
];

/// One appended tool receipt and where it is stored now.
struct Stored {
    spec: Spec,
    receipt: ChioReceipt,
    archived: bool,
}

/// A valid capability lineage row the campaign added.
struct Lineage {
    subject: String,
    token: CapabilityToken,
    /// Inserted without its signed token, as a pre-provenance local row.
    unsigned: bool,
}

#[derive(Debug, Clone, Copy)]
enum Malformed {
    /// Signed-token provenance with no token.
    MissingToken,
    /// A valid signed token whose subject is not the row's subject.
    MismatchedToken,
    /// Synthetic-anchor provenance on an identifier that is not an anchor.
    Anchor,
}

/// Epoch, step and operation in progress, for failure reports.
type Position = Cell<(usize, usize, &'static str)>;

/// What a campaign covered, reported when it passes.
#[derive(Debug, Default)]
struct Tally {
    /// Distinct published generations whose counts were compared in their
    /// own hold.
    generations: u64,
    /// Committed states compared in their own hold, staging and settlement
    /// holds included.
    held_states: u64,
    /// Comparisons the campaign itself made on the served version, one
    /// while extension may be mid-cycle and one once settled per operation.
    sampled_count_checks: u64,
    receipts: usize,
    archived: usize,
    lineage_rows: usize,
    dropped: usize,
    /// Batch operations that armed an extension gate before resuming.
    gated: u64,
    operations: BTreeMap<Op, u64>,
}

type Page = (Vec<u64>, u64, Option<u64>);

/// What the per-hold count comparison recorded.
#[derive(Default)]
struct Generations {
    /// Generations compared, per lineage.
    seen: BTreeMap<String, BTreeSet<u64>>,
    held_states: u64,
    /// Lineages whose owned rows the campaign edits on purpose before a read
    /// drops them; their counts are not compared again.
    tampered: BTreeSet<String>,
    /// The first state whose maintained counts differed from `GROUP BY`.
    mismatch: Option<String>,
}

/// Compare the maintained counts of every committed state with `GROUP BY`
/// over its rows, inside the hold that committed it.
fn generation_observer(record: Arc<Mutex<Generations>>) -> GenerationObserver {
    Arc::new(move |db, lineage, generation| {
        let compared =
            std::panic::catch_unwind(AssertUnwindSafe(|| (count_rows(db), grouped_rows(db))));
        let Ok(mut record) = record.lock() else {
            return;
        };
        record.held_states += 1;
        record
            .seen
            .entry(lineage.to_string())
            .or_default()
            .insert(generation);
        if record.tampered.contains(lineage) {
            return;
        }
        let differs = match compared {
            Ok((maintained, grouped)) if maintained == grouped => None,
            Ok((maintained, grouped)) => {
                Some(format!("maintained {maintained:?}, GROUP BY {grouped:?}"))
            }
            Err(_) => Some("the comparison could not read the snapshot".to_string()),
        };
        if let (Some(differs), None) = (differs, &record.mismatch) {
            record.mismatch = Some(format!("{lineage}:{generation}: {differs}"));
        }
    })
}

/// Sets its flag when dropped, also while unwinding.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn lineage_of(watermark: &ReceiptSnapshotWatermark) -> String {
    let id = &watermark.snapshot_id;
    id.split(':').next().unwrap_or_default().to_string()
}

fn admin(limit: usize) -> ReceiptQuery {
    ReceiptQuery {
        limit,
        ..ReceiptQuery::default().local_operator_admin()
    }
}

fn tenant(name: &str) -> ReceiptQuery {
    ReceiptQuery {
        limit: MAX_QUERY_LIMIT,
        ..ReceiptQuery::default().authenticated_tenant(name)
    }
}

fn is_invalid<T>(result: &Result<T, ReceiptStoreError>) -> bool {
    matches!(
        result,
        Err(ReceiptStoreError::QuerySnapshot(
            ReceiptQuerySnapshotError::Invalid(_)
        ))
    )
}

/// The page `limit` and `cursor` select from a whole filtered set.
fn slice(all: &[u64], limit: usize, cursor: Option<u64>) -> Page {
    let rows: Vec<u64> = all
        .iter()
        .copied()
        .filter(|seq| cursor.is_none_or(|cursor| *seq > cursor))
        .take(limit)
        .collect();
    let next = (rows.len() == limit)
        .then(|| rows.last().copied())
        .flatten();
    (rows, u64::try_from(all.len()).unwrap(), next)
}

/// A capability token for `capability`, held by the subject `serial` names.
fn token(capability: &str, serial: u64) -> CapabilityToken {
    let mut seed = [0x5a_u8; 32];
    seed[..8].copy_from_slice(&serial.to_le_bytes());
    let issuer = other_keypair();
    let grant = ToolGrant {
        server_id: "shell".to_string(),
        tool_name: "bash".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let body = CapabilityTokenBody {
        id: capability.to_string(),
        issuer: issuer.public_key(),
        subject: Keypair::from_seed(&seed).public_key(),
        scope: ChioScope {
            grants: vec![grant],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, &issuer).unwrap()
}

struct Campaign<'p> {
    seed: u64,
    weights: &'p [(Op, u64)],
    rng: Rng,
    position: &'p Position,
    fixture: Fixture,
    service: Option<ReceiptQuerySnapshots>,
    receipts: Vec<Stored>,
    children: u64,
    timestamp: u64,
    lineage: BTreeMap<String, Lineage>,
    serial: u64,
    served: String,
    dropped: BTreeSet<String>,
    sampled: Cell<u64>,
    generations: Arc<Mutex<Generations>>,
    gated: Cell<u64>,
    /// The per-call listing of every tool receipt, until the next append.
    listing: Option<Vec<StoredToolReceipt>>,
}

impl<'p> Campaign<'p> {
    fn start(seed: u64, weights: &'p [(Op, u64)], epoch_seed: u64, position: &'p Position) -> Self {
        let mut campaign = Self {
            seed,
            weights,
            rng: Rng(epoch_seed),
            position,
            fixture: Fixture::new(BATCH),
            service: None,
            receipts: Vec::new(),
            children: 0,
            timestamp: 1_700_000_000,
            lineage: BTreeMap::new(),
            serial: 0,
            served: String::new(),
            dropped: BTreeSet::new(),
            sampled: Cell::new(0),
            generations: Arc::default(),
            gated: Cell::new(0),
            listing: None,
        };
        for _ in 0..12 {
            campaign.append_one();
        }
        campaign.append_child();
        campaign.rotate();
        let store = campaign.fixture.store.clone();
        let observer = generation_observer(Arc::clone(&campaign.generations));
        let service = ReceiptQuerySnapshots::start_observed_for_test(store, config(), observer);
        campaign.service = Some(service.unwrap());
        let deadline = Instant::now() + DEADLINE;
        campaign.served = loop {
            let status = campaign.service().status();
            if let (ReceiptQuerySnapshotState::Ready, Some(watermark)) =
                (&status.state, status.watermark.as_ref())
            {
                break lineage_of(watermark);
            }
            campaign.within(deadline, "the first lineage");
            std::thread::sleep(TICK);
        };
        campaign.settle();
        campaign.verify();
        campaign
    }

    fn service(&self) -> &ReceiptQuerySnapshots {
        self.service.as_ref().unwrap()
    }

    fn fail(&self, message: impl std::fmt::Display) -> ! {
        let (epoch, step, op) = self.position.get();
        panic!(
            "seed {:#x} epoch {epoch} step {step} ({op}): {message}",
            self.seed
        )
    }

    fn within(&self, deadline: Instant, what: &str) {
        if Instant::now() > deadline {
            self.fail(format!("timed out waiting for {what}"));
        }
    }

    fn run(mut self, steps: usize, tally: &mut Tally) {
        let epoch = self.position.get().0;
        for step in 0..steps {
            self.position.set((epoch, step, "choose"));
            let mut op = self.choose();
            self.position.set((epoch, step, op_name(op)));
            if !self.apply(op) {
                op = if self.receipts.len() < MAX_TOOL_RECEIPTS {
                    Op::Append
                } else {
                    Op::AppendChild
                };
                self.position.set((epoch, step, op_name(op)));
                assert!(self.apply(op));
            }
            *tally.operations.entry(op).or_default() += 1;
        }
        self.every_generation_matched();
        self.service.take().unwrap().shutdown();
        tally.sampled_count_checks += self.sampled.get();
        let generations = self.generations.lock().unwrap();
        tally.held_states += generations.held_states;
        tally.generations += generations
            .seen
            .values()
            .map(|seen| u64::try_from(seen.len()).unwrap())
            .sum::<u64>();
        drop(generations);
        tally.gated += self.gated.get();
        tally.receipts += self.receipts.len();
        tally.archived += self
            .receipts
            .iter()
            .filter(|stored| stored.archived)
            .count();
        tally.lineage_rows += self.lineage.len();
        tally.dropped += self.dropped.len();
    }

    fn choose(&mut self) -> Op {
        let total: u64 = self.weights.iter().map(|(_, weight)| weight).sum();
        let mut roll = self.rng.below(total);
        for &(op, weight) in self.weights {
            if roll < weight {
                return op;
            }
            roll -= weight;
        }
        Op::Append
    }

    /// Apply `op`; false when the store offers it no target.
    fn apply(&mut self, op: Op) -> bool {
        match op {
            Op::Append => self.append(),
            Op::AppendChild => {
                self.append_child();
                self.after_valid_change();
                true
            }
            Op::Rotate => {
                self.rotate();
                self.after_valid_change();
                true
            }
            Op::SignedLineage => self.add_lineage(false),
            Op::UnsignedLineage => self.add_lineage(true),
            Op::UpgradeLineage => self.upgrade_lineage(),
            Op::Latch => self.latch(),
            Op::ProjectionTamper => self.projection_tamper(),
            Op::CustodyFailure => self.custody_failure(),
            Op::WriterPoison => self.writer_poison(),
            Op::CheckpointedSubstitution => self.checkpointed_substitution(),
            Op::VerifiedThenChanged => self.verified_then_changed(),
            Op::InterruptedCycle => self.interrupted_cycle(),
            Op::MalformedLineage => self.malformed_lineage(),
        }
    }

    fn next_serial(&mut self) -> u64 {
        self.serial += 1;
        self.serial
    }

    // Valid source changes.

    fn next_spec(&mut self) -> Spec {
        let index = u64::try_from(self.receipts.len()).unwrap();
        self.timestamp += self.rng.below(1_800);
        let mut spec = Spec::new(format!("sequence-{index:04}"), self.timestamp);
        spec.tenant = match self.rng.below(4) {
            0 => None,
            n => Some(TENANTS[usize::try_from(n - 1).unwrap()].to_string()),
        };
        // Capabilities rotate as the history grows, so fresh ones keep
        // appearing whose receipts are all live.
        let epoch = (index / 16).saturating_sub(self.rng.below(2));
        spec.capability = format!("cap-{epoch}-{}", self.rng.below(4));
        spec.tool_server = (*self.rng.pick(&SERVERS)).to_string();
        spec.tool_name = (*self.rng.pick(&TOOLS)).to_string();
        spec.deny = self.rng.percent(30);
        spec.cost = match self.rng.below(4) {
            0 => Some((self.rng.below(1_000), "USD")),
            1 => Some((self.rng.below(1_000), "EUR")),
            _ => None,
        };
        spec.subject = self
            .rng
            .percent(30)
            .then(|| (*self.rng.pick(&SIGNED_SUBJECTS)).to_string());
        spec
    }

    fn append_one(&mut self) {
        let spec = self.next_spec();
        let receipt = spec.sign(&keypair());
        let store = &self.fixture.store;
        store.append_chio_receipt_returning_seq(&receipt).unwrap();
        self.listing = None;
        self.receipts.push(Stored {
            spec,
            receipt,
            archived: false,
        });
    }

    fn append(&mut self) -> bool {
        let room = MAX_TOOL_RECEIPTS.saturating_sub(self.receipts.len());
        if room == 0 {
            return false;
        }
        for _ in 0..(1 + self.rng.index(2)).min(room) {
            self.append_one();
        }
        self.fixture.flush();
        self.after_valid_change();
        true
    }

    fn append_child(&mut self) {
        self.children += 1;
        self.timestamp += self.rng.below(600);
        let id = format!("sequence-child-{}", self.children);
        self.fixture.append_child(&id, self.timestamp);
        self.fixture.flush();
    }

    /// Archive every checkpointed receipt older than a cutoff inside the
    /// history, then record which receipts left the live store.
    fn rotate(&mut self) {
        let bound = (self.receipts.len() * 3 / 4).max(1);
        let cutoff = self.receipts[self.rng.index(bound)].receipt.timestamp + 1;
        self.fixture.rotate(cutoff);
        let connection = self.fixture.tamper();
        let mut statement = connection
            .prepare("SELECT receipt_id FROM chio_tool_receipts")
            .unwrap();
        let live: BTreeSet<String> = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        drop(statement);
        for stored in &mut self.receipts {
            stored.archived = !live.contains(&stored.receipt.id);
        }
    }

    /// Capabilities without lineage, with whether they have unattributed
    /// receipts that are live and that are archived.
    fn unattributed(&self) -> BTreeMap<String, (bool, bool)> {
        let mut capabilities: BTreeMap<String, (bool, bool)> = BTreeMap::new();
        for stored in &self.receipts {
            let capability = stored.spec.capability.clone();
            let entry = capabilities.entry(capability).or_default();
            if stored.spec.subject.is_none() {
                if stored.archived {
                    entry.1 = true;
                } else {
                    entry.0 = true;
                }
            }
        }
        capabilities.retain(|capability, _| !self.lineage.contains_key(capability));
        capabilities
    }

    /// Add a valid lineage row. Lineage arrives before any unattributed
    /// receipt of its capability is archived: an archive keeps the lineage
    /// rows it was written with.
    fn add_lineage(&mut self, unsigned: bool) -> bool {
        let live: Vec<String> = self
            .unattributed()
            .into_iter()
            .filter(|(_, (live, archived))| *live && !*archived)
            .map(|(capability, _)| capability)
            .collect();
        let capability = if !live.is_empty() && self.rng.percent(80) {
            self.rng.pick(&live).clone()
        } else {
            // A capability no receipt uses yet: later appends take its
            // subject when they are written.
            let epoch = u64::try_from(self.receipts.len()).unwrap() / 16 + 1;
            let capability = format!("cap-{epoch}-{}", self.rng.below(4));
            if self.lineage.contains_key(&capability) {
                return false;
            }
            capability
        };
        let serial = self.next_serial();
        let token = token(&capability, serial);
        let subject = token.subject.to_hex();
        if unsigned {
            self.insert_lineage(&capability, &subject, &token, "legacy_projection", None);
        } else {
            let store = &self.fixture.store;
            store.record_capability_snapshot(&token, None).unwrap();
        }
        let row = Lineage {
            subject,
            token,
            unsigned,
        };
        self.lineage.insert(capability, row);
        self.after_valid_change();
        true
    }

    /// Upgrade an unsigned row to its signed token, before any receipt of its
    /// capability is archived.
    fn upgrade_lineage(&mut self) -> bool {
        let archived: BTreeSet<&str> = self
            .receipts
            .iter()
            .filter(|stored| stored.archived)
            .map(|stored| stored.spec.capability.as_str())
            .collect();
        let candidates: Vec<String> = self
            .lineage
            .iter()
            .filter(|(capability, row)| row.unsigned && !archived.contains(capability.as_str()))
            .map(|(capability, _)| capability.clone())
            .collect();
        if candidates.is_empty() {
            return false;
        }
        let capability = self.rng.pick(&candidates).clone();
        let row = self.lineage.get_mut(&capability).unwrap();
        let store = &self.fixture.store;
        store.record_capability_snapshot(&row.token, None).unwrap();
        row.unsigned = false;
        self.after_valid_change();
        true
    }

    fn insert_lineage(
        &self,
        capability: &str,
        subject: &str,
        token: &CapabilityToken,
        provenance: &str,
        signed: Option<String>,
    ) {
        let grants = serde_json::to_string(&token.scope).unwrap();
        let issued = i64::try_from(token.issued_at).unwrap();
        let expires = i64::try_from(token.expires_at).unwrap();
        self.fixture
            .tamper()
            .execute(
                "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at,
                    expires_at, grants_json, delegation_depth, provenance, signed_capability_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)",
                rusqlite::params![
                    capability,
                    subject,
                    token.issuer.to_hex(),
                    issued,
                    expires,
                    grants,
                    provenance,
                    signed
                ],
            )
            .unwrap();
    }

    /// A valid change: one version sampled while extension may be mid-cycle,
    /// then the settled version that covers the change.
    fn after_valid_change(&mut self) {
        self.counts_match_group_by();
        self.settle();
        self.verify();
    }

    // Invalidations. Each drops the served lineage, which never serves again;
    // a new authenticated lineage replaces it.

    fn lease(&self) -> u64 {
        let lease = self.service().lease_for_test();
        lease.unwrap_or_else(|error| self.fail(format!("no lease on the served lineage: {error}")))
    }

    /// The read that met the failure refused as invalid, and a read after it
    /// is served by another lineage or refused.
    fn refused(&self, outcome: &Result<(), ReceiptStoreError>, what: &str) {
        if !is_invalid(outcome) {
            self.fail(format!("{what} was answered as {outcome:?}"));
        }
        self.not_served_again(what);
    }

    fn not_served_again(&self, what: &str) {
        if let Ok(page) = self.service().query_receipts(&admin(1)) {
            let lineage = page.snapshot.as_ref().map(lineage_of).unwrap_or_default();
            if lineage == self.served || self.dropped.contains(&lineage) {
                self.fail(format!("lineage {lineage} served again after {what}"));
            }
        }
    }

    fn latch(&mut self) -> bool {
        let epoch = self.lease();
        self.service().invalidate_for_test("sequence latch");
        self.not_served_again("a latched invalidation");
        self.replace_dropped(epoch);
        true
    }

    /// Move one receipt into another tenant in the owned snapshot only, then
    /// read it as that tenant.
    fn projection_tamper(&mut self) -> bool {
        let tenants: Vec<(String, String)> = self
            .receipts
            .iter()
            .filter_map(|stored| {
                let tenant = stored.receipt.tenant_id.clone()?;
                Some((stored.receipt.id.clone(), tenant))
            })
            .collect();
        if tenants.is_empty() {
            return false;
        }
        let (moved, from) = self.rng.pick(&tenants).clone();
        let Some((other, into)) = tenants.iter().find(|(_, tenant)| *tenant != from).cloned()
        else {
            return false;
        };
        let epoch = self.lease();
        let mut generations = self.generations.lock().unwrap();
        generations.tampered.insert(self.served.clone());
        drop(generations);
        let changed = self.service().execute_on_snapshot_for_test(
            "UPDATE snapshot_tool_receipt \
             SET tenant = (SELECT tenant FROM snapshot_tool_receipt WHERE receipt_id = ?2) \
             WHERE receipt_id = ?1",
            rusqlite::params![moved, other],
        );
        if changed != 1 {
            self.fail(format!("the owned projection of {moved} was not changed"));
        }
        let context = ReceiptReadContext::authenticated_tenant(into);
        let read = self.service().load_receipt(&moved, &context).map(drop);
        self.refused(&read, "a tenant projection mismatch");
        self.replace_dropped(epoch);
        true
    }

    /// Change the mode of the published backing file for one read.
    #[cfg(target_os = "linux")]
    fn custody_failure(&mut self) -> bool {
        use std::os::unix::fs::PermissionsExt;
        let Some(path) = self.service().backing_path_for_test() else {
            self.fail("a Linux snapshot has no private backing file");
        };
        let epoch = self.lease();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let read = self.service().query_receipts(&admin(5)).map(drop);
        // The dropped lineage may already have removed its file.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        self.refused(&read, "a custody failure");
        self.replace_dropped(epoch);
        true
    }

    #[cfg(not(target_os = "linux"))]
    fn custody_failure(&mut self) -> bool {
        self.latch()
    }

    /// Diverge the newest live checkpoint out of band so the writer's own
    /// reseed poisons its head, then repair it and reseed.
    fn writer_poison(&mut self) -> bool {
        let newest: Option<(i64, i64)> = self
            .fixture
            .tamper()
            .query_row(
                "SELECT checkpoint_seq, batch_end_seq FROM kernel_checkpoints \
                 ORDER BY checkpoint_seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        let Some((checkpoint, end)) = newest else {
            return false;
        };
        let original = format!("\"batch_end_seq\":{end}");
        let diverged = format!("\"batch_end_seq\":{}", end - 1);
        let rewrite = |from: &str, to: &str| {
            let sql = "UPDATE kernel_checkpoints \
                       SET statement_json = replace(statement_json, ?1, ?2) WHERE checkpoint_seq = ?3";
            let tamper = self.fixture.tamper();
            tamper
                .execute(sql, rusqlite::params![from, to, checkpoint])
                .unwrap()
        };
        let epoch = self.lease();
        assert_eq!(rewrite(&original, &diverged), 1);
        if self.fixture.store.reseed_verified_head().is_ok() {
            self.fail(format!(
                "checkpoint {checkpoint} diverged but the writer reseeded"
            ));
        }
        let read = self.service().query_receipts(&admin(1)).map(drop);
        self.refused(&read, "a poisoned writer head");
        assert_eq!(rewrite(&diverged, &original), 1);
        self.fixture.store.reseed_verified_head().unwrap();
        self.replace_dropped(epoch);
        true
    }

    fn checkpointed_through(&self) -> u64 {
        let end: i64 = self
            .fixture
            .tamper()
            .query_row(
                "SELECT COALESCE(MAX(batch_end_seq), 0) FROM kernel_checkpoints",
                [],
                |row| row.get(0),
            )
            .unwrap();
        u64::try_from(end).unwrap()
    }

    /// Pause extension at the settled head and complete the open checkpoint
    /// batch with new receipts. Returns the head and the first new receipt.
    fn paused_batch(&mut self) -> Option<(u64, usize)> {
        let batch = usize::try_from(BATCH).unwrap();
        if self.receipts.len() + batch > MAX_TOOL_RECEIPTS {
            return None;
        }
        self.service().pause_extension_for_test(true);
        let head = self.await_pause();
        let needed = BATCH - (head - self.checkpointed_through()) % BATCH;
        let first = self.receipts.len();
        for _ in 0..needed {
            self.append_one();
        }
        self.fixture.flush();
        let deadline = Instant::now() + DEADLINE;
        while self.checkpointed_through() < head + needed {
            self.within(deadline, "the checkpoint covering the new batch");
            std::thread::sleep(Duration::from_millis(2));
        }
        Some((head, first))
    }

    /// Resume extension, first arming `gate` unless a cycle that passed the
    /// pause check before it was set already ingested past `head`. Returns
    /// whether the gate is armed.
    fn resume(&self, head: u64, gate: (GatePoint, GateAction, u32)) -> bool {
        let watermark = self.service().status().watermark;
        let raced = watermark.map(|w| w.through_entry_seq) != Some(head);
        if !raced {
            let (point, action, skip) = gate;
            self.service().arm_gate_for_test(point, action, skip);
            self.gated.set(self.gated.get() + 1);
        }
        self.service().pause_extension_for_test(false);
        !raced
    }

    /// The receipt at or after `first` that a batch operation replaces, half
    /// of the time the first one, and a validly signed replacement for it.
    fn replacement(&mut self, first: usize) -> (ChioReceipt, ChioReceipt) {
        let target = if self.rng.percent(50) {
            first
        } else {
            first + self.rng.index(self.receipts.len() - first)
        };
        let mut spec = self.receipts[target].spec.clone();
        spec.timestamp += 1;
        (self.receipts[target].receipt.clone(), spec.sign(&keypair()))
    }

    /// Complete a checkpoint batch while extension is paused, replace one of
    /// its receipts and source rows with another validly signed receipt, and
    /// resume. The walker stops after staging the batch and before checking
    /// the covering root: nothing of the batch is visible there, and once the
    /// root mismatches the lineage drops without exposing the replacement.
    fn checkpointed_substitution(&mut self) -> bool {
        let before = u64::try_from(self.receipts.len()).unwrap();
        let epoch = self.lease();
        let Some((head, first)) = self.paused_batch() else {
            return false;
        };
        let (original, replacement) = self.replacement(first);
        substitute(&self.fixture, &original, &replacement);
        let held = self.resume(head, (GatePoint::Settlement, GateAction::Hold, 0));
        let unchanged = || {};
        let gate = held.then_some(&unchanged as &dyn Fn());
        let exposures = self.watch_substitution(&replacement.id, held.then_some(before), gate);
        if !exposures.is_empty() {
            self.fail(format!(
                "receipt {} was served before the checkpoint covering it was verified: {exposures:?}",
                replacement.id
            ));
        }
        substitute(&self.fixture, &replacement, &original);
        self.replace_dropped(epoch);
        true
    }

    /// Hold extension after it verified a checkpoint root and before it
    /// publishes the batch, then replace one receipt of the batch. The
    /// publication re-reads every entry, so the replacement is never served
    /// and the lineage drops.
    fn verified_then_changed(&mut self) -> bool {
        let epoch = self.lease();
        let Some((head, first)) = self.paused_batch() else {
            return false;
        };
        let (original, replacement) = self.replacement(first);
        if !self.resume(head, (GatePoint::Publication, GateAction::Hold, 0)) {
            self.after_valid_change();
            return true;
        }
        let change = || substitute(&self.fixture, &original, &replacement);
        let exposures = self.watch_substitution(&replacement.id, None, Some(&change as &dyn Fn()));
        if !exposures.is_empty() {
            self.fail(format!(
                "receipt {} was published although it changed after its root was verified: {exposures:?}",
                replacement.id
            ));
        }
        substitute(&self.fixture, &replacement, &original);
        self.replace_dropped(epoch);
        true
    }

    /// Interrupt one extension cycle as contention at a gate after it staged
    /// a valid checkpointed batch; the next cycle stages it again and
    /// publishes it.
    fn interrupted_cycle(&mut self) -> bool {
        let Some((head, _)) = self.paused_batch() else {
            return false;
        };
        let gate = if self.rng.percent(50) {
            (GatePoint::Settlement, GateAction::Interrupt, 0)
        } else {
            let skip = u32::try_from(self.rng.below(3)).unwrap();
            (GatePoint::Publication, GateAction::Interrupt, skip)
        };
        self.resume(head, gate);
        self.after_valid_change();
        self.service().release_gate_for_test();
        true
    }

    /// Read the batch until the served lineage drops, from three point
    /// readers and this thread's pages, and return every exposure of
    /// `replacement` or count above `bound`. With `held`, the extension waits
    /// at its armed gate while `held` runs and the reads and counts are
    /// checked, and is then released.
    fn watch_substitution(
        &self,
        replacement: &str,
        bound: Option<u64>,
        held: Option<&dyn Fn()>,
    ) -> Vec<String> {
        let service = self.service();
        let stop = AtomicBool::new(false);
        let exposures = Mutex::new(Vec::new());
        let expose = |what: String| exposures.lock().unwrap().push(what);
        let probe = || {
            if let Ok(page) = service.query_receipts(&admin(MAX_QUERY_LIMIT)) {
                let id = page.snapshot.as_ref().map(|w| w.snapshot_id.clone());
                if page
                    .receipts
                    .iter()
                    .any(|row| row.receipt.id == replacement)
                {
                    expose(format!("page row from {id:?}"));
                }
                if bound.is_some_and(|bound| page.total_count > bound) {
                    expose(format!("page total {} from {id:?}", page.total_count));
                }
            }
        };
        let deadline = Instant::now() + DEADLINE;
        std::thread::scope(|scope| {
            for _ in 0..3 {
                scope.spawn(|| {
                    let context = ReceiptReadContext::admin_service();
                    while !stop.load(Ordering::SeqCst) {
                        let read = service.load_receipt(replacement, &context);
                        if let Ok((Some(found), watermark)) = read {
                            let id = watermark.snapshot_id;
                            expose(format!("point read of {} from {id}", found.id));
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                });
            }
            // A failure below stops the readers before the scope joins them.
            let _stop = StopOnDrop(&stop);
            if let Some(held) = held {
                if !service.await_gate_for_test(DEADLINE) {
                    self.fail("the extension did not reach its armed gate");
                }
                held();
                probe();
                self.counts_match_group_by();
                service.release_gate_for_test();
            }
            while self.still_served() {
                probe();
                self.within(deadline, "the lineage to drop after a changed batch");
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        exposures.into_inner().unwrap()
    }

    /// Insert a lineage row whose provenance claim fails local validation,
    /// for a capability whose receipts carry no signed subject. It never
    /// refreshes attribution: the lineage drops instead.
    fn malformed_lineage(&mut self) -> bool {
        let unattributed = self.unattributed();
        let with = |archived: bool| -> Vec<String> {
            let flagged = unattributed
                .iter()
                .filter(|(_, (live, old))| if archived { *old } else { *live });
            flagged.map(|(capability, _)| capability.clone()).collect()
        };
        let (archived, live) = (with(true), with(false));
        let capability = if !archived.is_empty() && (live.is_empty() || self.rng.percent(75)) {
            self.rng.pick(&archived).clone()
        } else if !live.is_empty() {
            self.rng.pick(&live).clone()
        } else {
            return false;
        };
        let kinds = [
            Malformed::MissingToken,
            Malformed::MismatchedToken,
            Malformed::Anchor,
        ];
        let kind = *self.rng.pick(&kinds);
        let serial = self.next_serial();
        let subject = format!("malformed-subject-{serial}");
        let signed = token(&capability, serial);
        let epoch = self.lease();
        let (provenance, json) = match kind {
            Malformed::MissingToken => ("signed_token", None),
            Malformed::MismatchedToken => (
                "signed_token",
                Some(serde_json::to_string(&signed).unwrap()),
            ),
            Malformed::Anchor => ("synthetic_anchor", None),
        };
        self.insert_lineage(&capability, &subject, &signed, provenance, json);
        let query = ReceiptQuery {
            agent_subject: Some(subject.clone()),
            ..admin(MAX_QUERY_LIMIT)
        };
        let deadline = Instant::now() + DEADLINE;
        let mut last: Option<u64> = None;
        let mut cycles = 0;
        loop {
            if let Ok(page) = self.service().query_receipts(&query) {
                if page.total_count > 0 || !page.receipts.is_empty() {
                    self.fail(format!(
                        "a {kind:?} lineage row for {capability} refreshed attribution: {} receipts match {subject} in {:?}",
                        page.total_count,
                        page.snapshot.map(|w| w.snapshot_id)
                    ));
                }
            }
            let Some(observed) = self.served_observation() else {
                break;
            };
            if last.is_some_and(|last| last != observed) {
                cycles += 1;
            }
            last = Some(observed);
            if cycles >= 2 {
                self.fail(format!(
                    "a {kind:?} lineage row for {capability} was accepted by two extension cycles"
                ));
            }
            self.within(deadline, "the lineage to drop after a malformed row");
            std::thread::sleep(Duration::from_millis(2));
        }
        // Retire the row in place: its rowid stays taken, and its capability
        // is one no receipt uses.
        let retired = self
            .fixture
            .tamper()
            .execute(
                "UPDATE capability_lineage SET capability_id = ?2, provenance = 'legacy_projection',
                    signed_capability_json = NULL WHERE capability_id = ?1",
                rusqlite::params![capability, format!("retired-{serial}")],
            )
            .unwrap();
        assert_eq!(retired, 1);
        self.replace_dropped(epoch);
        true
    }

    /// The observation time of the served lineage while it is the ready one.
    fn served_observation(&self) -> Option<u64> {
        let status = self.service().status();
        match (&status.state, status.watermark.as_ref()) {
            (ReceiptQuerySnapshotState::Ready, Some(watermark))
                if lineage_of(watermark) == self.served =>
            {
                Some(watermark.observed_at_unix_ms)
            }
            _ => None,
        }
    }

    fn still_served(&self) -> bool {
        self.served_observation().is_some()
    }

    /// The served lineage failed. It never serves again, the lease taken
    /// under it stays refused, and a new authenticated lineage replaces it.
    fn replace_dropped(&mut self, epoch: u64) {
        self.dropped.insert(self.served.clone());
        let deadline = Instant::now() + DEADLINE;
        let rebuilt = loop {
            let status = self.service().status();
            if let (ReceiptQuerySnapshotState::Ready, Some(watermark)) =
                (&status.state, status.watermark.as_ref())
            {
                let lineage = lineage_of(watermark);
                if self.dropped.contains(&lineage) {
                    self.fail(format!("dropped lineage {lineage} is ready again"));
                }
                break lineage;
            }
            self.within(deadline, "a new lineage");
            std::thread::sleep(TICK);
        };
        let lease = self.service().recheck_lease_for_test(epoch);
        if !is_invalid(&lease) {
            self.fail(format!(
                "a lease under a dropped lineage was answered as {lease:?}"
            ));
        }
        self.served = rebuilt;
        self.settle();
        self.verify();
    }

    /// Wait until extension stops completing cycles and return the head the
    /// served version covers.
    fn await_pause(&self) -> u64 {
        let observed = || {
            let watermark = self.service().status().watermark;
            let watermark = watermark.unwrap_or_else(|| self.fail("no version is served"));
            (watermark.observed_at_unix_ms, watermark.through_entry_seq)
        };
        let deadline = Instant::now() + DEADLINE;
        let mut last = observed();
        loop {
            std::thread::sleep(TICK * 10);
            let now = observed();
            if now == last {
                return now.1;
            }
            last = now;
            self.within(deadline, "extension to pause");
        }
    }

    /// Wait for two extension cycles of the served lineage to complete after
    /// this call. The second observed the store after every change made
    /// before the call, so the version it leaves covers them all.
    fn settle(&self) {
        let deadline = Instant::now() + DEADLINE;
        let mut last: Option<u64> = None;
        let mut cycles = 0;
        while cycles < 2 {
            let Some(observed) = self.served_observation() else {
                let state = self.service().status().state;
                self.fail(format!(
                    "lineage {} stopped serving after a valid change: {state:?}",
                    self.served
                ));
            };
            if last.is_some_and(|last| last != observed) {
                cycles += 1;
            }
            last = Some(observed);
            self.within(deadline, "two extension cycles");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // Oracles.

    /// The maintained counts of the version served now equal `GROUP BY` over
    /// its own rows. One statement on the snapshot connection sees exactly one
    /// version; its tallies are read back from a temporary table only this
    /// check writes.
    fn counts_match_group_by(&self) {
        let service = self.service();
        let run = |sql: &str| service.execute_on_snapshot_for_test(sql, []);
        run("CREATE TEMP TABLE IF NOT EXISTS sequence_counts (source TEXT NOT NULL,
             scope INTEGER, dim INTEGER, value INTEGER, n INTEGER, min_seq INTEGER, max_seq INTEGER)");
        run("DELETE FROM temp.sequence_counts");
        let maintained = MAINTAINED_COUNTS_SQL;
        let grouped = grouped_counts_sql();
        let inserted = run(&format!(
            "INSERT INTO temp.sequence_counts
             SELECT 'maintained', * FROM ({maintained})
             UNION ALL SELECT 'grouped', * FROM ({grouped})
             UNION ALL SELECT 'differ', * FROM
                 (SELECT * FROM ({maintained}) EXCEPT SELECT * FROM ({grouped}))
             UNION ALL SELECT 'differ', * FROM
                 (SELECT * FROM ({grouped}) EXCEPT SELECT * FROM ({maintained}))"
        ));
        let take = |source: &str| {
            let sql = "DELETE FROM temp.sequence_counts WHERE source = ?1";
            service.execute_on_snapshot_for_test(sql, [source])
        };
        let (kept, recomputed, differ) = (take("maintained"), take("grouped"), take("differ"));
        if recomputed == 0 || inserted != kept + recomputed + differ {
            self.fail(format!(
                "the count comparison did not run on a served version: inserted {inserted}, maintained {kept}, grouped {recomputed}, differing {differ}"
            ));
        }
        if kept != recomputed || differ != 0 {
            self.fail(format!(
                "maintained counts differ from GROUP BY: {kept} maintained rows, {recomputed} grouped rows, {differ} differing"
            ));
        }
        self.sampled.set(self.sampled.get() + 1);
    }

    /// The settled version answers as the per-call authenticated path. The
    /// per-call listing of every tool receipt, read again after each append,
    /// is the source of truth: the version owns exactly its rows, each
    /// filter's whole set is selected from it by signed content, and the
    /// served total and a cursor page of five filters chosen afresh must
    /// match. A version whose listing was not read again may also read one of
    /// them through the per-call filter path.
    fn verify(&mut self) {
        self.every_generation_matched();
        self.counts_match_group_by();
        let anchored = self.listing.is_some();
        let listing = match self.listing.take() {
            Some(listing) => listing,
            None => match self.fixture.store.query_receipts(&admin(MAX_QUERY_LIMIT)) {
                Ok(listing) => listing.receipts,
                Err(error) => self.fail(format!("the per-call listing refused: {error}")),
            },
        };
        if listing.len() >= MAX_QUERY_LIMIT {
            self.fail("the per-call listing does not fit one page");
        }
        self.owned_rows_match(&listing);
        let mut queries = self.queries();
        while queries.len() > 5 {
            let index = self.rng.index(queries.len());
            queries.swap_remove(index);
        }
        let anchor = (anchored && self.rng.percent(40)).then(|| self.rng.index(queries.len()));
        for (index, query) in queries.iter().enumerate() {
            let selected = self.selected(query, &listing);
            if anchor == Some(index) {
                let direct = per_call(&self.fixture.store, query);
                if direct != slice(&selected, MAX_QUERY_LIMIT, None) {
                    self.fail(format!(
                        "{query:?}: the per-call filter path answers {direct:?}, the listing selects {selected:?}"
                    ));
                }
            }
            let limit = 1 + self.rng.index(4);
            let cursor = match self.rng.below(4) {
                0 => None,
                1 => Some(self.rng.below(200)),
                _ if selected.is_empty() => None,
                _ => Some(*self.rng.pick(&selected)),
            };
            let paged = ReceiptQuery {
                limit,
                cursor,
                ..query.clone()
            };
            let expected = slice(&selected, limit, cursor);
            let served = self.page(&paged);
            if served != expected {
                self.fail(format!(
                    "{paged:?} served {served:?}, expected {expected:?}"
                ));
            }
        }
        self.listing = Some(listing);
        self.point_parity();
    }

    /// The served version owns exactly the rows of the authenticated listing.
    /// The comparison runs on the snapshot connection in one statement.
    fn owned_rows_match(&self, listing: &[StoredToolReceipt]) {
        let service = self.service();
        let run = |sql: &str| service.execute_on_snapshot_for_test(sql, []);
        run("CREATE TEMP TABLE IF NOT EXISTS sequence_rows (source TEXT NOT NULL, seq INTEGER, receipt_id TEXT)");
        run("DELETE FROM temp.sequence_rows");
        let mut values = Vec::new();
        for row in listing {
            values.push(rusqlite::types::Value::Integer(
                i64::try_from(row.seq).unwrap(),
            ));
            values.push(rusqlite::types::Value::Text(row.receipt.id.clone()));
        }
        let rows = vec!["('expected', ?, ?)"; listing.len()].join(", ");
        let expected = service.execute_on_snapshot_for_test(
            &format!("INSERT INTO temp.sequence_rows VALUES {rows}"),
            rusqlite::params_from_iter(values),
        );
        let owned = "SELECT seq, receipt_id FROM snapshot_tool_receipt";
        let listed = "SELECT seq, receipt_id FROM temp.sequence_rows WHERE source = 'expected'";
        let inserted = run(&format!(
            "INSERT INTO temp.sequence_rows SELECT 'owned', * FROM ({owned})
             UNION ALL SELECT 'differ', * FROM ({owned} EXCEPT {listed})
             UNION ALL SELECT 'differ', * FROM ({listed} EXCEPT {owned})"
        ));
        let take = |source: &str| {
            let sql = "DELETE FROM temp.sequence_rows WHERE source = ?1";
            service.execute_on_snapshot_for_test(sql, [source])
        };
        let (owned, differ) = (take("owned"), take("differ"));
        if expected != listing.len() || inserted != owned + differ {
            self.fail(format!(
                "the row comparison did not run on a served version: listed {}, inserted {expected}, owned {owned}, differing {differ}",
                listing.len()
            ));
        }
        if owned != listing.len() || differ != 0 {
            self.fail(format!(
                "the served version owns {owned} rows, {differ} differing from the {} authenticated receipts",
                listing.len()
            ));
        }
    }

    /// Every state committed so far matched `GROUP BY` in its own hold, and
    /// every generation of the served lineage up to the one served now was
    /// compared there.
    fn every_generation_matched(&self) {
        let Some(watermark) = self.service().status().watermark else {
            self.fail("no version is served");
        };
        let served: u64 = watermark
            .snapshot_id
            .rsplit(':')
            .next()
            .and_then(|generation| generation.parse().ok())
            .unwrap_or_else(|| self.fail(format!("snapshot id {}", watermark.snapshot_id)));
        let record = self.generations.lock().unwrap();
        if let Some(mismatch) = &record.mismatch {
            self.fail(format!(
                "a committed state's counts differ from GROUP BY at {mismatch}"
            ));
        }
        let seen = record.seen.get(&lineage_of(&watermark));
        let missing: Vec<u64> = (1..=served)
            .filter(|generation| !seen.is_some_and(|seen| seen.contains(generation)))
            .collect();
        if !missing.is_empty() {
            self.fail(format!(
                "generations {missing:?} of {} were published without a count comparison",
                watermark.snapshot_id
            ));
        }
    }

    /// Seqs of the authenticated listing that `query` selects, before its
    /// cursor and limit apply.
    fn selected(&self, query: &ReceiptQuery, listing: &[StoredToolReceipt]) -> Vec<u64> {
        let scope = query.effective_read_scope().unwrap();
        let equal = |wanted: &Option<String>, value: &str| {
            wanted.as_deref().is_none_or(|wanted| wanted == value)
        };
        let selects = |receipt: &ChioReceipt| {
            let currency = receipt_cost_projection(receipt).unwrap().currency;
            let subject = extract_receipt_attribution(receipt)
                .subject_key
                .or_else(|| {
                    let row = self.lineage.get(&receipt.capability_id);
                    row.map(|row| row.subject.clone())
                });
            let tenant = receipt.tenant_id.as_deref();
            scope
                .tenant
                .as_deref()
                .is_none_or(|scope| Some(scope) == tenant)
                && equal(&query.capability_id, &receipt.capability_id)
                && equal(&query.tool_server, &receipt.tool_server)
                && equal(&query.tool_name, &receipt.tool_name)
                && equal(&query.outcome, receipt_decision_kind(receipt))
                && query.since.is_none_or(|since| receipt.timestamp >= since)
                && query.until.is_none_or(|until| receipt.timestamp <= until)
                && (query.cost_currency.is_none() || query.cost_currency == currency)
                && (query.agent_subject.is_none() || query.agent_subject == subject)
        };
        let rows = listing.iter().filter(|row| selects(&row.receipt));
        rows.map(|row| row.seq).collect()
    }

    fn queries(&mut self) -> Vec<ReceiptQuery> {
        let mut subjects: Vec<String> = SIGNED_SUBJECTS.map(String::from).to_vec();
        subjects.extend(self.lineage.values().map(|row| row.subject.clone()));
        let capabilities: Vec<String> = self
            .receipts
            .iter()
            .map(|stored| stored.spec.capability.clone())
            .collect();
        let mut timestamp = || {
            let index = self.rng.index(self.receipts.len());
            self.receipts[index].receipt.timestamp
        };
        let (a, b) = (timestamp(), timestamp());
        let since = a.min(b).saturating_sub(self.rng.below(1_800));
        let until = a.max(b) + self.rng.below(1_800);
        let outcome = Some(
            if self.rng.percent(50) {
                "allow"
            } else {
                "deny"
            }
            .to_string(),
        );
        let currency = Some(if self.rng.percent(50) { "USD" } else { "EUR" }.to_string());
        let mut text = |items: &[&str]| Some((*self.rng.pick(items)).to_string());
        let (server, tool, other_tool) = (text(&SERVERS), text(&TOOLS), text(&TOOLS));
        let (scope_a, scope_b, scope_c, scope_d) = (
            text(&TENANTS),
            text(&TENANTS),
            text(&TENANTS),
            text(&TENANTS),
        );
        let subject = Some(self.rng.pick(&subjects).clone());
        let capability = Some(self.rng.pick(&capabilities).clone());
        let other_capability = Some(self.rng.pick(&capabilities).clone());
        let all = admin(MAX_QUERY_LIMIT);
        vec![
            tenant(scope_a.as_deref().unwrap()),
            ReceiptQuery {
                outcome: outcome.clone(),
                ..tenant(scope_b.as_deref().unwrap())
            },
            ReceiptQuery {
                tool_name: other_tool,
                ..all.clone()
            },
            ReceiptQuery {
                tool_server: server,
                tool_name: tool,
                ..all.clone()
            },
            ReceiptQuery {
                since: Some(since),
                until: Some(until),
                ..all.clone()
            },
            ReceiptQuery {
                since: Some(since),
                ..tenant(scope_c.as_deref().unwrap())
            },
            ReceiptQuery {
                agent_subject: subject,
                ..all.clone()
            },
            ReceiptQuery {
                capability_id: capability,
                outcome,
                ..all.clone()
            },
            ReceiptQuery {
                cost_currency: currency,
                ..all.clone()
            },
            ReceiptQuery {
                tenant_filter: scope_d,
                capability_id: other_capability,
                ..all
            },
        ]
    }

    fn page(&self, query: &ReceiptQuery) -> Page {
        match self.service().query_receipts(query) {
            Ok(page) => {
                self.served_by_current(page.snapshot.as_ref(), query);
                let seqs = page.receipts.iter().map(|row| row.seq).collect();
                (seqs, page.total_count, page.next_cursor)
            }
            Err(error) => self.fail(format!("a settled read refused {query:?}: {error}")),
        }
    }

    fn served_by_current(
        &self,
        watermark: Option<&ReceiptSnapshotWatermark>,
        what: &dyn std::fmt::Debug,
    ) {
        let lineage = watermark.map(lineage_of).unwrap_or_default();
        if lineage != self.served || self.dropped.contains(&lineage) {
            let served = &self.served;
            self.fail(format!(
                "{what:?} was served by lineage {lineage}, not {served}"
            ));
        }
    }

    fn point_parity(&mut self) {
        let stored = &self.receipts[self.rng.index(self.receipts.len())];
        let id = stored.receipt.id.clone();
        let (context, expected) = match self.rng.below(4) {
            0 => (ReceiptReadContext::admin_service(), Some(id.clone())),
            n => {
                let scope = TENANTS[usize::try_from(n - 1).unwrap()];
                let visible = stored.receipt.tenant_id.as_deref() == Some(scope);
                let context = ReceiptReadContext::authenticated_tenant(scope);
                (context, visible.then(|| id.clone()))
            }
        };
        let absent = ("sequence-absent", ReceiptReadContext::admin_service(), None);
        for (id, context, expected) in [(id.as_str(), context, expected), absent] {
            match self.service().load_receipt(id, &context) {
                Ok((found, watermark)) => {
                    self.served_by_current(Some(&watermark), &id);
                    let found = found.map(|receipt| receipt.id);
                    if found != expected {
                        self.fail(format!(
                            "point read of {id} as {context:?} found {found:?}, expected {expected:?}"
                        ));
                    }
                }
                Err(error) => self.fail(format!("a settled point read of {id} refused: {error}")),
            }
        }
    }
}

fn op_name(op: Op) -> &'static str {
    match op {
        Op::Append => "append",
        Op::AppendChild => "append child",
        Op::Rotate => "rotate",
        Op::SignedLineage => "signed lineage",
        Op::UnsignedLineage => "unsigned lineage",
        Op::UpgradeLineage => "upgrade lineage",
        Op::Latch => "latch",
        Op::ProjectionTamper => "projection tamper",
        Op::CustodyFailure => "custody failure",
        Op::WriterPoison => "writer poison",
        Op::CheckpointedSubstitution => "checkpointed substitution",
        Op::VerifiedThenChanged => "verified then changed",
        Op::InterruptedCycle => "interrupted cycle",
        Op::MalformedLineage => "malformed lineage",
    }
}

fn campaign(seed: u64, epochs: usize, weights: &[(Op, u64)]) {
    let position = Position::new((0, 0, "setup"));
    let mut seeds = Rng(seed);
    let mut tally = Tally::default();
    let started = Instant::now();
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        for epoch in 0..epochs {
            position.set((epoch, 0, "setup"));
            let campaign = Campaign::start(seed, weights, seeds.next(), &position);
            campaign.run(EPOCH_STEPS, &mut tally);
        }
    }));
    if let Err(panic) = outcome {
        let (epoch, step, op) = position.get();
        eprintln!("receipt query snapshot sequence failed: seed {seed:#x}, epoch {epoch}, step {step}, operation {op}");
        std::panic::resume_unwind(panic);
    }
    eprintln!(
        "seed {seed:#x}: {epochs} epochs of {EPOCH_STEPS} operations in {:?}: {tally:?}",
        started.elapsed()
    );
}

#[test]
fn a_seeded_sequence_keeps_counts_and_pages_equal_to_the_authenticated_source() {
    campaign(SEED, EPOCHS, &WEIGHTS);
}

#[test]
#[ignore = "long campaign; run explicitly"]
fn a_long_seeded_sequence_keeps_counts_and_pages_equal_to_the_authenticated_source() {
    campaign(LONG_SEED, LONG_EPOCHS, &WEIGHTS);
}
