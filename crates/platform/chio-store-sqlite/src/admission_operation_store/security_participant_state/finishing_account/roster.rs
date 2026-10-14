//! The complete priced roster of one original native finishing account.
//! Every purpose is priced from its actual producer's authenticated shape:
//! the ToolOutcome family, the owed Output join and its seal, the registered
//! receipt sink, the Process journal and the account's own transitions.
use super::row_plan::{self, NativeRowPlan};
use super::*;
use crate::admission_operation_store::recovery::resources::{
    price_native_tool_outcome_phases, price_protected_command_with_row_limits,
    ProtectedCommandLiabilityPlan,
};
use crate::admission_operation_store::recovery::storage::NativeFinishingPageRecipeV1;
use crate::admission_operation_store::tool_outcome_liability::ToolOutcomeTransactionPurposeData;
use crate::security_state::NativeRowChange;
use chio_sqlite_file_identity::{
    SqliteFramePriceProfileData, SqliteTransactionWriteShapeData, SqliteTreeWriteShapeData,
};

/// The Output event record CHECK bound.
const MAX_OUTPUT_RECORD_BYTES: u64 = 16_777_216;
/// Declassification outbox bodies are bounded by their CHECK.
const MAX_DECLASSIFICATION_ROW_BYTES: u64 = 1_048_576 + 8_192;
/// IDs are at most 256 bytes, labels at most 1 MiB and hashes 32 bytes.
const MAX_TEXT_ID_BYTES: u64 = 256;
const MAX_AUTHORITY_BYTES: u64 =
    chio_kernel::admission_operation::MAX_ADMISSION_IDENTIFIER_BYTES as u64;
const MAX_LABEL_JSON_BYTES: u64 = 1_048_576;
/// One record header plus the table's real columns bounds a flow row.
const MAX_RECORD_HEADER_BYTES: u64 = 64;
/// The most pre-effect generation allocations this original can still make
/// before its external effect: the Input join and the Nonce preflight join.
const PRE_EFFECT_JOIN_SLOTS: u64 = 2;

pub(super) struct PricedRoster {
    pub(super) liabilities: Vec<NativeFinishingLiabilityV1>,
    pub(super) transitions: NativeFinishingTransitionAllowanceV1,
    pub(super) recipe_digest: String,
}

/// Process side-database purposes quoted inside the Process writer.
pub(super) struct ProcessQuote {
    pub(super) liabilities: Vec<NativeFinishingLiabilityV1>,
    pub(super) future_transactions_digest: String,
}

/// The registered receipt sink file and its priced append transaction.
pub(super) struct ReceiptSinkQuote {
    pub(super) file: NativeFinishingFileV1,
    pub(super) registration_digest: String,
    pub(super) liability: NativeFinishingLiabilityV1,
}

pub(super) fn price_roster(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    origin: &NativeSourceTransactionOrigin<'_>,
    plan: &VerifiedNativeInitialFinishingPlan<'_, '_>,
    account_key: &str,
    identity: &NativeFinishingIdentityV1,
    process: Option<ProcessQuote>,
    receipt: ReceiptSinkQuote,
) -> Result<PricedRoster, AdmissionOperationStoreError> {
    let flow_scope = identity.flow_scope_digest.as_str();
    plan.verify_before(tx, owner, origin)?;
    let spill: i64 = tx
        .query_row("PRAGMA main.cache_spill", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if spill != 0 {
        return Err(invalid("native finishing requires its spill-free writer"));
    }
    let row_plan = NativeRowPlan::prepare(tx, owner, plan)?;
    let transactions = crate::admission_operation_store::tool_outcome_liability::describe_native_tool_outcome_transactions(plan)?;
    let mut liabilities = Vec::new();
    let prices = price_native_tool_outcome_phases(tx, (owner, origin), plan, row_plan.ceilings())?;
    for (price, transaction) in prices.into_iter().zip(&transactions) {
        let purpose = match price.purpose() {
            ToolOutcomeTransactionPurposeData::RawCustody => NativeFinishingPurposeV1::RawCustody,
            ToolOutcomeTransactionPurposeData::EvaluationBegin => {
                NativeFinishingPurposeV1::EvaluationBegin
            }
            ToolOutcomeTransactionPurposeData::Finalization { pure_prefix } => {
                NativeFinishingPurposeV1::Finalization { pure_prefix }
            }
            ToolOutcomeTransactionPurposeData::SecurityRelease => {
                NativeFinishingPurposeV1::SecurityRelease
            }
            ToolOutcomeTransactionPurposeData::TerminalProjection { .. } => {
                NativeFinishingPurposeV1::TerminalProjection
            }
            ToolOutcomeTransactionPurposeData::PaymentAuthorization => {
                NativeFinishingPurposeV1::PaymentAuthorization
            }
            ToolOutcomeTransactionPurposeData::PaymentCompensation => {
                NativeFinishingPurposeV1::PaymentCompensation
            }
            ToolOutcomeTransactionPurposeData::PaymentSettlement => {
                NativeFinishingPurposeV1::PaymentSettlement
            }
            ToolOutcomeTransactionPurposeData::PaymentCompletion => {
                NativeFinishingPurposeV1::PaymentCompletion
            }
        };
        let mut liability = outstanding(purpose, price.profile(), price.physical().clone());
        liability.row_loans = row_plan.tool_outcome_loans(transaction)?;
        liability.page_recipe = Some(NativeFinishingPageRecipeV1 {
            page_bucket: 1 << 32,
            page_growth: price.page_growth(),
        });
        liabilities.push(liability);
    }
    let seal = price_owed_seal(tx, plan, &row_plan)?;
    liabilities.push(seal);
    let output = price_output_join(tx, owner, plan, &row_plan)?;
    liabilities.push(output);
    liabilities.push(receipt.liability);
    let process_digest = match process {
        Some(process) => {
            liabilities.extend(process.liabilities);
            Some(process.future_transactions_digest)
        }
        None => None,
    };
    let mut transitions = price_transitions(
        tx,
        owner,
        account_key,
        flow_scope,
        identity,
        &liabilities,
        &row_plan,
    )?;
    reserve_complete_growth(tx, owner, &mut liabilities, &mut transitions)?;
    let profiles: Vec<_> = liabilities
        .iter()
        .map(|liability| &liability.profile_digest)
        .collect();
    let recipe_digest = sha256_hex(
        &canonical_json_bytes(&(
            "chio.native-finishing-roster-recipe.v1",
            &profiles,
            &transitions.profile_digest,
            &process_digest,
            &receipt.registration_digest,
        ))
        .map_err(invalid)?,
    );
    Ok(PricedRoster {
        liabilities,
        transitions,
        recipe_digest,
    })
}

fn outstanding(
    purpose: NativeFinishingPurposeV1,
    profile: &str,
    liability: PhysicalLiabilityData,
) -> NativeFinishingLiabilityV1 {
    NativeFinishingLiabilityV1 {
        purpose,
        profile_digest: profile.to_owned(),
        liability,
        disposition: NativeFinishingDispositionV1::Outstanding,
        page_recipe: None,
        width_recipe: None,
        wal_frames: None,
        row_loans: Vec::new(),
    }
}

/// The owed Output append may seal its live segment first. The seal is a
/// pristine protected command of the authority's fixed seal key width.
fn price_owed_seal(
    tx: &Transaction<'_>,
    plan: &VerifiedNativeInitialFinishingPlan<'_, '_>,
    rows: &NativeRowPlan,
) -> Result<NativeFinishingLiabilityV1, AdmissionOperationStoreError> {
    let (key, scope) = plan.next_seal_record(tx)?;
    let allowance = plan.native_seal_price();
    let mut command = ProtectedCommandLiabilityPlan::new();
    command.add_new_command(tx, &key, &scope, allowance.maximum_payload_bytes())?;
    let price = price_protected_command_with_row_limits(tx, &command, rows.ceilings())?;
    let profile = sha256_hex(
        &canonical_json_bytes(&(
            "chio.native-finishing-owed-seal-price.v1",
            allowance,
            &price,
        ))
        .map_err(invalid)?,
    );
    let mut liability = outstanding(NativeFinishingPurposeV1::NativeJournalSeal, &profile, price);
    liability.row_loans = rows.command_loans(1, true)?;
    Ok(liability)
}

/// One owed Output join: its immutable event row, every native flow row the
/// join can rewrite at its CHECK bound, the declassification rows a pending
/// consumption may write, and one global commit. The output label is chosen
/// after the effect, so every shape is priced at its authenticated maximum.
fn price_output_join(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    plan: &VerifiedNativeInitialFinishingPlan<'_, '_>,
    rows: &NativeRowPlan,
) -> Result<NativeFinishingLiabilityV1, AdmissionOperationStoreError> {
    let flow_catalog = super::super::schema::native_flow_write_catalog(tx)?;
    super::super::output::verify_catalog(tx)?;
    let geometry = crate::admission_operation_store::raw_custody_liability::raw_write_profile(tx)?;
    let frame_profile =
        SqliteFramePriceProfileData::checked(geometry.page_size(), 0).map_err(invalid)?;
    let tree = |before: Option<u64>, after: u64| {
        SqliteTreeWriteShapeData::record(before, after, 1).map_err(invalid)
    };
    let mut trees = vec![
        // The event row and its primary, operation and transition indexes.
        tree(
            None,
            MAX_OUTPUT_RECORD_BYTES
                + MAX_AUTHORITY_BYTES
                + 2 * MAX_TEXT_ID_BYTES
                + 2 * 64
                + 2 * 8
                + MAX_RECORD_HEADER_BYTES,
        )?,
        tree(None, MAX_AUTHORITY_BYTES + 8 + 8 + MAX_RECORD_HEADER_BYTES)?,
        tree(None, 64 + 8 + MAX_RECORD_HEADER_BYTES)?,
        tree(
            None,
            MAX_AUTHORITY_BYTES + 2 * MAX_TEXT_ID_BYTES + 8 + MAX_RECORD_HEADER_BYTES,
        )?,
    ];
    // The eight closed WITHOUT ROWID flow tables, each priced at its real
    // column bound. IsolationEpochs alone keeps a secondary unique tree
    // whose key is a subset of the full row.
    let output_ceiling = rows.ceiling("security_participant_output_events")?;
    trees = trees
        .into_iter()
        .map(|tree| tree.within_retained_rows(output_ceiling).map_err(invalid))
        .collect::<Result<_, _>>()?;
    trees.extend(flow_tree_write_shapes(Some(rows))?);
    // A pending declassification consumption updates its use, tombstone and
    // receipt outbox rows inside the same join. Only a declassified egress can
    // leave one, and that egress presents the live request's grant; an
    // original priced without it refuses that egress before any effect.
    let declassifies = plan.request().declassification_grant.is_some();
    let declassification_tables: &[&str] = if declassifies {
        &row_plan::OUTPUT_TABLES[9..]
    } else {
        &[]
    };
    for table in declassification_tables {
        trees.push(
            tree(
                Some(MAX_DECLASSIFICATION_ROW_BYTES),
                MAX_DECLASSIFICATION_ROW_BYTES,
            )?
            .within_retained_rows(rows.ceiling(table)?)
            .map_err(invalid)?,
        );
    }
    // The Output's INVALIDATE_PRINCIPAL, INVALIDATE_LINEAGE and INVALIDATE_SESSION
    // updates rewrite `generation` of every related context under an unchanged
    // primary key. The table is STRICT WITHOUT ROWID with no secondary index. A
    // generation is a variable-width SQLite integer, so a rewrite either keeps
    // its encoded size (an in-place overwrite) or replaces its cell with at
    // most one balance cascade. Every possible width change is priced by the
    // measured split: the capture caps one join at `MAX_JOIN_CHANGES` rows and
    // `MAX_JOIN_IMAGE_BYTES` of images, every after image is at least as long
    // as its record, and the width recipe below funds the complete split.
    // No retained generation is rewritten and no transition is refused.
    let context_ceiling = rows.ceiling(row_plan::CONTEXTS)?;
    // Three overlapping invalidation statements can each visit a context.
    // STORE_CONTEXT is already in the ordinary flow-row descriptor below.
    let fanout_rows = u64::try_from(NativeRowChange::MAX_JOIN_CHANGES)
        .map_err(invalid)?
        .min(
            context_ceiling
                .checked_mul(3)
                .ok_or_else(|| invalid("native context fanout exhausted"))?,
        );
    let fanout_bytes = fanout_rows
        .checked_mul(MAX_RECORD_HEADER_BYTES + MAX_AUTHORITY_BYTES + 5 * MAX_TEXT_ID_BYTES + 8)
        .ok_or_else(|| invalid("native context image bound exhausted"))?;
    // The width recipe measured in this same transaction, scoped to this
    // account's actual security authority and tenant: every generation this
    // tenant's flow state stores is allocated by `next_flow_generation` from
    // the tenant's own counter, so that counter bounds the class of any
    // generation the join allocates. A stored generation below the class
    // floor is the exact set of context rows whose cell can grow in the
    // join's rewrites: rows inserted later carry a generation at or above
    // the next one, whose class never decreases while the native owner's
    // allocator keeps the counter inside the retained class. The native
    // owner enforces that retention on the allocator.
    let authority = plan.initialized().security_authority_id().as_str();
    let tenant = plan.key().tenant_id.as_str();
    let sequence_generation: Option<i64> = tx
        .query_row(
            "SELECT last_generation FROM main.security_participant_state_flow_sequences
             WHERE security_authority_id = ?1 AND tenant_id = ?2",
            params![authority, tenant],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored_max: Option<i64> = tx
        .query_row(
            "SELECT MAX(generation) FROM (
                SELECT generation FROM main.security_participant_state_flow_contexts
                 WHERE security_authority_id = ?1 AND tenant_id = ?2
                UNION ALL
                SELECT generation FROM main.security_participant_state_principal_flow_state
                 WHERE security_authority_id = ?1 AND tenant_id = ?2
                UNION ALL
                SELECT generation FROM main.security_participant_state_lineage_flow_state
                 WHERE security_authority_id = ?1 AND tenant_id = ?2
                UNION ALL
                SELECT generation FROM main.security_participant_state_session_flow_state
                 WHERE security_authority_id = ?1 AND tenant_id = ?2
            )",
            params![authority, tenant],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let counter = sequence_generation
        .max(stored_max)
        .map(u64::try_from)
        .transpose()
        .map_err(invalid)?
        .unwrap_or(0);
    // Select a retained class with room for this original's own pre-effect
    // joins (at most Input and Nonce), its own Output, and every Output slot
    // the bank already owes this scope. An existing outstanding loan keeps
    // its class; a class that cannot hold all of them refuses before any
    // effect. A first loan takes the smallest serial-type class that fits,
    // never overflowing the SafeInteger generation bound.
    let debt = crate::admission_operation_store::recovery::storage::native_finishing_width_debt(
        tx, authority, tenant,
    )?;
    let (width_class, class_floor) =
        solve_output_width_class(counter, debt.map(|debt| (debt.width_class, debt.loans)))?;
    let n_grow = u64::try_from(
        tx.query_row(
            "SELECT COUNT(*) FROM main.security_participant_state_flow_contexts
             WHERE security_authority_id = ?1 AND tenant_id = ?2 AND generation < ?3",
            params![
                authority,
                tenant,
                i64::try_from(class_floor).map_err(invalid)?
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?,
    )
    .map_err(invalid)?;
    let growing_rows = n_grow.min(fanout_rows);
    trees.push(
        SqliteTreeWriteShapeData::same_key_rewrites_class_split(
            fanout_rows,
            fanout_bytes,
            growing_rows,
        )
        .and_then(|tree| tree.within_retained_rows(context_ceiling))
        .map_err(invalid)?,
    );
    let global = super::super::output::finishing_global_row_bounds(
        owner,
        plan.initialized().security_authority_id().as_str(),
    )?;
    trees.push(
        tree(None, global.0)?
            .within_retained_rows(rows.ceiling(row_plan::GLOBAL)?)
            .map_err(invalid)?,
    );
    trees.push(
        tree(None, global.1)?
            .within_retained_rows(rows.ceiling(row_plan::GLOBAL)?)
            .map_err(invalid)?,
    );
    trees.push(SqliteTreeWriteShapeData::singleton_root(8 + 8 + 64 + 9 * 4, 1).map_err(invalid)?);
    let shape = SqliteTransactionWriteShapeData::checked(trees).map_err(invalid)?;
    let recipe = NativeFinishingPageRecipeV1 {
        page_bucket: 1 << 32,
        page_growth: shape.maximum_page_growth(&frame_profile).map_err(invalid)?,
    };
    let priced = shape.price_without_spill(&frame_profile).map_err(invalid)?;
    let liability =
        PhysicalLiabilityData::native_transaction(priced.wal_bytes(), priced.disk_bytes(), 0, 1)?;
    let profile = sha256_hex(
        &canonical_json_bytes(&(
            "chio.native-finishing-output-join-price.v2",
            geometry.fingerprint(),
            flow_catalog.fingerprint(),
            chio_sqlite_file_identity::write_price_algorithm_descriptor(),
            SqliteTransactionWriteShapeData::page_bounded_descriptor(),
            SqliteTransactionWriteShapeData::no_spill_descriptor(),
            SqliteTransactionWriteShapeData::split_same_key_rewrites_descriptor(),
            (fanout_rows, fanout_bytes),
            (counter, width_class, class_floor, n_grow, growing_rows),
            (recipe.page_bucket, recipe.page_growth),
            (
                MAX_OUTPUT_RECORD_BYTES,
                MAX_DECLASSIFICATION_ROW_BYTES,
                declassifies,
            ),
            global.0,
            global.1,
            &liability,
        ))
        .map_err(invalid)?,
    );
    let mut purpose = outstanding(NativeFinishingPurposeV1::OutputJoin, &profile, liability);
    purpose.page_recipe = Some(recipe);
    purpose.row_loans = rows.loans(
        row_plan::OUTPUT_TABLES[..9]
            .iter()
            .chain(declassification_tables)
            .map(|&table| (table, 1))
            .chain([(row_plan::GLOBAL, 1), (row_plan::GLOBAL_META, 0)]),
    )?;
    // The retained width recipe: exactly one reserved Output generation slot,
    // bound to this account's actual security authority and tenant, measured
    // in this same transaction and reused unchanged at spend time.
    purpose.width_recipe = Some(
        crate::admission_operation_store::recovery::storage::NativeFinishingWidthRecipeV1 {
            security_authority: authority.to_owned(),
            tenant_id: tenant.to_owned(),
            width_class,
            n_grow,
            allocation_allowance: 1,
        },
    );
    Ok(purpose)
}

/// Whether this account's Output join priced a declassification consumption:
/// its loan then carries the declassification tables. A declassified egress
/// of an account without it refuses before the effect.
pub(super) fn output_join_prices_declassification(account: &NativeFinishingAccountV1) -> bool {
    account
        .liability(NativeFinishingPurposeV1::OutputJoin)
        .is_some_and(|liability| {
            liability
                .row_loans
                .iter()
                .any(|loan| loan.table == row_plan::OUTPUT_TABLES[9])
        })
}

/// The retained width class and its floor for one Output loan: with existing
/// outstanding loans the bank's single retained class is kept and must hold
/// this original's own pre-effect joins (at most Input and Nonce), its own
/// Output slot and every already reserved slot; a first loan selects the
/// smallest SQLite record serial-type class that holds them all. `None` debt
/// never overflows the SafeInteger generation bound.
fn solve_output_width_class(
    counter: u64,
    debt: Option<(u8, u64)>,
) -> Result<(u8, u64), AdmissionOperationStoreError> {
    use crate::admission_operation_store::recovery::storage;
    let reserved = debt.map_or(0, |(_, loans)| loans);
    let room = counter
        .checked_add(PRE_EFFECT_JOIN_SLOTS)
        .and_then(|joins| joins.checked_add(1))
        .and_then(|own| own.checked_add(reserved))
        .filter(|room| *room <= storage::width_class_ceiling(8).unwrap_or(0))
        .ok_or_else(|| invalid("native output generation counter is exhausted"))?;
    match debt {
        Some((width_class, _)) => {
            if storage::width_class_ceiling(width_class).is_some_and(|ceiling| ceiling >= room) {
                Ok((
                    width_class,
                    storage::generation_width_class_floor(width_class)?,
                ))
            } else {
                Err(invalid(
                    "native output retained width class lacks room for its owed Output slots",
                ))
            }
        }
        None => {
            let width_class = [0_u8, 1, 2, 3, 4, 6, 8]
                .into_iter()
                .find(|class| {
                    storage::width_class_ceiling(*class).is_some_and(|ceiling| ceiling >= room)
                })
                .ok_or_else(|| invalid("native output generation counter is exhausted"))?;
            Ok((
                width_class,
                storage::generation_width_class_floor(width_class)?,
            ))
        }
    }
}

/// The real write shapes of the eight closed WITHOUT ROWID flow tables:
/// contexts, sequences, IsolationEpochs with its secondary unique tree,
/// lineage, principal and session flow state, memberships and transitions.
/// Each is one existing-row write priced at its real column bound: one
/// record header, every text ID at most 256 bytes, one 1 MiB label where
/// the table keeps one, and each hash 32 bytes.
fn flow_tree_write_shapes(
    rows: Option<&NativeRowPlan>,
) -> Result<Vec<SqliteTreeWriteShapeData>, AdmissionOperationStoreError> {
    let header = MAX_RECORD_HEADER_BYTES + MAX_AUTHORITY_BYTES;
    let id = MAX_TEXT_ID_BYTES;
    let label = MAX_LABEL_JSON_BYTES;
    let isolation_epoch_row = header + 8 * id + 32 + 8;
    [
        // security_flow_contexts
        header + 5 * id + 8,
        // security_flow_sequences
        header + id + 8,
        // security_isolation_epochs and its secondary unique tree
        isolation_epoch_row,
        isolation_epoch_row,
        // security_lineage_flow_state
        header + 2 * id + label + 32 + 8,
        // security_principal_flow_state
        header + 3 * id + label + 32 + 8,
        // security_session_flow_state
        header + 4 * id + label + 32 + 8,
        // security_session_memberships
        header + 4 * id,
        // security_transitions
        header + 3 * id + 32,
    ]
    .into_iter()
    .zip([
        row_plan::CONTEXTS,
        row_plan::OUTPUT_TABLES[2],
        row_plan::OUTPUT_TABLES[3],
        row_plan::OUTPUT_TABLES[3],
        row_plan::OUTPUT_TABLES[4],
        row_plan::OUTPUT_TABLES[5],
        row_plan::OUTPUT_TABLES[6],
        row_plan::OUTPUT_TABLES[7],
        row_plan::OUTPUT_TABLES[8],
    ])
    .map(|(after, table)| {
        let tree = if table == row_plan::OUTPUT_TABLES[3] {
            SqliteTreeWriteShapeData::record(Some(after), after, 1)
        } else {
            // These owners never change the primary key. A new row is also
            // covered by one balance and the conservative old-plus-new images.
            SqliteTreeWriteShapeData::same_key_rewrites(1, after)
        }
        .map_err(invalid)?;
        match rows {
            Some(rows) => tree
                .within_retained_rows(rows.ceiling(table)?)
                .map_err(invalid),
            None => Ok(tree),
        }
    })
    .collect()
}

/// Reserve every native writer's growth together. New prices depend on their
/// retained table cardinalities, not a small whole-file ceiling. The power of
/// two above SQLite's compiled maximum admits unrelated retained history while
/// the existing physical debt and actual SQLite page cap still limit writes.
/// Any older outstanding page-bounded quote keeps its original smaller ceiling.
fn reserve_complete_growth(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    liabilities: &mut [NativeFinishingLiabilityV1],
    transitions: &mut NativeFinishingTransitionAllowanceV1,
) -> Result<(), AdmissionOperationStoreError> {
    let page_size: i64 = tx
        .query_row("PRAGMA main.page_size", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let pages: i64 = tx
        .query_row("PRAGMA main.page_count", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let page_size = u64::try_from(page_size).map_err(invalid)?;
    let pages = u64::try_from(pages).map_err(invalid)?;
    let frame = page_size
        .checked_add(24)
        .ok_or_else(|| invalid("native frame size exhausted"))?;
    let transition_growth = (transitions.per_transition.wal_bytes() / frame)
        .checked_add(1)
        .ok_or_else(|| invalid("native transition growth exhausted"))?;
    let mut growth = transition_growth
        .checked_mul(transitions.remaining)
        .ok_or_else(|| invalid("native transition growth exhausted"))?;
    for liability in liabilities
        .iter_mut()
        .filter(|liability| liability.purpose.file_role() == NativeFinishingFileRoleV1::Native)
    {
        let own = liability.page_recipe.map_or_else(
            || {
                (liability.liability.wal_bytes() / frame)
                    .checked_add(1)
                    .ok_or_else(|| invalid("native writer growth exhausted"))
            },
            |recipe| Ok(recipe.page_growth),
        )?;
        growth = growth
            .checked_add(own)
            .ok_or_else(|| invalid("native roster growth exhausted"))?;
        liability.page_recipe = Some(NativeFinishingPageRecipeV1 {
            page_bucket: 1 << 32,
            page_growth: own,
        });
    }
    let debt = crate::admission_operation_store::native_authority_file_page_debt(
        tx,
        &owner.fence.store_uuid,
    )?;
    solve_output_page_recipe(pages, debt.owed_pages, debt.page_ceiling, growth)?;
    if pages
        .checked_add(debt.owed_pages)
        .and_then(|pages| pages.checked_add(growth))
        .is_none_or(|pages| pages > 4_294_967_294)
    {
        return Err(invalid(
            "native roster exceeds SQLite's actual page capacity",
        ));
    }
    let bucket = debt.page_ceiling.unwrap_or(1 << 32);
    for liability in liabilities
        .iter_mut()
        .filter(|liability| liability.purpose.file_role() == NativeFinishingFileRoleV1::Native)
    {
        if let Some(recipe) = &mut liability.page_recipe {
            recipe.page_bucket = bucket;
        }
        liability.profile_digest = sha256_hex(
            &canonical_json_bytes(&(
                "chio.native-finishing-cardinality-price.v1",
                &liability.profile_digest,
                &liability.page_recipe,
                &liability.row_loans,
                &liability.liability,
            ))
            .map_err(invalid)?,
        );
    }
    transitions.page_recipe = Some(NativeFinishingPageRecipeV1 {
        page_bucket: bucket,
        page_growth: transition_growth,
    });
    transitions.profile_digest = sha256_hex(
        &canonical_json_bytes(&(
            "chio.native-finishing-cardinality-transition.v1",
            &transitions.profile_digest,
            &transitions.page_recipe,
            &transitions.row_loans,
        ))
        .map_err(invalid)?,
    );
    Ok(())
}

/// The smallest power-of-two ceiling holding the file's pages, every other
/// owed growth and this growth, within every retained ceiling.
fn solve_output_page_recipe(
    page_count: u64,
    owed: u64,
    page_ceiling: Option<u64>,
    growth: u64,
) -> Result<NativeFinishingPageRecipeV1, AdmissionOperationStoreError> {
    if growth == 0 {
        return Err(invalid("native output page growth is empty"));
    }
    let needed = page_count
        .checked_add(owed)
        .and_then(|pages| pages.checked_add(growth))
        .ok_or_else(|| invalid("native output page recipe overflows"))?;
    if page_ceiling.is_some_and(|ceiling| needed > ceiling) {
        return Err(invalid(
            "native output page growth exceeds the authority file's owed page ceiling",
        ));
    }
    let bucket = needed
        .checked_next_power_of_two()
        .filter(|bucket| *bucket <= 1 << 40)
        .ok_or_else(|| invalid("native output page recipe is unbounded"))?;
    Ok(NativeFinishingPageRecipeV1 {
        page_bucket: bucket,
        page_growth: growth,
    })
}

/// Each later account version rewrites the account and the bank head. The
/// allowance covers Confirmed, every native purpose and Settled. The account
/// rewrite is priced at this original's own account bound, which the account
/// writer enforces on every version, not at the legal record maximum.
fn price_transitions(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    account_key: &str,
    flow_scope: &str,
    identity: &NativeFinishingIdentityV1,
    liabilities: &[NativeFinishingLiabilityV1],
    rows: &NativeRowPlan,
) -> Result<NativeFinishingTransitionAllowanceV1, AdmissionOperationStoreError> {
    let store = &owner.fence.store_uuid;
    let row_loans = rows.command_loans(2, false)?;
    let account_bytes = native_finishing_account_bound(identity, liabilities, &row_loans)?;
    let mut command = ProtectedCommandLiabilityPlan::new();
    command.add_owned_rewrite(tx, account_key, flow_scope, account_bytes)?;
    command.add_owned_rewrite(
        tx,
        &native_finishing_bank_key(store),
        &native_finishing_bank_scope(store)?,
        NATIVE_FINISHING_BANK_MAX_BYTES,
    )?;
    let per_transition = price_protected_command_with_row_limits(tx, &command, rows.ceilings())?;
    let native_purposes = liabilities
        .iter()
        .filter(|liability| liability.purpose.file_role() == NativeFinishingFileRoleV1::Native)
        .count();
    let remaining = u64::try_from(native_purposes)
        .ok()
        .and_then(|count| count.checked_add(2))
        .ok_or_else(|| invalid("native finishing transition count exhausted"))?;
    let profile_digest = sha256_hex(
        &canonical_json_bytes(&(
            "chio.native-finishing-transition-price.v1",
            account_bytes,
            NATIVE_FINISHING_BANK_MAX_BYTES,
            &per_transition,
            remaining,
        ))
        .map_err(invalid)?,
    );
    Ok(NativeFinishingTransitionAllowanceV1 {
        profile_digest,
        per_transition,
        remaining,
        page_recipe: None,
        row_loans,
    })
}

/// Price the actual Process purposes on the Process file. The quote comes
/// from the concrete Process writer against its exact prepared source cut.
pub(super) fn price_process(
    source: &chio_process::native_return_custody::ProcessNativeFinishingSource,
) -> Result<ProcessQuote, AdmissionOperationStoreError> {
    use chio_process::native_return_custody::ProcessReturnTransactionData;
    let prices = source
        .future_prices()
        .map_err(|error| invalid(format!("native Process quote refused: {error}")))?;
    let mut liabilities = Vec::new();
    let mut facts = Vec::new();
    for price in &prices {
        let purpose = match price.purpose() {
            ProcessReturnTransactionData::Enrollment => NativeFinishingPurposeV1::ProcessEnrollment,
            ProcessReturnTransactionData::OriginalNonceCustody => {
                NativeFinishingPurposeV1::ProcessNonceCustody
            }
            ProcessReturnTransactionData::UnavailableNotice => {
                NativeFinishingPurposeV1::ProcessUnavailableNotice
            }
            ProcessReturnTransactionData::FinalNativeCustody => {
                NativeFinishingPurposeV1::ProcessFinalCustody
            }
            ProcessReturnTransactionData::Reconciliation => {
                NativeFinishingPurposeV1::ProcessReconciliation
            }
        };
        let fact = (
            format!("{:?}", price.purpose()),
            price.wal_bytes(),
            price.disk_bytes(),
            price.wal_frames(),
        );
        let profile = sha256_hex(
            &canonical_json_bytes(&("chio.native-finishing-process-price.v1", &fact))
                .map_err(invalid)?,
        );
        facts.push(fact);
        let mut liability = outstanding(
            purpose,
            &profile,
            PhysicalLiabilityData::registered_file(price.wal_bytes(), price.disk_bytes())?,
        );
        liability.wal_frames = Some(price.wal_frames());
        liabilities.push(liability);
    }
    let future_transactions_digest = sha256_hex(
        &canonical_json_bytes(&(
            "chio.native-finishing-process-future-transactions.v1",
            &facts,
        ))
        .map_err(invalid)?,
    );
    Ok(ProcessQuote {
        liabilities,
        future_transactions_digest,
    })
}

/// Price one receipt append on the registered sink file. The sink authenticates
/// its exact canonical producer catalog and quotes the append at the original
/// receipt envelope, the original capability's lineage keys and a page bucket
/// above every already owed loan. The account retains that recipe and the
/// funded append re-quotes it inside its own writer transaction.
pub(super) fn price_receipt_sink(
    receipts: &crate::SqliteReceiptStore,
    receipt_bytes: u64,
    capability_id: &str,
    owed_pages: u64,
) -> Result<ReceiptSinkQuote, AdmissionOperationStoreError> {
    let quote = receipts
        .quote_native_receipt_append(receipt_bytes, capability_id, owed_pages)
        .map_err(|error| invalid(format!("native receipt sink quote refused: {error}")))?;
    let registration_digest = receipt_registration_digest(receipts, quote.device, quote.inode)?;
    let profile = crate::receipt_store::native_receipt_sink_profile(
        &quote,
        &registration_digest,
        receipt_bytes,
        capability_id,
    )
    .map_err(|error| invalid(error.to_string()))?;
    let liability = PhysicalLiabilityData::registered_file(quote.wal_bytes, quote.disk_bytes)?;
    let mut purpose = outstanding(NativeFinishingPurposeV1::ReceiptSink, &profile, liability);
    purpose.page_recipe = Some(NativeFinishingPageRecipeV1 {
        page_bucket: quote.page_bucket,
        page_growth: quote.page_growth,
    });
    purpose.wal_frames = Some(quote.wal_frames);
    Ok(ReceiptSinkQuote {
        file: NativeFinishingFileV1 {
            role: NativeFinishingFileRoleV1::ReceiptSink,
            device: quote.device,
            inode: quote.inode,
        },
        registration_digest,
        liability: purpose,
    })
}

/// The registered sink's identity: its actual file and durable sink id.
pub(super) fn receipt_registration_digest(
    receipts: &crate::SqliteReceiptStore,
    device: u64,
    inode: u64,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(
        &canonical_json_bytes(&(
            "chio.native-finishing-receipt-sink.v1",
            device,
            inode,
            chio_kernel::receipt_store::ReceiptStore::durable_sink_id(receipts),
        ))
        .map_err(invalid)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_join_growth_reads_neither_the_file_nor_other_loans(
    ) -> Result<(), AdmissionOperationStoreError> {
        let recipe = solve_output_page_recipe(262, 400, None, 5_000)?;
        assert_eq!((recipe.page_bucket, recipe.page_growth), (8_192, 5_000));
        // A released loan or a larger file changes only the ceiling.
        let released = solve_output_page_recipe(662, 0, None, 5_000)?;
        assert_eq!((released.page_bucket, released.page_growth), (8_192, 5_000));
        let larger = solve_output_page_recipe(100_000, 0, None, 5_000)?;
        assert_eq!((larger.page_bucket, larger.page_growth), (131_072, 5_000));
        assert!(solve_output_page_recipe(1, 0, None, 0).is_err());
        Ok(())
    }

    #[test]
    fn a_second_output_must_fit_within_the_first_ceiling(
    ) -> Result<(), AdmissionOperationStoreError> {
        let first = solve_output_page_recipe(1_000, 0, None, 30_000)?;
        assert_eq!((first.page_bucket, first.page_growth), (32_768, 30_000));
        assert!(solve_output_page_recipe(
            1_000,
            first.page_growth,
            Some(first.page_bucket),
            30_000
        )
        .is_err());
        let second =
            solve_output_page_recipe(1_000, first.page_growth, Some(first.page_bucket), 768)?;
        assert_eq!((second.page_bucket, second.page_growth), (32_768, 768));
        Ok(())
    }

    #[test]
    fn real_flow_column_bounds_price_below_the_superseded_one_mib_blanket(
    ) -> Result<(), AdmissionOperationStoreError> {
        let profile = SqliteFramePriceProfileData::checked(4096, 0).map_err(invalid)?;
        let real = SqliteTransactionWriteShapeData::checked(flow_tree_write_shapes(None)?)
            .map_err(invalid)?;
        let blanket = SqliteTransactionWriteShapeData::checked(
            [1_048_576 + 4_096; 9]
                .iter()
                .copied()
                .map(|bound| SqliteTreeWriteShapeData::record(Some(bound), bound, 1))
                .collect::<Result<Vec<_>, _>>()
                .map_err(invalid)?,
        )
        .map_err(invalid)?;
        let priced = chio_sqlite_file_identity::price_transaction_write_shape(&profile, &real)
            .map_err(invalid)?;
        let blanket_price =
            chio_sqlite_file_identity::price_transaction_write_shape(&profile, &blanket)
                .map_err(invalid)?;
        assert!(priced.wal_bytes() < blanket_price.wal_bytes());
        Ok(())
    }

    #[test]
    fn a_first_output_selects_the_smallest_class_holding_its_own_room(
    ) -> Result<(), AdmissionOperationStoreError> {
        // Room 8 uses the one-byte integer-content class, whose floor is 2.
        assert_eq!(solve_output_width_class(5, None)?, (1, 2));
        // Room 128 and 32768 cross the one- and two-byte content ceilings.
        assert_eq!(solve_output_width_class(125, None)?, (2, 128));
        assert_eq!(solve_output_width_class(32_765, None)?, (3, 32_768));
        assert_eq!(solve_output_width_class(9_007_199_254_740_987, None)?.0, 8);
        assert!(solve_output_width_class(9_007_199_254_740_989, None).is_err());
        Ok(())
    }

    #[test]
    fn an_existing_retained_class_is_kept_and_must_hold_all_owed_slots(
    ) -> Result<(), AdmissionOperationStoreError> {
        assert_eq!(solve_output_width_class(100, Some((1, 2)))?, (1, 2));
        assert!(solve_output_width_class(125, Some((1, 1))).is_err());
        assert_eq!(solve_output_width_class(5, Some((3, 1)))?, (3, 32_768));
        Ok(())
    }
}
