//! D1 allocation rules shared by every allocator store. Each function checks
//! one transition against a consistent snapshot read inside the caller's
//! write transaction and returns the rows to persist; it performs no I/O.

use super::{types::*, DelegationError as Error, Result};
use chio_core::crypto::{Keypair, PublicKey};

/// Children a single slot may hold.
pub const MAX_CHILDREN_PER_SLOT: u64 = 64;
/// Slots a single root may hold, including the root.
pub const MAX_SLOTS_PER_ROOT: u64 = 4096;

/// Persisted state of one slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotState {
    pub slot: WorkSlot,
    pub parent: Option<String>,
    pub root: String,
    pub allocated: u64,
    pub selection: Option<Signed<Selection>>,
    pub revision: u64,
    pub dispatched: bool,
}

impl SlotState {
    /// Validate stored state read back from an allocator store.
    pub fn validate(&self) -> Result<()> {
        self.slot.validate()?;
        if self.allocated > self.slot.contract.max_units {
            return Err(Error::Invalid("stored allocation".into()));
        }
        if self.parent.is_none() != (self.root == self.slot.id) {
            return Err(Error::Invalid("stored allocation root".into()));
        }
        Ok(())
    }

    fn root(slot: WorkSlot) -> Self {
        Self {
            root: slot.id.clone(),
            slot,
            parent: None,
            allocated: 0,
            selection: None,
            revision: 0,
            dispatched: false,
        }
    }
}

/// Bind a mutation or offer to the allocator namespace and the exact root and slot.
pub fn allocation_digest(namespace: &str, root: &SlotState, row: &SlotState) -> Result<String> {
    hash(namespace)?;
    if root.parent.is_some() || root.root != root.slot.id || row.root != root.slot.id {
        return Err(Error::Invalid("stored allocation root".into()));
    }
    binding_digest(&("chio.work-allocation.v1", namespace, &root.slot, &row.slot))
}

/// Outcome of a root creation.
pub enum RootOutcome {
    Existing,
    Insert(Box<SlotState>),
}

/// Trusted owner configuration creating a root slot.
pub fn create_root(slot: WorkSlot, existing: Option<&SlotState>) -> Result<RootOutcome> {
    slot.validate()?;
    match existing {
        Some(row) if row.parent.is_none() && row.slot == slot => Ok(RootOutcome::Existing),
        Some(_) => Err(Error::Conflict),
        None => Ok(RootOutcome::Insert(Box::new(SlotState::root(slot)))),
    }
}

/// Outcome of a subdivision.
pub enum SubdivisionOutcome {
    Existing(Box<WorkSlot>),
    Insert {
        child: Box<SlotState>,
        parent_allocated: u64,
    },
}

/// Counts of existing slots under the parent and its root.
pub struct SubdivisionCounts {
    pub children: u64,
    pub root_slots: u64,
}

pub fn subdivide(
    request: &Signed<Subdivision>,
    parent: &SlotState,
    parent_allocation_hash: &str,
    existing_child: Option<&SlotState>,
    counts: SubdivisionCounts,
    now: u64,
) -> Result<SubdivisionOutcome> {
    request.verify_integrity_embedded_key()?;
    let child = &request.body.child;
    child.validate()?;
    if request.body.parent_allocation_hash != parent_allocation_hash {
        return Err(Error::Conflict);
    }
    if request.signer != parent.slot.holder {
        return Err(Error::Authority);
    }
    live(parent.slot.contract.expires_at, now)?;
    live(child.contract.expires_at, now)?;
    parent.slot.contract.permits_child(&child.contract)?;
    if parent.selection.is_some() {
        return Err(Error::Conflict);
    }
    if let Some(existing) = existing_child {
        if existing.slot != *child || existing.parent.as_ref() != Some(&parent.slot.id) {
            return Err(Error::Conflict);
        }
        return Ok(SubdivisionOutcome::Existing(Box::new(
            existing.slot.clone(),
        )));
    }
    let parent_allocated = parent
        .allocated
        .checked_add(child.contract.max_units)
        .ok_or(Error::Bounds)?;
    if parent_allocated > parent.slot.contract.max_units {
        return Err(Error::Bounds);
    }
    if counts.children >= MAX_CHILDREN_PER_SLOT || counts.root_slots >= MAX_SLOTS_PER_ROOT {
        return Err(Error::Bounds);
    }
    Ok(SubdivisionOutcome::Insert {
        child: Box::new(SlotState {
            slot: child.clone(),
            parent: Some(parent.slot.id.clone()),
            root: parent.root.clone(),
            allocated: 0,
            selection: None,
            revision: 0,
            dispatched: false,
        }),
        parent_allocated,
    })
}

/// Outcome of a selection.
pub enum SelectionOutcome {
    Unchanged,
    Replace { revision: u64 },
}

/// Enrollment in `qualified` is trusted local configuration, never a field
/// from an offer.
pub fn select(
    request: &Signed<Selection>,
    row: &SlotState,
    allocation_hash: &str,
    children: u64,
    now: u64,
    qualified: &[PublicKey],
) -> Result<SelectionOutcome> {
    request.verify_integrity_embedded_key()?;
    let selection = &request.body;
    selection.offer.verify_integrity_embedded_key()?;
    identifier(&selection.request_id)?;
    hash(&selection.capability_hash)?;
    let offer = &selection.offer.body;
    hash(&offer.arguments_hash)?;
    if offer.slot_id != row.slot.id
        || offer.contract_hash != binding_digest(&row.slot)?
        || offer.allocation_hash != allocation_hash
    {
        return Err(Error::Conflict);
    }
    if request.signer != row.slot.holder
        || selection.offer.signer != offer.receiver
        || !qualified.contains(&offer.receiver)
        || !row.slot.contract.readers.contains(&offer.receiver.to_hex())
    {
        return Err(Error::Authority);
    }
    live(row.slot.contract.expires_at, now)?;
    live(offer.expires_at, now)?;
    if offer.expires_at > row.slot.contract.expires_at
        || offer.price_units > row.slot.contract.max_units
        || !row.slot.contract.effects.contains(&offer.effect)
    {
        return Err(Error::Bounds);
    }
    if children != 0 {
        return Err(Error::Conflict);
    }
    if row.selection.as_ref() == Some(request) {
        return Ok(SelectionOutcome::Unchanged);
    }
    if row.dispatched || selection.expected_revision != row.revision {
        return Err(Error::Conflict);
    }
    let revision = row
        .revision
        .checked_add(1)
        .filter(|next| *next <= MAX_UNITS)
        .ok_or(Error::Bounds)?;
    Ok(SelectionOutcome::Replace { revision })
}

/// Irreversible claim of the selected leaf. Native operation replay is a
/// separate, required boundary; idempotence here is not permission to repeat
/// an effect.
pub fn claim(
    row: &SlotState,
    allocation_hash: &str,
    binding: &DispatchBinding,
    now: u64,
) -> Result<Admission> {
    let selection = row.selection.clone().ok_or(Error::Conflict)?;
    if binding.slot_id != row.slot.id
        || selection.body.offer.body.allocation_hash != allocation_hash
    {
        return Err(Error::Conflict);
    }
    validate_dispatch(&row.slot, &selection, binding, now)?;
    Ok(Admission {
        slot: row.slot.clone(),
        selection,
    })
}

/// Seal the claimed leaf. `retained` is the permit already stored for this
/// slot; a retry returns those exact bytes. A new permit is signed with the
/// allocator's configured key and must be persisted in the same commit that
/// marks the slot dispatched.
pub fn seal(
    row: &SlotState,
    allocation_hash: &str,
    binding: &DispatchBinding,
    retained: Option<Signed<DispatchPermit>>,
    now: u64,
    issuer: &Keypair,
) -> Result<Signed<DispatchPermit>> {
    let admission = claim(row, allocation_hash, binding, now)?;
    let permit = match retained {
        Some(permit) => permit,
        None => Signed::sign(
            DispatchPermit {
                allocation_hash: allocation_hash.to_owned(),
                root_id: row.root.clone(),
                slot: admission.slot,
                selection: admission.selection,
                issued_at: now,
            },
            issuer,
        )?,
    };
    if permit.body.allocation_hash != allocation_hash {
        return Err(Error::Conflict);
    }
    verify_dispatch_permit(&permit, binding, now, &[issuer.public_key()])?;
    Ok(permit)
}

/// Check a retained permit against its exact binding without granting fresh
/// liveness: an expired permit stays readable as history.
pub fn verify_historical_permit(
    permit: &Signed<DispatchPermit>,
    row: &SlotState,
    allocation_hash: &str,
    binding: &DispatchBinding,
    issuer: &PublicKey,
) -> Result<()> {
    permit.verify_integrity_embedded_key()?;
    if permit.signer != *issuer
        || permit.body.allocation_hash != allocation_hash
        || permit.body.slot != row.slot
        || permit.body.root_id != row.root
        || Some(&permit.body.selection) != row.selection.as_ref()
        || binding.slot_id != row.slot.id
    {
        return Err(Error::Conflict);
    }
    validate_dispatch(
        &row.slot,
        &permit.body.selection,
        binding,
        permit.body.issued_at,
    )
}
