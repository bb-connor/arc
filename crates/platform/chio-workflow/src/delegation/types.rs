use super::{DelegationError as Error, Result};
use chio_core::{
    canonical_json_bytes,
    crypto::{sha256_hex, Keypair, PublicKey, Signature},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// RFC 8785 interoperable integer ceiling for this wire profile.
pub const MAX_UNITS: u64 = 9_007_199_254_740_991;
pub const MAX_ENVELOPE_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    pub server: String,
    pub tool: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Clause {
    Equals { pointer: String, value: Value },
    IntegerRange { pointer: String, min: i64, max: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub clauses: Vec<Clause>,
}

impl Acceptance {
    pub fn validate(&self) -> Result<()> {
        if self.clauses.is_empty() || self.clauses.len() > 16 {
            return invalid("acceptance clause count");
        }
        for clause in &self.clauses {
            let pointer = match clause {
                Clause::Equals { pointer, .. } => pointer,
                Clause::IntegerRange { pointer, min, max } => {
                    if min > max || min.unsigned_abs() > MAX_UNITS || max.unsigned_abs() > MAX_UNITS
                    {
                        return invalid("integer predicate range");
                    }
                    pointer
                }
            };
            if pointer.len() > 1024 || (!pointer.is_empty() && !pointer.starts_with('/')) {
                return invalid("JSON pointer");
            }
            let mut chars = pointer.chars();
            while let Some(c) = chars.next() {
                if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                    return invalid("JSON pointer escape");
                }
            }
        }
        canonical(self)?;
        Ok(())
    }

    /// Evaluates only these predicates; it cannot certify arbitrary usefulness.
    pub fn check(&self, value: &Value) -> Result<()> {
        self.validate()?;
        for clause in &self.clauses {
            let passes = match clause {
                Clause::Equals {
                    pointer,
                    value: expected,
                } => value.pointer(pointer) == Some(expected),
                Clause::IntegerRange { pointer, min, max } => value
                    .pointer(pointer)
                    .and_then(Value::as_i64)
                    .is_some_and(|n| n >= *min && n <= *max),
            };
            if !passes {
                return Err(Error::Rejected);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkContract {
    pub effects: BTreeSet<Effect>,
    /// Explicit owner-approved observer identifiers, including each holder and receiver key.
    pub readers: BTreeSet<String>,
    pub max_units: u64,
    pub currency: String,
    pub expires_at: u64,
    pub depth: u16,
    pub acceptance: Acceptance,
}

impl WorkContract {
    pub fn validate(&self) -> Result<()> {
        if self.effects.is_empty()
            || self.effects.len() > 64
            || self.readers.is_empty()
            || self.readers.len() > 256
            || self.max_units > MAX_UNITS
            || self.expires_at == 0
            || self.expires_at > MAX_UNITS
            || self.depth > 32
        {
            return invalid("envelope bounds");
        }
        identifier(&self.currency)?;
        for effect in &self.effects {
            identifier(&effect.server)?;
            identifier(&effect.tool)?;
        }
        for reader in &self.readers {
            identifier(reader)?;
        }
        self.acceptance.validate()?;
        canonical(self)?;
        Ok(())
    }

    pub(crate) fn permits_child(&self, child: &Self) -> Result<()> {
        child.validate()?;
        if !child.effects.is_subset(&self.effects)
            || !child.readers.is_subset(&self.readers)
            || child.currency != self.currency
            || child.max_units > self.max_units
            || child.expires_at > self.expires_at
            || child.depth >= self.depth
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSlot {
    pub id: String,
    pub holder: PublicKey,
    pub contract: WorkContract,
}
impl WorkSlot {
    pub(crate) fn validate(&self) -> Result<()> {
        identifier(&self.id)?;
        self.contract.validate()?;
        if !self.contract.readers.contains(&self.holder.to_hex()) {
            return Err(Error::Authority);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subdivision {
    pub parent_id: String,
    /// Commits the allocator namespace and complete immutable root/parent slots.
    pub parent_allocation_hash: String,
    pub child: WorkSlot,
}

/// Receiver-signed v2 offer with accepted-output pricing: a result rejected by
/// the bound predicate earns zero charge in the qualified native payment profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOffer {
    pub slot_id: String,
    pub allocation_hash: String,
    /// Includes holder, bounds and acceptance terms, not just a reusable name.
    pub contract_hash: String,
    pub receiver: PublicKey,
    pub effect: Effect,
    pub arguments_hash: String,
    pub price_units: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub offer: Signed<WorkOffer>,
    pub request_id: String,
    pub capability_hash: String,
    /// Compare-and-swap version. Replaying an older selection cannot undo a replacement.
    pub expected_revision: u64,
}

mod sealed {
    pub trait Body {
        const DOMAIN: &'static str;
    }
}
impl sealed::Body for Subdivision {
    const DOMAIN: &'static str = "chio.work-subdivision.v2";
}
impl sealed::Body for WorkOffer {
    const DOMAIN: &'static str = "chio.work-offer.v2";
}
impl sealed::Body for Selection {
    const DOMAIN: &'static str = "chio.work-selection.v2";
}

/// Portable evidence from an explicitly trusted resource allocator. It does
/// not assert that funds were escrowed or grant authority at a receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchPermit {
    pub root_id: String,
    pub allocation_hash: String,
    pub slot: WorkSlot,
    pub selection: Signed<Selection>,
    pub issued_at: u64,
}
impl sealed::Body for DispatchPermit {
    const DOMAIN: &'static str = "chio.work-dispatch-permit.v2";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub body: T,
    pub signer: PublicKey,
    pub signature: Signature,
}
impl<T: Serialize + sealed::Body> Signed<T> {
    pub fn sign(body: T, key: &Keypair) -> Result<Self> {
        let signer = key.public_key();
        let signature = key.sign(&signing_message::<T>(&body, &signer)?);
        Ok(Self {
            body,
            signer,
            signature,
        })
    }
    pub fn verify(&self) -> Result<()> {
        if !self.signer.verify_strict(
            &signing_message::<T>(&self.body, &self.signer)?,
            &self.signature,
        ) {
            return Err(Error::Signature);
        }
        Ok(())
    }
}
fn signing_message<T: Serialize + sealed::Body>(body: &T, signer: &PublicKey) -> Result<Vec<u8>> {
    canonical(&(T::DOMAIN, signer, body))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchBinding {
    pub slot_id: String,
    pub receiver: PublicKey,
    pub subject: PublicKey,
    pub request_id: String,
    pub capability_hash: String,
    pub arguments_hash: String,
    pub effect: Effect,
    pub max_units: u64,
    pub currency: String,
}

#[derive(Debug, Clone)]
pub struct Admission {
    pub slot: WorkSlot,
    pub selection: Signed<Selection>,
}

/// Check locally, without the issuer database. Issuer keys are trusted operator
/// configuration; never accept a key merely because it arrived in a permit.
pub fn verify_dispatch_permit(
    permit: &Signed<DispatchPermit>,
    binding: &DispatchBinding,
    now: u64,
    accepted_issuers: &[PublicKey],
) -> Result<Admission> {
    permit.verify()?;
    if !accepted_issuers.contains(&permit.signer) {
        return Err(Error::Authority);
    }
    let body = &permit.body;
    body.slot.validate()?;
    identifier(&body.root_id)?;
    if body.issued_at == 0 || body.issued_at > now {
        return invalid("permit issuance time");
    }
    let selection = &body.selection;
    selection.verify()?;
    selection.body.offer.verify()?;
    let offer = &selection.body.offer.body;
    hash(&body.allocation_hash)?;
    if offer.allocation_hash != body.allocation_hash {
        return Err(Error::Conflict);
    }
    if selection.signer != body.slot.holder
        || selection.body.offer.signer != offer.receiver
        || !body
            .slot
            .contract
            .readers
            .contains(&offer.receiver.to_hex())
    {
        return Err(Error::Authority);
    }
    if offer.slot_id != body.slot.id || binding.slot_id != body.slot.id {
        return Err(Error::Conflict);
    }
    if offer.contract_hash != binding_digest(&body.slot)? {
        return Err(Error::Conflict);
    }
    if offer.expires_at > body.slot.contract.expires_at
        || offer.price_units > body.slot.contract.max_units
        || !body.slot.contract.effects.contains(&offer.effect)
    {
        return Err(Error::Bounds);
    }
    validate_dispatch(&body.slot, selection, binding, now)?;
    Ok(Admission {
        slot: body.slot.clone(),
        selection: selection.clone(),
    })
}

pub(crate) fn validate_dispatch(
    slot: &WorkSlot,
    selection: &Signed<Selection>,
    binding: &DispatchBinding,
    now: u64,
) -> Result<()> {
    let offer = &selection.body.offer.body;
    live(slot.contract.expires_at, now)?;
    live(offer.expires_at, now)?;
    if binding.subject != slot.holder || binding.receiver != offer.receiver {
        return Err(Error::Authority);
    }
    if binding.request_id != selection.body.request_id
        || binding.capability_hash != selection.body.capability_hash
        || binding.arguments_hash != offer.arguments_hash
        || binding.effect != offer.effect
    {
        return Err(Error::Conflict);
    }
    if binding.currency != slot.contract.currency || binding.max_units > offer.price_units {
        return Err(Error::Bounds);
    }
    Ok(())
}

/// Excludes the evidence envelope to avoid a circular commitment. The slot and
/// exact payload are signed; capability and request identity are also bound.
pub fn work_input_digest(slot_id: &str, payload: &Value) -> Result<String> {
    binding_digest(&(slot_id, payload))
}

/// Domain-separated digest of an exact native capability or request payload.
pub fn binding_digest(value: &impl Serialize) -> Result<String> {
    Ok(sha256_hex(&canonical(&("chio.work-binding.v1", value))?))
}
pub(crate) fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = canonical_json_bytes(value).map_err(|e| Error::Invalid(e.to_string()))?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return invalid("envelope byte limit");
    }
    Ok(bytes)
}
pub(crate) fn identifier(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 256
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
    {
        return invalid("identifier");
    }
    Ok(())
}
pub(crate) fn hash(s: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return invalid("SHA-256 digest");
    }
    Ok(())
}
pub(crate) fn live(expires_at: u64, now: u64) -> Result<()> {
    if now == 0 || now > MAX_UNITS {
        return invalid("trusted clock");
    }
    if now >= expires_at {
        return Err(Error::Expired);
    }
    Ok(())
}
pub(crate) fn invalid<T>(message: &str) -> Result<T> {
    Err(Error::Invalid(message.into()))
}
