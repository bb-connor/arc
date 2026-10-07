//! Closed label atoms preserve exact owner, reader and compartment semantics.
use crate::admission_operation_store::{invariant, AdmissionOperationStoreError};
use chio_security_types::knowledge::*;
use chio_security_types::ports::BoundedVec;
use chio_security_types::recovery::*;
use chio_security_types::{Compartment, InformationLabel, PrincipalId, DEFAULT_LABEL_LIMITS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const MAX_LABELS: usize = 16;
const MAX_OWNERS: usize = DEFAULT_LABEL_LIMITS.max_owners();
const MAX_READERS: usize = DEFAULT_LABEL_LIMITS.max_readers_per_owner();
const MAX_COMPARTMENTS: usize = DEFAULT_LABEL_LIMITS.max_compartments();
const MAX_POLICIES: usize = MAX_LABELS * MAX_OWNERS;
const MAX_ATOMS: usize = MAX_LABELS * (MAX_OWNERS * (MAX_READERS + 1) + MAX_COMPARTMENTS);
const MAX_IDENTIFIER_JSON_BYTES: usize =
    2 * chio_security_types::flow::MAX_FLOW_IDENTIFIER_BYTES + 2;

/// Identifiers exclude control characters. Every remaining UTF-8 byte needs at
/// most two canonical JSON bytes (quote or backslash), plus the surrounding
/// quotes. This bound covers the complete public flow-label protocol.
pub(crate) const MAX_LOGICAL_LABEL_BYTES: usize = 128
    + MAX_OWNERS * (MAX_IDENTIFIER_JSON_BYTES + 4 + MAX_READERS * (MAX_IDENTIFIER_JSON_BYTES + 1))
    + MAX_COMPARTMENTS * (MAX_IDENTIFIER_JSON_BYTES + 1);

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct LabelIndex(u8);

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
struct AtomIndex(u32);

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
struct ReaderSetIndex(u16);

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
struct PolicyIndex(u16);

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderSet {
    readers: BoundedVec<AtomIndex, MAX_READERS>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    owner: AtomIndex,
    readers: ReaderSetIndex,
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LabelDefinition {
    Known {
        policies: BoundedVec<PolicyIndex, MAX_OWNERS>,
        compartments: BoundedVec<AtomIndex, MAX_COMPARTMENTS>,
    },
    Top,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelAtoms {
    atoms: BoundedVec<PrincipalId, MAX_ATOMS>,
    readers: BoundedVec<ReaderSet, MAX_POLICIES>,
    policies: BoundedVec<Policy, MAX_POLICIES>,
    values: BoundedVec<LabelDefinition, MAX_LABELS>,
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct LabelTable {
    wire: LabelAtoms,
    #[serde(skip)]
    expanded: OnceLock<Result<Vec<InformationLabel>, AdmissionOperationStoreError>>,
}

pub(crate) struct LabelTableBuilder {
    atoms: Vec<PrincipalId>,
    atom_index: BTreeMap<PrincipalId, AtomIndex>,
    readers: Vec<ReaderSet>,
    reader_index: BTreeMap<Vec<AtomIndex>, ReaderSetIndex>,
    policies: Vec<Policy>,
    policy_index: BTreeMap<Policy, PolicyIndex>,
    values: Vec<LabelDefinition>,
}

impl LabelTableBuilder {
    pub(crate) fn new() -> Self {
        Self {
            atoms: Vec::new(),
            atom_index: BTreeMap::new(),
            readers: Vec::new(),
            reader_index: BTreeMap::new(),
            policies: Vec::new(),
            policy_index: BTreeMap::new(),
            values: Vec::new(),
        }
    }

    fn atom(&mut self, value: &PrincipalId) -> Result<AtomIndex, AdmissionOperationStoreError> {
        if let Some(index) = self.atom_index.get(value) {
            return Ok(*index);
        }
        if self.atoms.len() == MAX_ATOMS {
            return Err(invalid());
        }
        let index = AtomIndex(u32::try_from(self.atoms.len()).map_err(|_| invalid())?);
        self.atoms.push(value.clone());
        self.atom_index.insert(value.clone(), index);
        Ok(index)
    }

    fn policy(
        &mut self,
        owner: &PrincipalId,
        readers: &BTreeSet<PrincipalId>,
    ) -> Result<PolicyIndex, AdmissionOperationStoreError> {
        if readers.len() > MAX_READERS || !readers.contains(owner) {
            return Err(invalid());
        }
        let owner = self.atom(owner)?;
        let readers = readers
            .iter()
            .map(|reader| self.atom(reader))
            .collect::<Result<Vec<_>, _>>()?;
        let readers_index = if let Some(index) = self.reader_index.get(&readers) {
            *index
        } else {
            if self.readers.len() == MAX_POLICIES {
                return Err(invalid());
            }
            let index = ReaderSetIndex(u16::try_from(self.readers.len()).map_err(|_| invalid())?);
            self.readers.push(ReaderSet {
                readers: BoundedVec::new(readers.clone()).map_err(|_| invalid())?,
            });
            self.reader_index.insert(readers, index);
            index
        };
        let policy = Policy {
            owner,
            readers: readers_index,
        };
        if let Some(index) = self.policy_index.get(&policy) {
            return Ok(*index);
        }
        if self.policies.len() == MAX_POLICIES {
            return Err(invalid());
        }
        let index = PolicyIndex(u16::try_from(self.policies.len()).map_err(|_| invalid())?);
        self.policies.push(policy);
        self.policy_index.insert(policy, index);
        Ok(index)
    }

    pub(crate) fn insert(
        &mut self,
        label: &InformationLabel,
    ) -> Result<LabelIndex, AdmissionOperationStoreError> {
        let value = match label {
            InformationLabel::Top => LabelDefinition::Top,
            InformationLabel::Known {
                owners,
                compartments,
                ..
            } => {
                if owners.len() > MAX_OWNERS || compartments.len() > MAX_COMPARTMENTS {
                    return Err(invalid());
                }
                let policies = owners
                    .iter()
                    .map(|(owner, readers)| self.policy(owner, readers))
                    .collect::<Result<Vec<_>, _>>()?;
                let compartments = compartments
                    .iter()
                    .map(|value| {
                        let identifier = PrincipalId::new(value.as_str()).map_err(|_| invalid())?;
                        self.atom(&identifier)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                LabelDefinition::Known {
                    policies: BoundedVec::new(policies).map_err(|_| invalid())?,
                    compartments: BoundedVec::new(compartments).map_err(|_| invalid())?,
                }
            }
        };
        if let Some(index) = self.values.iter().position(|known| *known == value) {
            return u8::try_from(index).map(LabelIndex).map_err(|_| invalid());
        }
        if self.values.len() == MAX_LABELS {
            return Err(invalid());
        }
        let index = LabelIndex(u8::try_from(self.values.len()).map_err(|_| invalid())?);
        self.values.push(value);
        Ok(index)
    }

    pub(crate) fn finish(self) -> Result<LabelTable, AdmissionOperationStoreError> {
        let table = LabelTable {
            wire: LabelAtoms {
                atoms: BoundedVec::new(self.atoms).map_err(|_| invalid())?,
                readers: BoundedVec::new(self.readers).map_err(|_| invalid())?,
                policies: BoundedVec::new(self.policies).map_err(|_| invalid())?,
                values: BoundedVec::new(self.values).map_err(|_| invalid())?,
            },
            expanded: OnceLock::new(),
        };
        table.validate()?;
        Ok(table)
    }
}

impl LabelAtoms {
    fn atom(&self, index: AtomIndex) -> Result<&PrincipalId, AdmissionOperationStoreError> {
        self.atoms
            .as_slice()
            .get(usize::try_from(index.0).map_err(|_| invalid())?)
            .ok_or_else(invalid)
    }

    /// Checks every index, ordering, self-reader, alias and actual logical byte
    /// count before allocating any expanded owner map or repeated label.
    fn layout(&self) -> Result<Vec<usize>, AdmissionOperationStoreError> {
        if self.values.is_empty()
            || self.atoms.as_slice().iter().collect::<BTreeSet<_>>().len() != self.atoms.len()
            || self
                .policies
                .as_slice()
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.policies.len()
            || self
                .values
                .as_slice()
                .iter()
                .enumerate()
                .any(|(index, value)| self.values.as_slice()[..index].contains(value))
        {
            return Err(invalid());
        }
        let mut reader_sets = BTreeSet::new();
        for readers in self.readers.as_slice() {
            if readers.readers.is_empty()
                || !reader_sets.insert(readers.readers.as_slice())
                || !readers.readers.as_slice().windows(2).all(|pair| {
                    matches!((self.atom(pair[0]), self.atom(pair[1])), (Ok(a), Ok(b)) if a < b)
                })
            {
                return Err(invalid());
            }
            for index in readers.readers.as_slice() {
                self.atom(*index)?;
            }
        }
        let atom_bytes = self
            .atoms
            .as_slice()
            .iter()
            .map(|atom| chio_core::canonical_json_bytes(atom).map(|bytes| bytes.len()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        let mut atoms_seen = vec![false; self.atoms.len()];
        let mut readers_seen = vec![false; self.readers.len()];
        let mut policies_seen = vec![false; self.policies.len()];
        let mut next_atom = 0;
        let mut next_readers = 0;
        let mut next_policy = 0;
        let mut lengths = Vec::with_capacity(self.values.len());
        for value in self.values.as_slice() {
            let bytes = match value {
                LabelDefinition::Top => b"{\"kind\":\"top\"}".len(),
                LabelDefinition::Known {
                    policies,
                    compartments,
                } => {
                    let mut bytes = b"{\"compartments\":[],\"kind\":\"known\",\"owners\":{}}".len();
                    let mut previous_owner = None;
                    for index in policies.as_slice() {
                        let index = usize::from(index.0);
                        let policy = self.policies.as_slice().get(index).ok_or_else(invalid)?;
                        let owner = self.atom(policy.owner)?;
                        if previous_owner.is_some_and(|previous| previous >= owner) {
                            return Err(invalid());
                        }
                        previous_owner = Some(owner);
                        first_occurrence(&mut atoms_seen, &mut next_atom, policy.owner.0)?;
                        let readers_index = usize::from(policy.readers.0);
                        let readers = self
                            .readers
                            .as_slice()
                            .get(readers_index)
                            .ok_or_else(invalid)?;
                        if !readers.readers.as_slice().contains(&policy.owner) {
                            return Err(invalid());
                        }
                        bytes = add(
                            bytes,
                            atom_bytes[usize::try_from(policy.owner.0).map_err(|_| invalid())?],
                        )?;
                        bytes = add(bytes, 3)?; // colon and two reader-array delimiters
                        for reader in readers.readers.as_slice() {
                            first_occurrence(&mut atoms_seen, &mut next_atom, reader.0)?;
                            bytes = add(
                                bytes,
                                atom_bytes[usize::try_from(reader.0).map_err(|_| invalid())?],
                            )?;
                        }
                        bytes = add(bytes, readers.readers.len().saturating_sub(1))?;
                        first_occurrence(
                            &mut readers_seen,
                            &mut next_readers,
                            u32::from(policy.readers.0),
                        )?;
                        first_occurrence(
                            &mut policies_seen,
                            &mut next_policy,
                            u32::try_from(index).map_err(|_| invalid())?,
                        )?;
                    }
                    bytes = add(bytes, policies.len().saturating_sub(1))?;
                    let mut previous_compartment = None;
                    for index in compartments.as_slice() {
                        let compartment = self.atom(*index)?;
                        if previous_compartment.is_some_and(|previous| previous >= compartment) {
                            return Err(invalid());
                        }
                        previous_compartment = Some(compartment);
                        first_occurrence(&mut atoms_seen, &mut next_atom, index.0)?;
                        bytes = add(
                            bytes,
                            atom_bytes[usize::try_from(index.0).map_err(|_| invalid())?],
                        )?;
                    }
                    add(bytes, compartments.len().saturating_sub(1))?
                }
            };
            if bytes > MAX_LOGICAL_LABEL_BYTES {
                return Err(invalid());
            }
            lengths.push(bytes);
        }
        if next_atom != self.atoms.len()
            || next_readers != self.readers.len()
            || next_policy != self.policies.len()
        {
            return Err(invalid());
        }
        Ok(lengths)
    }

    fn expand(&self) -> Result<Vec<InformationLabel>, AdmissionOperationStoreError> {
        self.layout()?;
        self.values
            .as_slice()
            .iter()
            .map(|value| match value {
                LabelDefinition::Top => Ok(InformationLabel::Top),
                LabelDefinition::Known {
                    policies,
                    compartments,
                } => {
                    let mut owners = BTreeMap::new();
                    for index in policies.as_slice() {
                        let policy = self
                            .policies
                            .as_slice()
                            .get(usize::from(index.0))
                            .ok_or_else(invalid)?;
                        let set = self
                            .readers
                            .as_slice()
                            .get(usize::from(policy.readers.0))
                            .ok_or_else(invalid)?;
                        let readers = set
                            .readers
                            .as_slice()
                            .iter()
                            .map(|index| self.atom(*index).cloned())
                            .collect::<Result<BTreeSet<_>, _>>()?;
                        owners.insert(self.atom(policy.owner)?.clone(), readers);
                    }
                    let compartments = compartments
                        .as_slice()
                        .iter()
                        .map(|index| {
                            Compartment::new(self.atom(*index)?.as_str()).map_err(|_| invalid())
                        })
                        .collect::<Result<BTreeSet<_>, _>>()?;
                    InformationLabel::try_known(owners, compartments).map_err(|_| invalid())
                }
            })
            .collect()
    }
}

impl LabelTable {
    pub(crate) fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        self.wire.layout().map(|_| ())
    }

    /// The closed owning schema supplies its exact label slots before any map
    /// expansion. An internally valid but unused extra label is still refused.
    pub(crate) fn validate_references(
        &self,
        references: &[LabelIndex],
    ) -> Result<(), AdmissionOperationStoreError> {
        self.validate()?;
        let mut seen = vec![false; self.wire.values.len()];
        let mut next = 0;
        for index in references {
            first_occurrence(&mut seen, &mut next, u32::from(index.0))?;
        }
        if next != self.wire.values.len() {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn label(
        &self,
        index: LabelIndex,
    ) -> Result<&InformationLabel, AdmissionOperationStoreError> {
        match self.expanded.get_or_init(|| self.wire.expand()) {
            Ok(values) => values.get(usize::from(index.0)).ok_or_else(invalid),
            Err(_) => Err(invalid()),
        }
    }
    pub(crate) fn label_bytes(
        &self,
        index: LabelIndex,
    ) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        chio_core::canonical_json_bytes(self.label(index)?).map_err(|_| invalid())
    }
    pub(crate) fn logical_label_bytes(
        &self,
        index: LabelIndex,
    ) -> Result<usize, AdmissionOperationStoreError> {
        self.wire
            .layout()?
            .get(usize::from(index.0))
            .copied()
            .ok_or_else(invalid)
    }
    pub(crate) fn maximum_label_bytes(&self) -> Result<usize, AdmissionOperationStoreError> {
        self.wire.layout()?.into_iter().max().ok_or_else(invalid)
    }
    pub(crate) fn expansion_budget(
        &self,
        occurrences: usize,
        other_bytes: usize,
    ) -> Result<usize, AdmissionOperationStoreError> {
        self.maximum_label_bytes()?
            .checked_mul(occurrences)
            .and_then(|bytes| bytes.checked_add(other_bytes))
            .ok_or_else(invalid)
    }
}

fn first_occurrence(
    seen: &mut [bool],
    next: &mut usize,
    index: u32,
) -> Result<(), AdmissionOperationStoreError> {
    let index = usize::try_from(index).map_err(|_| invalid())?;
    let value = seen.get_mut(index).ok_or_else(invalid)?;
    if !*value {
        if index != *next {
            return Err(invalid());
        }
        *value = true;
        *next = next.checked_add(1).ok_or_else(invalid)?;
    }
    Ok(())
}
fn add(left: usize, right: usize) -> Result<usize, AdmissionOperationStoreError> {
    left.checked_add(right).ok_or_else(invalid)
}
fn invalid() -> AdmissionOperationStoreError {
    invariant("knowledge label atom encoding is invalid")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredRecipient {
    recipient: ArtifactRecipientId,
    scope: RecoveryScopeV1,
    runtime: ProtectedText<128>,
    principal: chio_security_types::PrincipalId,
    lineage: IsolationLineageId,
    isolation_epoch: ProtectedText<128>,
    context_generation: SafeInteger,
    clearance: LabelIndex,
    sink: ArtifactSinkV1,
}

impl StoredRecipient {
    pub(crate) fn label_reference(&self) -> LabelIndex {
        self.clearance
    }

    pub(crate) fn capture(
        value: &ArtifactRecipientV1,
        labels: &mut LabelTableBuilder,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            recipient: value.recipient.clone(),
            scope: value.scope.clone(),
            runtime: value.runtime.clone(),
            principal: value.principal.clone(),
            lineage: value.lineage.clone(),
            isolation_epoch: value.isolation_epoch.clone(),
            context_generation: value.context_generation,
            clearance: labels.insert(&value.clearance)?,
            sink: value.sink.clone(),
        })
    }
    pub(crate) fn expand(
        &self,
        labels: &LabelTable,
    ) -> Result<ArtifactRecipientV1, AdmissionOperationStoreError> {
        Ok(ArtifactRecipientV1 {
            recipient: self.recipient.clone(),
            scope: self.scope.clone(),
            runtime: self.runtime.clone(),
            principal: self.principal.clone(),
            lineage: self.lineage.clone(),
            isolation_epoch: self.isolation_epoch.clone(),
            context_generation: self.context_generation,
            clearance: labels.label(self.clearance)?.clone(),
            sink: self.sink.clone(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredRelease {
    domain_version: VersionV1,
    release: ReleaseId,
    kind: ArtifactReleaseKindV1,
    artifact: ArtifactVersionRefV1,
    source_label: LabelIndex,
    admitted_label: LabelIndex,
    influence: ArtifactInfluenceV1,
    recipient: StoredRecipient,
    policy: PolicyDigest,
    authorization: ReleaseAuthorizationDigest,
    observation_transition: EvidenceRef,
    observation_generation: SafeInteger,
    state: ArtifactDeliveryStateV1,
}

impl StoredRelease {
    pub(crate) fn label_references(&self) -> [LabelIndex; 3] {
        [
            self.source_label,
            self.admitted_label,
            self.recipient.label_reference(),
        ]
    }

    pub(crate) fn capture(
        value: &ArtifactReleaseIntentV1,
        labels: &mut LabelTableBuilder,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            domain_version: value.domain_version,
            release: value.release.clone(),
            kind: value.kind.clone(),
            artifact: value.artifact.clone(),
            source_label: labels.insert(&value.source_label)?,
            admitted_label: labels.insert(&value.admitted_label)?,
            influence: value.influence.clone(),
            recipient: StoredRecipient::capture(&value.recipient, labels)?,
            policy: value.policy,
            authorization: value.authorization,
            observation_transition: value.observation_transition.clone(),
            observation_generation: value.observation_generation,
            state: value.state,
        })
    }
    pub(crate) fn expand(
        &self,
        labels: &LabelTable,
    ) -> Result<ArtifactReleaseIntentV1, AdmissionOperationStoreError> {
        Ok(ArtifactReleaseIntentV1 {
            domain_version: self.domain_version,
            release: self.release.clone(),
            kind: self.kind.clone(),
            artifact: self.artifact.clone(),
            source_label: labels.label(self.source_label)?.clone(),
            admitted_label: labels.label(self.admitted_label)?.clone(),
            influence: self.influence.clone(),
            recipient: self.recipient.expand(labels)?,
            policy: self.policy,
            authorization: self.authorization,
            observation_transition: self.observation_transition.clone(),
            observation_generation: self.observation_generation,
            state: self.state,
        })
    }
}
