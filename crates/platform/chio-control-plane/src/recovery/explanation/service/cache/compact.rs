use super::bounds::{self, NATIVE_FACTS, NATIVE_TEMPLATES};
use super::flat_label::FlatLabel;
use super::*;
use chio_kernel::recovery::MAX_RECOVERY_RECORD_BYTES;

/// One native context label replaces its repeated snapshot/fact/template copies.
/// The remaining profile labels share the same private dictionary when equal.
pub(in super::super) struct CompactGraph {
    snapshot: RecoverySnapshotV1,
    registry: RecoveryRemedyRegistryV1,
    report: SignedRecoveryExplanationReportV1,
    view: SignedRecoveryExplanationViewV1,
    labels: Box<[FlatLabel]>,
    audience: usize,
    disclosure: usize,
}

fn invalid() -> RecoveryRuntimeError {
    RecoveryRuntimeError::UnsupportedProfile
}

impl CompactGraph {
    pub(super) fn new(
        artifact: ProtectedRecoveryExplanationV1,
    ) -> Result<Self, RecoveryRuntimeError> {
        let ProtectedRecoveryExplanationV1 {
            mut snapshot,
            mut registry,
            report,
            view,
            classification,
            audience_clearance,
        } = artifact;
        snapshot.validate().map_err(|_| invalid())?;
        registry.validate(&snapshot).map_err(|_| invalid())?;
        if snapshot.observations.as_slice().len() != NATIVE_FACTS
            || registry.templates.as_slice().len() != NATIVE_TEMPLATES
            || snapshot.observations.as_slice().iter().any(|fact| {
                fact.label != snapshot.context_label
                    || fact.source != ExplanationFactSource::NativeAuthority
                    || fact.integrity != ExplanationIntegrity::NativeOwned
            })
            || registry.classification != snapshot.context_label
            || report.body().protected_graph_ref != view.body().report_ref
            || report.body().recipient != view.body().recipient
            || report.body().scope != snapshot.scope
            || report.body().issued_at_unix_ms != snapshot.observed_at_unix_ms
            || view.body().issued_at_unix_ms != snapshot.observed_at_unix_ms
            || matches!(audience_clearance, InformationLabel::Top)
        {
            return Err(invalid());
        }
        let context = core::mem::replace(&mut snapshot.context_label, InformationLabel::bottom());
        let mut facts = snapshot.observations.as_slice().to_vec();
        for fact in &mut facts {
            fact.label = InformationLabel::bottom();
        }
        snapshot.observations = BoundedList::new(facts).map_err(|_| invalid())?;
        registry.classification = InformationLabel::bottom();
        let mut templates = registry.templates.as_slice().to_vec();
        let template = templates.first_mut().ok_or_else(invalid)?;
        if template.classification != context
            || template.requirements.as_slice().len() != NATIVE_FACTS
        {
            return Err(invalid());
        }
        template.classification = InformationLabel::bottom();
        let disclosure =
            core::mem::replace(&mut template.disclosure_label, InformationLabel::bottom());
        registry.templates = BoundedList::new(templates).map_err(|_| invalid())?;
        let joined_classification = context
            .join_restrictions(&disclosure)
            .unwrap_or(InformationLabel::Top);
        if classification != joined_classification {
            return Err(invalid());
        }

        // These two labels came from one authenticated protected deployment.
        // Their combined serialization cannot exceed that deployment record.
        let profile_bytes = bounds::measure(
            &(&audience_clearance, &disclosure),
            MAX_RECOVERY_RECORD_BYTES,
        )?;
        let context_bytes = bounds::measure(&context, bounds::maximum_label_wire_bytes()?)?;
        let metadata_bytes = bounds::measure(
            &(&snapshot, &registry, &report, &view),
            bounds::METADATA_BYTES,
        )?;
        let encoded_bytes = context_bytes
            .checked_add(profile_bytes)
            .and_then(|bytes| bytes.checked_add(metadata_bytes))
            .ok_or_else(invalid)?;
        if encoded_bytes > bounds::maximum_wire_bytes()? {
            return Err(invalid());
        }

        let mut labels = vec![context];
        let mut insert = |label: InformationLabel| {
            if let Some(index) = labels.iter().position(|existing| existing == &label) {
                index
            } else {
                let index = labels.len();
                labels.push(label);
                index
            }
        };
        let audience = insert(audience_clearance);
        let disclosure = insert(disclosure);
        let labels = labels
            .into_iter()
            .map(FlatLabel::new)
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        let label_resident = labels.iter().try_fold(0usize, |total, label| {
            total
                .checked_add(label.resident_bytes()?)
                .ok_or_else(invalid)
        })?;
        if label_resident > bounds::reservation_bytes()? {
            return Err(invalid());
        }
        Ok(Self {
            snapshot,
            registry,
            report,
            view,
            labels,
            audience,
            disclosure,
        })
    }

    pub(super) fn reference(&self) -> &ExplanationRef {
        &self.view.body().report_ref
    }

    pub(super) fn recipient(&self) -> &ActorId {
        &self.view.body().recipient
    }

    pub(super) fn valid_at(&self, now: u64) -> bool {
        self.view.body().issued_at_unix_ms.get() <= now
            && now < self.view.body().expires_at_unix_ms.get()
    }

    pub(super) fn expires_at(&self) -> u64 {
        self.view.body().expires_at_unix_ms.get()
    }

    pub(in super::super) fn scope(&self) -> &RecoveryScopeV1 {
        &self.snapshot.scope
    }

    pub(in super::super) fn expand(
        &self,
    ) -> Result<ProtectedRecoveryExplanationV1, RecoveryRuntimeError> {
        let context = self.labels.first().ok_or_else(invalid)?.expand()?;
        let audience = self
            .labels
            .get(self.audience)
            .ok_or_else(invalid)?
            .expand()?;
        let disclosure = self
            .labels
            .get(self.disclosure)
            .ok_or_else(invalid)?
            .expand()?;
        let mut snapshot = self.snapshot.clone();
        snapshot.context_label = context.clone();
        let mut facts = snapshot.observations.as_slice().to_vec();
        for fact in &mut facts {
            fact.label = context.clone();
        }
        snapshot.observations = BoundedList::new(facts).map_err(|_| invalid())?;
        let mut registry = self.registry.clone();
        registry.classification = context.clone();
        let mut templates = registry.templates.as_slice().to_vec();
        let template = templates.first_mut().ok_or_else(invalid)?;
        template.classification = context.clone();
        let classification = context
            .join_restrictions(&disclosure)
            .unwrap_or(InformationLabel::Top);
        template.disclosure_label = disclosure;
        registry.templates = BoundedList::new(templates).map_err(|_| invalid())?;
        Ok(ProtectedRecoveryExplanationV1 {
            snapshot,
            registry,
            report: self.report.clone(),
            view: self.view.clone(),
            classification,
            audience_clearance: audience,
        })
    }
}
