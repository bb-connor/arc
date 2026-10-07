//! Selected restrict-only annotations are current protected observations.
use super::*;

fn annotation_key(
    scope: &RecoveryScopeV1,
    signer: RoleKeyDigest,
    input: &SemanticInputVersionV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "semantic-annotation:{}:{}",
        scope_key(scope)?,
        sha256_hex(&protected::encode(&(signer, input))?)
    ))
}

pub(super) struct CurrentAnnotationAssessment {
    pub basis_changed: bool,
    pub restriction_floor: chio_security_types::InformationLabel,
}

pub(super) fn assess_current_annotations(
    tx: &Transaction<'_>,
    invocation: &SemanticInvocationV1,
    route: &SemanticRouteV1,
    now: u64,
    budget: &mut VerificationBudget,
) -> Result<CurrentAnnotationAssessment, AdmissionOperationStoreError> {
    let required = route
        .annotators
        .as_slice()
        .len()
        .checked_mul(invocation.action.inputs.as_slice().len())
        .ok_or_else(|| refused("annotation count overflow"))?;
    if required > 8 {
        return Err(refused("annotation envelope exhausted"));
    }
    let mut basis_changed = false;
    let mut restriction_floor = chio_security_types::InformationLabel::bottom();
    for proof in invocation.annotations.as_slice() {
        budget.charge(32).map_err(refused)?;
        let body = proof.body();
        let signer = semantic_key_digest(proof.authority_key()).map_err(refused)?;
        let current: SignedSemanticAnnotationV1 =
            load(tx, &annotation_key(&body.scope, signer, &body.input)?)?
                .ok_or_else(|| refused("current annotation absent"))?;
        let current_body = current.body();
        current_body.validate().map_err(refused)?;
        if current_body.scope != body.scope
            || current_body.input != body.input
            || semantic_key_digest(current.authority_key()).map_err(refused)? != signer
            || !current.verify_signature().map_err(refused)?
            || current_body.issued_at_unix_ms.get() > now
            || current_body.valid_until_unix_ms.get() <= now
            || body.issued_at_unix_ms.get() > now
            || body.valid_until_unix_ms.get() <= now
        {
            return Err(refused("current annotation authority or time changed"));
        }
        basis_changed |= current != *proof;
        restriction_floor = restriction_floor
            .join_restrictions(&current_body.restrictions)
            .map_err(refused)?;
    }
    for authority in route.annotators.as_slice() {
        for input in invocation.action.inputs.as_slice() {
            budget.charge(8).map_err(refused)?;
            let mut observed = false;
            for proof in invocation.annotations.as_slice() {
                if semantic_key_digest(proof.authority_key()).map_err(refused)? == authority.key
                    && proof.body().input == *input
                {
                    observed = true;
                    break;
                }
            }
            if !observed {
                return Err(refused("selected annotation omitted"));
            }
        }
    }
    Ok(CurrentAnnotationAssessment {
        basis_changed,
        restriction_floor,
    })
}

pub(super) fn verify_current_annotations(
    tx: &Transaction<'_>,
    invocation: &SemanticInvocationV1,
    route: &SemanticRouteV1,
    now: u64,
    budget: &mut VerificationBudget,
) -> Result<(), AdmissionOperationStoreError> {
    if assess_current_annotations(tx, invocation, route, now, budget)?.basis_changed {
        return Err(refused("annotation basis changed"));
    }
    Ok(())
}

impl SqliteAdmissionOperationStore {
    /// A selected signer can add restrictions and explicitly authorized facts.
    /// It cannot erase known restrictions on the same exact resource bytes.
    pub fn install_semantic_annotation(
        &self,
        value: &SignedSemanticAnnotationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        value.body().validate().map_err(refused)?;
        if !value.verify_signature().map_err(refused)? {
            return Err(refused("annotation signature"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, None)?;
        let body = value.body();
        let installed = installation(&tx, &body.scope)?;
        let signer = semantic_key_digest(value.authority_key()).map_err(refused)?;
        let selected = installed
            .deployment
            .body()
            .routes
            .as_slice()
            .iter()
            .flat_map(|route| route.annotators.as_slice())
            .any(|authority| {
                authority.key == signer
                    && (body.facts.as_slice().is_empty() || authority.may_attest_facts)
                    && body
                        .facts
                        .as_slice()
                        .iter()
                        .all(|fact| authority.facts.as_slice().contains(fact))
            });
        let now = schema::observe_authority_time(&tx)?;
        if !selected || body.issued_at_unix_ms.get() > now || body.valid_until_unix_ms.get() <= now
        {
            return Err(refused("annotation authority or time"));
        }
        let key = annotation_key(&body.scope, signer, &body.input)?;
        if let Some(prior) = load::<SignedSemanticAnnotationV1>(&tx, &key)? {
            if prior == *value {
                return self.commit_write(tx);
            }
            let old = prior.body();
            if old.issued_at_unix_ms >= body.issued_at_unix_ms
                || !old.restrictions.flows_to(&body.restrictions)
                || (old.externally_influenced && !body.externally_influenced)
            {
                return Err(refused("annotation observation regression"));
            }
        }
        save(
            &tx,
            &self.serving_owner,
            &body.scope,
            &key,
            "command",
            value,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
}
