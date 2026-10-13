//! Exact selected source versions are retained as data, never fresh references.
use super::*;
use serde::de::DeserializeOwned;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceRecord<T> {
    pub(super) source: protected::HistoricalProtectedSourceData,
    pub(super) body: T,
}

impl<T: Serialize + DeserializeOwned> SourceRecord<T> {
    pub(super) fn load(
        tx: &Connection,
        key: &str,
        scope: &RecoveryScopeV1,
        kind: &str,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let source = protected::source_reference(tx, key)?;
        if source.scope_key() != scope_key(scope)? || source.kind() != kind {
            return Err(refused("semantic input selected source identity"));
        }
        let body =
            load(tx, key)?.ok_or_else(|| refused("semantic input selected source absent"))?;
        Ok(Self {
            source: source.historical_data()?,
            body,
        })
    }

}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AudienceSources {
    exact: Option<SourceRecord<SignedSemanticAudienceV1>>,
    legacy: Option<SourceRecord<SignedSemanticAudienceV1>>,
}

fn audience_keys(
    expected: &SemanticAudienceObservationV1,
) -> Result<(String, String), AdmissionOperationStoreError> {
    Ok((
        audience_key(
            &expected.scope,
            &expected.provider,
            &expected.account,
            &expected.resource,
            &expected.subject_mapping,
            &expected.query,
        )?,
        format!(
            "semantic-acl:{}:{}",
            scope_key(&expected.scope)?,
            sha256_hex(&protected::encode(&(
                &expected.provider,
                &expected.account,
                &expected.resource,
            ))?)
        ),
    ))
}

fn same_audience_identity(
    actual: &SemanticAudienceObservationV1,
    expected: &SemanticAudienceObservationV1,
) -> bool {
    actual.scope == expected.scope
        && actual.provider == expected.provider
        && actual.account == expected.account
        && actual.resource == expected.resource
        && actual.subject_mapping == expected.subject_mapping
        && actual.query == expected.query
}

impl AudienceSources {
    pub(super) fn load(
        tx: &Connection,
        expected: &SemanticAudienceObservationV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let (exact, legacy) = audience_keys(expected)?;
        let load_optional = |key: &str| {
            if protected::raw_checked(tx, key)?.is_none() {
                Ok(None)
            } else {
                SourceRecord::load(tx, key, &expected.scope, "command").map(Some)
            }
        };
        let sources = Self {
            exact: load_optional(&exact)?,
            legacy: load_optional(&legacy)?,
        };
        sources.selected(expected)?;
        Ok(sources)
    }

    pub(super) fn selected(
        &self,
        expected: &SemanticAudienceObservationV1,
    ) -> Result<Option<&SignedSemanticAudienceV1>, AdmissionOperationStoreError> {
        if let Some(exact) = &self.exact {
            if !same_audience_identity(exact.body.body(), expected) {
                return Err(refused("semantic input exact ACL identity changed"));
            }
            return Ok(Some(&exact.body));
        }
        Ok(self
            .legacy
            .as_ref()
            .filter(|legacy| same_audience_identity(legacy.body.body(), expected))
            .map(|legacy| &legacy.body))
    }

}


pub(super) fn selected_annotations(
    tx: &Connection,
    invocation: &SemanticInvocationV1,
) -> Result<BoundedList<SourceRecord<SignedSemanticAnnotationV1>, 8>, AdmissionOperationStoreError>
{
    invocation
        .annotations
        .as_slice()
        .iter()
        .map(|proof| {
            let signer = semantic_key_digest(proof.authority_key()).map_err(refused)?;
            SourceRecord::load(
                tx,
                &annotations::annotation_key(&proof.body().scope, signer, &proof.body().input)?,
                &invocation.action.scope,
                "command",
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|sources| BoundedList::new(sources).map_err(refused))
}
