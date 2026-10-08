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

    pub(super) fn validate_at_cut(
        &self,
        tx: &Connection,
        key: &str,
        scope: &RecoveryScopeV1,
        kind: &str,
        cut: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if self.source.record_key() != key
            || self.source.global_commit_sequence() > cut
            || !protected::matches_historical_source_payload_at_cut(
                tx,
                &self.source,
                key,
                &scope_key(scope)?,
                kind,
                &protected::encode(&self.body)?,
                cut,
            )?
        {
            return Err(refused("semantic input historical selected source changed"));
        }
        Ok(())
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

    pub(super) fn validate_at_cut(
        &self,
        tx: &Connection,
        expected: &SemanticAudienceObservationV1,
        cut: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let (exact, legacy) = audience_keys(expected)?;
        for (source, key) in [(&self.exact, &exact), (&self.legacy, &legacy)] {
            if let Some(source) = source {
                source.validate_at_cut(tx, key, &expected.scope, "command", cut)?;
            } else {
                require_absent_at_cut(tx, key, cut)?;
            }
        }
        self.selected(expected)?;
        Ok(())
    }
}

pub(super) fn require_absent_at_cut(
    tx: &Connection,
    key: &str,
    cut: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_global_commits
             WHERE projection_kind='recovery' AND projection_key=?1 AND commit_sequence<=?2)",
            params![key, i64::try_from(cut).map_err(refused)?],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if exists {
        return Err(refused("semantic input historical source absence changed"));
    }
    Ok(())
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
