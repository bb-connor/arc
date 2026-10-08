//! A permanent exact-release marker serializes byte dispatch with independent Stop.
use super::*;
use chio_kernel::knowledge::{ArtifactBlobSealV1, VerifiedConfinedReturnDelivery};
use chio_security_types::confinement::{IsolationBoundaryV1, ReturnAdmissionV1};
use chio_security_types::knowledge::{ArtifactDeliveryStateV1, ArtifactReleaseKindV1};
use serde::{Deserialize, Serialize};

mod catalog;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryReceipt {
    boundary: IsolationBoundaryV1,
    seal: ArtifactBlobSealV1,
    admission: ReturnAdmissionV1,
}

impl Store {
    pub(crate) fn begin_verified_confined_delivery(
        &mut self,
        proof: VerifiedConfinedReturnDelivery,
        seal: &ArtifactBlobSealV1,
        admission: &ReturnAdmissionV1,
    ) -> Result<(), ProcessError> {
        self.require_enforced_knowledge()?;
        let boundary = proof.consume_for(seal, admission)?;
        let mut admission = admission.clone();
        admission.admitted.state = ArtifactDeliveryStateV1::Admitted;
        let receipt = DeliveryReceipt {
            boundary,
            seal: seal.clone(),
            admission,
        };
        let bytes = chio_core_types::canonical_json_bytes(&receipt)?;
        if bytes.len() > 262144 {
            return Err(ProcessError::Limit("confined delivery receipt"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_before_open(&tx)?;
        let (version, namespace, _) = metadata(&tx)?;
        if !matches!(version, 5..=7) || namespace != self.namespace {
            return Err(ProcessError::Conflict);
        }
        catalog::verify(&tx)?;
        verify_receipt(&tx, &receipt)?;
        let child =
            read_process(&tx, receipt.boundary.child.as_str())?.ok_or(ProcessError::Conflict)?;
        let parent = read_process(&tx, receipt.boundary.scope.process_id.as_str())?
            .ok_or(ProcessError::Conflict)?;
        require_running(&child)?;
        require_running(&parent)?;
        let prior: Option<Vec<u8>> = tx
            .query_row(
                "SELECT receipt FROM process_confined_delivery_markers WHERE child_id=?1",
                [receipt.boundary.child.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        match prior {
            Some(prior) if prior == bytes => (),
            Some(_) => return Err(ProcessError::Conflict),
            None => {
                tx.execute(
                    "INSERT INTO process_confined_delivery_markers(child_id,parent_id,boundary_id,release_id,receipt)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![receipt.boundary.child.as_str(),receipt.boundary.scope.process_id.as_str(),
                        receipt.boundary.boundary.as_str(),receipt.admission.admitted.release.as_str(),bytes],
                )?;
                if version < 7
                    && tx.execute(
                        "UPDATE process_runtime SET version=7 WHERE singleton=1 AND version=?1",
                        [version],
                    )? != 1
                {
                    return Err(ProcessError::Conflict);
                }
            }
        }
        verify_cohort(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

fn metadata(connection: &Connection) -> Result<(u32, String, String), ProcessError> {
    let (version, namespace, authority): (u32, Option<String>, Option<String>) = connection.query_row(
        "SELECT version,
         CASE WHEN typeof(namespace)='text' AND length(CAST(namespace AS BLOB)) BETWEEN 1 AND 256 THEN namespace END,
         CASE WHEN typeof(authority)='text' AND length(CAST(authority AS BLOB)) BETWEEN 1 AND 256 THEN authority END
         FROM process_runtime WHERE singleton=1",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    )?;
    Ok((
        version,
        namespace.ok_or(ProcessError::Conflict)?,
        authority.ok_or(ProcessError::Conflict)?,
    ))
}

fn verify_receipt(connection: &Connection, receipt: &DeliveryReceipt) -> Result<(), ProcessError> {
    let (_, namespace, authority) = metadata(connection)?;
    let boundary = &receipt.boundary;
    let seal = &receipt.seal;
    let admission = &receipt.admission;
    if boundary.parent.runtime.as_str() != namespace
        || boundary.scope.authority_domain.as_str() != authority
        || seal.runtime.as_str() != namespace
        || seal.process != boundary.child
        || seal.object.as_str() != boundary.boundary.as_str()
        || admission.boundary != boundary.boundary
        || admission.child != boundary.child
        || admission.contract != boundary.return_contract
        || admission.artifact.scope != boundary.scope
        || admission.admitted.artifact != admission.artifact
        || admission.admitted.recipient != boundary.parent
        || admission.admitted.policy != boundary.policy
        || admission.admitted.state != ArtifactDeliveryStateV1::Admitted
        || admission.admitted.kind
            != (ArtifactReleaseKindV1::IndependentlyAdmitted {
                request: boundary.request.clone(),
            })
    {
        return Err(ProcessError::Conflict);
    }
    let child = read_process(connection, boundary.child.as_str())?.ok_or(ProcessError::Conflict)?;
    let parent = read_process(connection, boundary.scope.process_id.as_str())?
        .ok_or(ProcessError::Conflict)?;
    crate::verify_capability(&parent.capability)?;
    crate::verify_capability(&child.capability)?;
    crate::validate_child(&parent.capability, &child.capability)?;
    if child.parent_id.as_deref() != Some(parent.id.as_str())
        || parent.parent_id.is_some()
        || parent.depth != 0
        || child.depth != 1
        || child.root_id != parent.id
        || parent.root_id != parent.id
        || chio_core_types::recovery::confined_capability_digest(&child.capability)?
            != boundary.child_capability
        || chio_core_types::recovery::confined_capability_digest(&parent.capability)?
            != boundary.parent_capability
    {
        return Err(ProcessError::Conflict);
    }
    let slot: Option<(
        String,
        String,
        String,
        String,
        Option<String>,
        Option<Vec<u8>>,
    )> = connection
        .query_row(
            "SELECT parent_id,boundary_id,boundary_digest,generation,sha256,
         CASE WHEN typeof(data)='blob' AND length(data) IN(4,5) THEN data END
         FROM process_confined_return_slots WHERE child_id=?1",
            [boundary.child.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((slot_parent, slot_boundary, slot_digest, generation, hash, bytes)) = slot else {
        return Err(ProcessError::Conflict);
    };
    let bytes = bytes.ok_or(ProcessError::Conflict)?;
    let content = chio_core_types::crypto::sha256_hex(&bytes);
    if slot_parent != parent.id
        || slot_boundary != boundary.boundary.as_str()
        || slot_digest
            != chio_core_types::crypto::sha256_hex(&chio_core_types::canonical_json_bytes(
                boundary,
            )?)
        || seal.generation.as_str() != format!("confined:{generation}")
        || hash.as_deref() != Some(content.as_str())
        || (bytes != b"true" && bytes != b"false")
        || seal.content != chio_core_types::recovery::knowledge_content_digest(&bytes)
        || seal.bytes.get() != bytes.len() as u64
    {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

/// This proof is independent of the unused reservation cohort and grants no
/// refund, collection or absence-of-future-output credit.
pub(super) fn verify_cohort(connection: &Connection) -> Result<(), ProcessError> {
    catalog::verify(connection)?;
    if metadata(connection)?.0 != 7 {
        return Err(ProcessError::Configuration(
            "confined delivery journal version changed",
        ));
    }
    let mut query = connection.prepare(
        "SELECT child_id,parent_id,boundary_id,release_id,
         CASE WHEN typeof(receipt)='blob' AND length(receipt) BETWEEN 1 AND 262144 THEN receipt END
         FROM process_confined_delivery_markers ORDER BY child_id",
    )?;
    let mut rows = query.query([])?;
    let mut found = false;
    while let Some(row) = rows.next()? {
        found = true;
        let child: String = row.get(0)?;
        let parent: String = row.get(1)?;
        let boundary: String = row.get(2)?;
        let release: String = row.get(3)?;
        let bytes: Option<Vec<u8>> = row.get(4)?;
        let bytes = bytes.ok_or(ProcessError::Conflict)?;
        let receipt: DeliveryReceipt = serde_json::from_slice(&bytes)?;
        if receipt.boundary.child.as_str() != child
            || receipt.boundary.scope.process_id.as_str() != parent
            || receipt.boundary.boundary.as_str() != boundary
            || receipt.admission.admitted.release.as_str() != release
            || chio_core_types::canonical_json_bytes(&receipt)? != bytes
        {
            return Err(ProcessError::Conflict);
        }
        verify_receipt(connection, &receipt)?;
    }
    if !found {
        return Err(ProcessError::Configuration(
            "confined delivery journal lacks actual ordered custody",
        ));
    }
    Ok(())
}

pub(super) fn verify_before_open(connection: &Connection) -> Result<(), ProcessError> {
    let runtime: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='process_runtime')",
        [],
        |row| row.get(0),
    )?;
    if !runtime {
        return if catalog::family_present(connection)? {
            Err(ProcessError::Conflict)
        } else {
            Ok(())
        };
    }
    let version: Option<u32> = connection
        .query_row(
            "SELECT version FROM process_runtime WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if version == Some(7) {
        return verify_cohort(connection);
    }
    if catalog::family_present(connection)? {
        catalog::verify(connection)?;
        let populated: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM process_confined_delivery_markers)",
            [],
            |row| row.get(0),
        )?;
        if populated {
            return Err(ProcessError::Configuration(
                "ordered delivery custody cannot be a predecessor",
            ));
        }
    }
    Ok(())
}

pub(super) fn install_or_verify(connection: &Connection, version: u32) -> Result<(), ProcessError> {
    if !catalog::family_present(connection)? {
        if version == 7 {
            return Err(ProcessError::Configuration(
                "confined delivery catalog disappeared",
            ));
        }
        connection.execute_batch(catalog::SQL)?;
    }
    verify_before_open(connection)
}

/// Call after updating Stop and retain its Result until after committing Stop.
/// A malformed marker cannot turn a stop request into a rollback.
pub(super) fn cancellation_has_ordered_return(
    connection: &Connection,
    id: &str,
) -> Result<bool, ProcessError> {
    verify_before_open(connection)?;
    if !catalog::family_present(connection)? {
        return Ok(false);
    }
    connection
        .query_row(
            "WITH RECURSIVE descendants(id) AS (
            SELECT id FROM processes WHERE id=?1
            UNION ALL SELECT p.id FROM processes p JOIN descendants d ON p.parent_id=d.id
         ) SELECT EXISTS(SELECT 1 FROM process_confined_delivery_markers m JOIN descendants d
            ON d.id=m.child_id OR d.id=m.parent_id)",
            [id],
            |row| row.get(0),
        )
        .map_err(ProcessError::from)
}
