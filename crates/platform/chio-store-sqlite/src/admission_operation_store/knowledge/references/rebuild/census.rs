//! Complete current and historical leaf custody is verified before rebuilding.
use super::*;
use crate::admission_operation_store::knowledge::references::reader::{
    indexed, verify_owner_leaf, Indexed,
};
use std::ops::Deref;


impl<'tx, 'conn> VerifiedKnowledgeReferenceRebuild<'tx, 'conn> {






}

impl Drop for VerifiedKnowledgeReferenceRebuild<'_, '_> {
    fn drop(&mut self) {
        // Temporary cleanup does not change native custody or durable history.
        let _ = self
            .transaction
            .execute_batch(&format!("DROP TABLE IF EXISTS temp.{};", self.guards));
    }
}
