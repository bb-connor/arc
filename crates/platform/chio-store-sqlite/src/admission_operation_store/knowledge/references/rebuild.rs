//! A fenced rebuild drains authenticated overflow into fresh bounded buckets.
use super::*;
use crate::admission_operation_store::knowledge::reference_source::VerifiedKnowledgeReferenceRebuildAuthority;

mod census;
use census::VerifiedKnowledgeReferenceRebuild;



impl<'tx, 'conn> PreparedReferenceRebuild<'tx, 'conn> {




}


impl std::fmt::Debug for PreparedReferenceRebuild<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedReferenceRebuild([redacted])")
    }
}
