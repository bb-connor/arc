//! Git-native managed branches for Computer resources.
//!
//! A snapshot is a tree object, a branch is an owner-namespaced ref, and the
//! project revision head is a ref the owner publishes. Branch writers hold a
//! generation-fenced lease; freezing advances the generation so a stale writer
//! cannot stage into a frozen revision. Apply records the sealed branch's one
//! publication intent before it moves the project ref, and the ref move
//! compares the head against the branch's exact base. An interrupted
//! publication is completed or refused only through its original identity.
//!
//! Every git invocation runs against a private bare object store with a
//! cleared environment, no system or global configuration, no hooks, no
//! filters and no alternates.

mod error;
mod git;
mod records;
mod tree;

use std::path::Path;

pub use error::{BranchError, UnsupportedKind};
pub use records::{BranchState, PublicationState, BRANCH_RECORD_SCHEMA, PUBLICATION_RECORD_SCHEMA};
pub use tree::TreeEntry;

use git::{Git, ZERO_OID};
use records::{BranchRecord, PublicationRecord};
use tree::Edit;

const NAMESPACE: &str = "refs/chio/computer";
const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_PRODUCER_BYTES: usize = 256;
const RECONCILE_ATTEMPTS: usize = 4;

/// RES-03 materialization bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_entries: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_path_bytes: usize,
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_file_bytes: 16 * 1024 * 1024,
            max_total_bytes: super::MAX_TRANSFER_BYTES,
            max_path_bytes: 4096,
            max_depth: 64,
        }
    }
}

/// An exact, validated managed revision of one project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    project_id: String,
    tree: String,
    entries: Vec<TreeEntry>,
}

impl Snapshot {
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn tree(&self) -> &str {
        &self.tree
    }

    pub fn entries(&self) -> &[TreeEntry] {
        &self.entries
    }
}

/// The write authority over one open branch at one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchLease {
    branch_id: String,
    generation: u64,
}

impl BranchLease {
    pub fn branch_id(&self) -> &str {
        &self.branch_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// One path changed between a sealed branch's base and output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    pub status: ChangeStatus,
    pub old_blob: Option<String>,
    pub new_blob: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeStatus {
    Added,
    Modified,
    Deleted,
}

/// The owner-side managed-branch service over one private object store.
pub struct ManagedBranches {
    git: Git,
    limits: Limits,
}

impl ManagedBranches {
    /// Opens (creating if absent) the private bare store at `store`.
    pub fn open(git_binary: &Path, store: &Path, limits: Limits) -> Result<Self, BranchError> {
        Ok(Self {
            git: Git::open(git_binary, store)?,
            limits,
        })
    }

    /// Admits a host directory as a new project's first managed revision.
    pub fn import_project(&self, project_id: &str, source: &Path) -> Result<Snapshot, BranchError> {
        check_identifier(project_id)?;
        let tree = tree::import_directory(&self.git, source, &self.limits)?;
        let reference = project_ref(project_id);
        if !self
            .git
            .transaction(&[format!("create {reference} {tree}")])?
        {
            return Err(BranchError::ProjectExists(project_id.to_owned()));
        }
        self.snapshot(project_id)
    }

    /// Snapshots the project's current managed revision.
    pub fn snapshot(&self, project_id: &str) -> Result<Snapshot, BranchError> {
        check_identifier(project_id)?;
        let tree = self
            .git
            .resolve(&project_ref(project_id))?
            .ok_or_else(|| BranchError::UnknownProject(project_id.to_owned()))?;
        let entries = tree::manifest(&self.git, &tree, &self.limits)?;
        Ok(Snapshot {
            project_id: project_id.to_owned(),
            tree,
            entries,
        })
    }

    /// The project's current revision head.
    pub fn project_head(&self, project_id: &str) -> Result<String, BranchError> {
        check_identifier(project_id)?;
        self.git
            .resolve(&project_ref(project_id))?
            .ok_or_else(|| BranchError::UnknownProject(project_id.to_owned()))
    }

    /// Creates an isolated writable branch of `snapshot`.
    pub fn create_branch(
        &self,
        snapshot: &Snapshot,
        branch_id: &str,
    ) -> Result<BranchLease, BranchError> {
        check_identifier(branch_id)?;
        let record = BranchRecord::open(branch_id, snapshot.project_id(), snapshot.tree());
        let blob = self.git.write_blob(&record.encode()?)?;
        let created = self.git.transaction(&[
            format!("create {} {}", branch_tree_ref(branch_id), snapshot.tree()),
            format!("create {} {blob}", branch_record_ref(branch_id)),
        ])?;
        if !created {
            return Err(BranchError::BranchExists(branch_id.to_owned()));
        }
        Ok(BranchLease {
            branch_id: branch_id.to_owned(),
            generation: record.generation,
        })
    }

    /// The branch's current tree.
    pub fn branch_tree(&self, branch_id: &str) -> Result<String, BranchError> {
        check_identifier(branch_id)?;
        self.git
            .resolve(&branch_tree_ref(branch_id))?
            .ok_or_else(|| BranchError::UnknownBranch(branch_id.to_owned()))
    }

    pub fn branch_state(&self, branch_id: &str) -> Result<BranchState, BranchError> {
        Ok(self.branch_record(branch_id)?.1.state)
    }

    /// Writes one file into the branch under the writer's lease.
    pub fn stage_write(
        &self,
        lease: &BranchLease,
        path: &str,
        content: &[u8],
        executable: bool,
    ) -> Result<String, BranchError> {
        tree::check_path(path, &self.limits)?;
        let size =
            u64::try_from(content.len()).map_err(|_| BranchError::BoundExceeded("file_bytes"))?;
        if size > self.limits.max_file_bytes {
            return Err(BranchError::BoundExceeded("file_bytes"));
        }
        let blob = self.git.write_blob(content)?;
        self.stage(
            lease,
            Edit::Write {
                path: path.to_owned(),
                blob,
                executable,
            },
        )
    }

    /// Removes one path from the branch under the writer's lease.
    pub fn stage_remove(&self, lease: &BranchLease, path: &str) -> Result<String, BranchError> {
        tree::check_path(path, &self.limits)?;
        self.stage(
            lease,
            Edit::Remove {
                path: path.to_owned(),
            },
        )
    }

    fn stage(&self, lease: &BranchLease, edit: Edit) -> Result<String, BranchError> {
        let (record_blob, record) = self.branch_record(&lease.branch_id)?;
        if lease.generation != record.generation {
            return Err(BranchError::StaleWriter {
                presented: lease.generation,
                current: record.generation,
            });
        }
        if record.state != BranchState::Open {
            return Err(BranchError::BranchFrozen);
        }
        let current = self.branch_tree(&lease.branch_id)?;
        let next = tree::edit_tree(&self.git, Some(&current), &[edit])?;
        tree::manifest(&self.git, &next, &self.limits)?;
        let committed = self.git.transaction(&[
            format!(
                "verify {} {record_blob}",
                branch_record_ref(&lease.branch_id)
            ),
            format!(
                "update {} {next} {current}",
                branch_tree_ref(&lease.branch_id)
            ),
        ])?;
        if !committed {
            let (_, now) = self.branch_record(&lease.branch_id)?;
            if now.generation != lease.generation {
                return Err(BranchError::StaleWriter {
                    presented: lease.generation,
                    current: now.generation,
                });
            }
            return Err(BranchError::ConcurrentUpdate(lease.branch_id.clone()));
        }
        Ok(next)
    }

    /// Fences every writer and binds the branch's current tree as its one
    /// proposed output revision.
    pub fn freeze(&self, branch_id: &str) -> Result<String, BranchError> {
        let (record_blob, record) = self.branch_record(branch_id)?;
        if record.state != BranchState::Open {
            return Err(BranchError::BranchFrozen);
        }
        let output = self.branch_tree(branch_id)?;
        tree::manifest(&self.git, &output, &self.limits)?;
        let frozen = record.frozen(&output)?;
        self.replace_record(branch_id, &record_blob, &frozen, Some(&output))?;
        Ok(output)
    }

    /// Retains the frozen output with its producer reference.
    pub fn seal(&self, branch_id: &str, producer: &str) -> Result<(), BranchError> {
        if producer.is_empty() || producer.len() > MAX_PRODUCER_BYTES {
            return Err(BranchError::InvalidIdentifier(producer.to_owned()));
        }
        let (record_blob, record) = self.branch_record(branch_id)?;
        if record.state != BranchState::Frozen {
            return Err(BranchError::BranchNotFrozen);
        }
        let sealed = record.sealed(producer);
        let output = sealed.output_tree.clone();
        self.replace_record(branch_id, &record_blob, &sealed, output.as_deref())
    }

    /// The exact base-to-output changes of a sealed branch. Every changed path
    /// must pass `release` or the whole diff is withheld.
    pub fn diff(
        &self,
        branch_id: &str,
        release: &dyn Fn(&str) -> bool,
    ) -> Result<Vec<Change>, BranchError> {
        let (_, record) = self.branch_record(branch_id)?;
        let output = match (&record.state, &record.output_tree) {
            (BranchState::Sealed, Some(output)) => output.clone(),
            _ => return Err(BranchError::BranchNotSealed),
        };
        let raw = self.git.run(
            "diff-tree",
            &[
                "diff-tree",
                "-r",
                "-z",
                "--no-renames",
                "--raw",
                &record.base_tree,
                &output,
            ],
            None,
            None,
        )?;
        let mut fields = raw.split(|byte| *byte == 0).filter(|f| !f.is_empty());
        let mut changes = Vec::new();
        while let Some(meta) = fields.next() {
            let meta = std::str::from_utf8(meta).map_err(|_| BranchError::Git("diff-tree"))?;
            let path = fields.next().ok_or(BranchError::Git("diff-tree"))?;
            let path = std::str::from_utf8(path).map_err(|_| BranchError::Git("diff-tree"))?;
            tree::check_path(path, &self.limits)?;
            let parts: Vec<&str> = meta.trim_start_matches(':').split(' ').collect();
            let [_, _, old, new, status] = parts.as_slice() else {
                return Err(BranchError::Git("diff-tree"));
            };
            let status = match *status {
                "A" => ChangeStatus::Added,
                "M" | "T" => ChangeStatus::Modified,
                "D" => ChangeStatus::Deleted,
                _ => return Err(BranchError::Git("diff-tree")),
            };
            if !release(path) {
                return Err(BranchError::ReleaseWithheld);
            }
            let blob = |oid: &str| (oid != ZERO_OID).then(|| oid.to_owned());
            changes.push(Change {
                path: path.to_owned(),
                status,
                old_blob: blob(old),
                new_blob: blob(new),
            });
        }
        Ok(changes)
    }

    /// Publishes a sealed branch's output as the project's revision head if
    /// the head still equals the branch's base. The publication intent is
    /// recorded first; a recorded publication is never applied afresh.
    pub fn apply(&self, branch_id: &str, publication_id: &str) -> Result<String, BranchError> {
        self.begin_publication(branch_id, publication_id)?;
        self.reconcile(branch_id)
    }

    /// Records the branch's one publication intent. The expected base is the
    /// tree the branch was created from.
    pub fn begin_publication(
        &self,
        branch_id: &str,
        publication_id: &str,
    ) -> Result<(), BranchError> {
        check_identifier(publication_id)?;
        let (record_blob, record) = self.branch_record(branch_id)?;
        let output = match (&record.state, &record.output_tree) {
            (BranchState::Sealed, Some(output)) => output.clone(),
            _ => return Err(BranchError::BranchNotSealed),
        };
        if let Some((_, existing)) = self.find_publication(branch_id)? {
            return Err(BranchError::PublicationPending(existing.publication_id));
        }
        let intent = PublicationRecord::intent(
            publication_id,
            branch_id,
            &record.project_id,
            &record.base_tree,
            &output,
        );
        let intent_blob = self.git.write_blob(&intent.encode()?)?;
        let recorded = self.git.transaction(&[
            format!("verify {} {record_blob}", branch_record_ref(branch_id)),
            format!("create {} {intent_blob}", publication_ref(branch_id)),
        ])?;
        if recorded {
            return Ok(());
        }
        match self.find_publication(branch_id)? {
            Some((_, existing)) => Err(BranchError::PublicationPending(existing.publication_id)),
            None => Err(BranchError::ConcurrentUpdate(branch_id.to_owned())),
        }
    }

    /// Completes or reports the branch's recorded publication by its original
    /// identity. A project head already at the output completes the record;
    /// a head at the expected base moves by compare-and-swap; any other head
    /// is a recorded conflict.
    pub fn reconcile(&self, branch_id: &str) -> Result<String, BranchError> {
        for _ in 0..RECONCILE_ATTEMPTS {
            let (intent_blob, intent) = self
                .find_publication(branch_id)?
                .ok_or_else(|| BranchError::UnknownPublication(branch_id.to_owned()))?;
            match &intent.state {
                PublicationState::Published => return Ok(intent.output_tree),
                PublicationState::Conflict { actual } => {
                    return Err(BranchError::BaseConflict {
                        expected: intent.expected_base,
                        actual: actual.clone(),
                    })
                }
                PublicationState::Intent => {}
            }
            let project = project_ref(&intent.project_id);
            let head = self
                .git
                .resolve(&project)?
                .ok_or_else(|| BranchError::UnknownProject(intent.project_id.clone()))?;
            let publication = publication_ref(branch_id);
            if head == intent.output_tree {
                let published = self.git.write_blob(&intent.published().encode()?)?;
                if self.git.transaction(&[
                    format!("verify {project} {head}"),
                    format!("update {publication} {published} {intent_blob}"),
                ])? {
                    return Ok(intent.output_tree);
                }
            } else if head == intent.expected_base {
                let published = self.git.write_blob(&intent.published().encode()?)?;
                if self.git.transaction(&[
                    format!("update {project} {} {head}", intent.output_tree),
                    format!("update {publication} {published} {intent_blob}"),
                ])? {
                    return Ok(intent.output_tree);
                }
            } else {
                let conflict = self.git.write_blob(&intent.conflict(&head).encode()?)?;
                if self.git.transaction(&[
                    format!("verify {project} {head}"),
                    format!("update {publication} {conflict} {intent_blob}"),
                ])? {
                    return Err(BranchError::BaseConflict {
                        expected: intent.expected_base,
                        actual: head,
                    });
                }
            }
        }
        Err(BranchError::ConcurrentUpdate(branch_id.to_owned()))
    }

    pub fn publication_state(&self, branch_id: &str) -> Result<PublicationState, BranchError> {
        self.find_publication(branch_id)?
            .map(|(_, record)| record.state)
            .ok_or_else(|| BranchError::UnknownPublication(branch_id.to_owned()))
    }

    fn branch_record(&self, branch_id: &str) -> Result<(String, BranchRecord), BranchError> {
        check_identifier(branch_id)?;
        let blob = self
            .git
            .resolve(&branch_record_ref(branch_id))?
            .ok_or_else(|| BranchError::UnknownBranch(branch_id.to_owned()))?;
        let record = BranchRecord::decode(&self.git.read_blob(&blob)?, branch_id)?;
        Ok((blob, record))
    }

    fn find_publication(
        &self,
        branch_id: &str,
    ) -> Result<Option<(String, PublicationRecord)>, BranchError> {
        check_identifier(branch_id)?;
        let Some(blob) = self.git.resolve(&publication_ref(branch_id))? else {
            return Ok(None);
        };
        let record = PublicationRecord::decode(&self.git.read_blob(&blob)?, branch_id)?;
        Ok(Some((blob, record)))
    }

    /// Replaces a branch record, verifying the branch tree still equals
    /// `tree` so no write lands between the read and the transition.
    fn replace_record(
        &self,
        branch_id: &str,
        old_blob: &str,
        next: &BranchRecord,
        tree: Option<&str>,
    ) -> Result<(), BranchError> {
        let blob = self.git.write_blob(&next.encode()?)?;
        let mut instructions = Vec::new();
        if let Some(tree) = tree {
            instructions.push(format!("verify {} {tree}", branch_tree_ref(branch_id)));
        }
        instructions.push(format!(
            "update {} {blob} {old_blob}",
            branch_record_ref(branch_id)
        ));
        if !self.git.transaction(&instructions)? {
            return Err(BranchError::ConcurrentUpdate(branch_id.to_owned()));
        }
        Ok(())
    }
}

fn check_identifier(value: &str) -> Result<(), BranchError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-');
    if valid {
        Ok(())
    } else {
        Err(BranchError::InvalidIdentifier(value.to_owned()))
    }
}

fn project_ref(project_id: &str) -> String {
    format!("{NAMESPACE}/projects/{project_id}")
}

fn branch_tree_ref(branch_id: &str) -> String {
    format!("{NAMESPACE}/branches/{branch_id}/tree")
}

fn branch_record_ref(branch_id: &str) -> String {
    format!("{NAMESPACE}/branches/{branch_id}/record")
}

fn publication_ref(branch_id: &str) -> String {
    format!("{NAMESPACE}/branches/{branch_id}/publication")
}
