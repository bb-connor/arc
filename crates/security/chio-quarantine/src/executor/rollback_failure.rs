use super::*;

pub(super) struct RollbackFailure<'a> {
    pub(super) current: ResponsePlanRecord,
    pub(super) effect_record: ResponseEffectRecord,
    pub(super) journal: EffectJournal,
    pub(super) attempt: u32,
    pub(super) installed_version_hash: Digest32,
    pub(super) error_code: ErrorCode,
    pub(super) work: &'a ScheduledWork,
    pub(super) now_unix_ms: u64,
}
