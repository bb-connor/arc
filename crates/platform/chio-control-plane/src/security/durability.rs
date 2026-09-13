#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityDurability {
    Ephemeral,
    FilesystemBacked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityDurability {
    flow: AuthorityDurability,
    declassification: AuthorityDurability,
    decoy: AuthorityDurability,
    event: AuthorityDurability,
    response: AuthorityDurability,
    overlay: AuthorityDurability,
}

impl SecurityDurability {
    #[must_use]
    pub const fn new(
        flow: AuthorityDurability,
        declassification: AuthorityDurability,
        decoy: AuthorityDurability,
        event: AuthorityDurability,
        response: AuthorityDurability,
        overlay: AuthorityDurability,
    ) -> Self {
        Self {
            flow,
            declassification,
            decoy,
            event,
            response,
            overlay,
        }
    }

    #[must_use]
    pub const fn persistent() -> Self {
        Self::new(
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
            AuthorityDurability::FilesystemBacked,
        )
    }

    #[must_use]
    pub const fn is_persistent(self) -> bool {
        matches!(self.flow, AuthorityDurability::FilesystemBacked)
            && matches!(self.declassification, AuthorityDurability::FilesystemBacked)
            && matches!(self.decoy, AuthorityDurability::FilesystemBacked)
            && matches!(self.event, AuthorityDurability::FilesystemBacked)
            && matches!(self.response, AuthorityDurability::FilesystemBacked)
            && matches!(self.overlay, AuthorityDurability::FilesystemBacked)
    }
}
