//! Read-work observations grant no custody, mutation or influence authority.
use std::cell::Cell;

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static HISTORY_BODIES: Cell<u64> = const { Cell::new(0) };
    static CURRENT_PROJECTIONS: Cell<u64> = const { Cell::new(0) };
    static KNOWLEDGE_JOIN_PREVIEWS: Cell<u64> = const { Cell::new(0) };
    static KNOWLEDGE_JOIN_READBACKS: Cell<u64> = const { Cell::new(0) };
}

pub struct NativeInfluenceReadWorkFixture {
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl NativeInfluenceReadWorkFixture {
    pub fn begin() -> Result<Self, &'static str> {
        if ACTIVE.with(|active| active.replace(true)) {
            return Err("native influence read-work observation already active");
        }
        HISTORY_BODIES.with(|count| count.set(0));
        CURRENT_PROJECTIONS.with(|count| count.set(0));
        KNOWLEDGE_JOIN_PREVIEWS.with(|count| count.set(0));
        KNOWLEDGE_JOIN_READBACKS.with(|count| count.set(0));
        Ok(Self {
            _thread: std::marker::PhantomData,
        })
    }

    pub fn history_bodies(&self) -> u64 {
        HISTORY_BODIES.with(Cell::get)
    }

    pub fn current_projections(&self) -> u64 {
        CURRENT_PROJECTIONS.with(Cell::get)
    }

    pub fn knowledge_join_previews(&self) -> u64 {
        KNOWLEDGE_JOIN_PREVIEWS.with(Cell::get)
    }

    pub fn knowledge_join_readbacks(&self) -> u64 {
        KNOWLEDGE_JOIN_READBACKS.with(Cell::get)
    }
}

pub(super) fn knowledge_join_preview() {
    if ACTIVE.with(Cell::get) {
        KNOWLEDGE_JOIN_PREVIEWS.with(|count| count.set(count.get().saturating_add(1)));
    }
}

pub(super) fn knowledge_join_readback() {
    if ACTIVE.with(Cell::get) {
        KNOWLEDGE_JOIN_READBACKS.with(|count| count.set(count.get().saturating_add(1)));
    }
}

impl Drop for NativeInfluenceReadWorkFixture {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
    }
}

pub(super) fn history_body() {
    if ACTIVE.with(Cell::get) {
        HISTORY_BODIES.with(|count| count.set(count.get().saturating_add(1)));
    }
}

#[allow(dead_code)]
pub(super) fn current_projection() {
    if ACTIVE.with(Cell::get) {
        CURRENT_PROJECTIONS.with(|count| count.set(count.get().saturating_add(1)));
    }
}
