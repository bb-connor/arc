use super::*;


#[cfg(feature = "std")]
pub trait SealedDecoyRegistryStore: Send + Sync {
    fn load_by_id(&self, id: &DecoyArtifactLookup) -> PortResult<Option<SealedDecoyRecord>>;
    fn load_by_marker(&self, lookup: &SealedMarkerLookup) -> PortResult<Option<SealedDecoyRecord>>;
    fn load_by_public_ref(
        &self,
        lookup: &SealedPublicRefLookup,
    ) -> PortResult<Option<SealedDecoyRecord>>;
    fn compare_and_swap(&self, request: &SealedDecoyCasRequest) -> PortResult<SealedDecoyRecord>;
    fn scan(&self, scan: &DecoyScan) -> PortResult<SealedDecoyPage>;
}

#[cfg(feature = "std")]
pub trait WatermarkSequenceStore: Send + Sync {
    fn reserve(
        &self,
        request: &WatermarkSequenceReservation,
    ) -> PortResult<WatermarkSequenceReservationResult>;
}

#[cfg(feature = "std")]
pub trait WatermarkObservationStore: Send + Sync {
    fn record_first(
        &self,
        observation: &WatermarkObservation,
    ) -> PortResult<WatermarkObservationResult>;
}
