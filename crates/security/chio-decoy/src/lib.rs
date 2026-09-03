#![forbid(unsafe_code)]

pub mod lifecycle;
pub mod matcher;
pub mod materialize;
pub mod registry;
pub mod watermark;

pub use chio_security_types::ports::{WatermarkObservationStore, WatermarkSequenceStore};
pub use chio_security_types::{
    WatermarkObservation, WatermarkObservationResult, WatermarkSequenceKey,
    WatermarkSequenceReservation, WatermarkSequenceReservationResult,
};

pub use lifecycle::{
    fail_transition, retry_transition, transition, ArmedReplacement, LifecycleError,
};
pub use matcher::{
    DecoyDetection, DecoyDetector, DetectionConfidence, DetectionFailure, ObservationClass,
    TripwireObservation,
};
pub use materialize::{
    CleanupOutcome, CleanupRequest, FileMaterializer, FileOwnershipProof, MaterializationIdentity,
    MaterializationReceipt, MaterializationRequest, MaterializeError, OwnershipKey, PathViolation,
    PersistedFileType,
};
pub use registry::{
    DecoyCreateRequest, PrivateDecoyRegistry, PrivilegedExportCredential, PrivilegedExportPage,
    RegistryError, RegistryExportAuthorizer, RegistryExportGrant, RegistryKey, RegistryKeyProvider,
    SecretMaterial,
};
pub use watermark::{
    InactiveWatermark, SignedWatermarkEnvelope, TrustedWatermarkKey, VerifiedWatermark,
    WatermarkCandidateError, WatermarkClock, WatermarkEncoding, WatermarkIssueError,
    WatermarkIssueRequest, WatermarkIssuer, WatermarkIssuerConfig, WatermarkIssuerDependencies,
    WatermarkIssuerPolicy, WatermarkKeyResolver, WatermarkKeyStatus, WatermarkObservationContext,
    WatermarkObservationPersistence, WatermarkPayload, WatermarkRegistryState, WatermarkScanError,
    WatermarkScanReport, WatermarkScanVerdict, WatermarkSourceContext,
    WatermarkSourceContextResolver, WatermarkVerifier, WatermarkVerifierDependencies,
    MAX_IJSON_INTEGER,
};
