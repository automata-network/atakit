//! Contract bindings from the pinned TeeWorkloadMeasurement artifacts.

pub use automata_tee_workload_measurement::stubs::{
    BaseImageRegistry, SessionRegistry, TeeVerifier, TpmVerifier, WorkloadRegistry,
};
pub use BaseImageRegistry::{
    getMeasurementVariantCall, getMeasurementVariantIdsCall, getPlatformProfileCall,
    getPlatformProfileIdsCall, isBaseImageRevokedCall,
};
pub use SessionRegistry::{
    akCollateralVerifierCall, baseImageRegistryCall, getNonceCall, getPcrPolicyCall,
    getSessionCall, getSessionOwnerCall, isSessionActiveCall, registerSessionCall,
    revokeSessionCall, rotateKeyCall, signatureVerifierCall, teeSecurityPolicyVerifierCall,
    teeVerifierCall, tpmVerifierCall, verifySessionSignatureCall, workloadRegistryCall,
};
pub use TeeVerifier::dcapAttestationCall;
pub use TpmVerifier::tpmAttestationCall;
pub use WorkloadRegistry::{
    addToWhitelistCall, getWorkloadCall, getWorkloadOwnerCall, isWhitelistedCall,
    isWorkloadRevokedCall, ownerCall, pausedCall, registerWorkloadCall, AttributeRequirement,
    PcrPolicyBlock, PcrSpec256, PublicIdentity, WorkloadSpec,
};
