# atakit-attestation-client

`atakit-attestation-client` is the read-only network client for atakit
attestation verification. The caller selects an RPC endpoint and a
`SessionRegistry` address. Portal evidence cannot select or replace either
value.

The client:

- checks the RPC-reported chain ID;
- derives `BaseImageRegistry` and `WorkloadRegistry` from `SessionRegistry`;
- checks optional expected registry addresses;
- loads the registered base-image measurement policy;
- loads and validates the registered `WorkloadSpec`;
- checks GCP vTPM AK and AMD ARK roots against the verifier contracts;
- resolves Azure MAA signing keys, including revocation, issuer, and expiry;
- produces `TrustedSessionBinding`; and
- fetches and verifies a fresh current-session evidence bundle after portal
  TLS has been verified.

It never signs or submits a transaction. It does not verify consensus or
storage proofs. The configured `rpc_url` is therefore a trusted data source.

## Connect and resolve policy

```rust,no_run
use atakit_attestation_client::{AttestationClient, AttestationClientConfig};

# async fn example(selected_base_image_id: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
let client = AttestationClient::connect(AttestationClientConfig {
    rpc_url: "https://rpc.example.invalid".to_string(),
    session_registry: "0x1111111111111111111111111111111111111111".to_string(),
    expected_chain_id: Some(12345),
    expected_base_image_registry: None,
    expected_workload_registry: None,
})
.await?;

let measurement_policy = client
    .resolve_base_image_measurement_policy("automata-linux:v0.2.7")
    .await?;

let workload_policy = client
    .resolve_workload_policy("storage-service:v0.1.0", selected_base_image_id)
    .await?;

let binding = client.trusted_session_binding();
# let _ = (measurement_policy, workload_policy, binding);
# Ok(())
# }
```

The selected base-image ID passed to `resolve_workload_policy` must come from
verified portal TLS identity. Do not take it from the evidence bundle.

## Verify a current session

After obtaining `VerifiedPortalTls`, call:

```rust,ignore
let result = client
    .verify_current_session(
        &verified_portal_tls,
        "203.0.113.10",
        2024,
        "storage-service:v0.1.0",
        None,
    )
    .await?;
```

This method resolves the `WorkloadSpec`, generates a fresh 32-byte challenge,
fetches `GET /session/evidence-bundle`, resolves the committed Azure MAA key
when required, constructs `SessionVerificationInputs`, and calls
`atakit_attestation::verify_session_bundle`.

Use `atakit_attestation::verify_session_bundle` directly when all typed inputs
are already available and no network access is required.
