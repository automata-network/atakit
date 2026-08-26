# atakit-attestation-client

`atakit-attestation-client` implements the complete atakit attestation
verification workflow. The caller selects an RPC endpoint and a
`SessionRegistry` address. Portal evidence cannot select or replace either
value.

The client:

- collects and verifies portal TLS attestation, returning a pinned client;
- loads verifier-supplied trust inputs from certificate, revocation-list, and
  policy files;
- resolves Intel TDX DCAP collateral and AMD SEV-SNP collateral for the
  presented evidence;
- states which trust inputs each `(cloud, tee)` pair requires;
- checks the RPC-reported chain ID;
- derives `BaseImageRegistry`, `WorkloadRegistry`, and
  `TeeSecurityPolicyVerifier` from `SessionRegistry`, then derives
  `AmdSnpSecurityPolicyRegistry` from `TeeSecurityPolicyVerifier`;
- checks optional expected registry addresses;
- loads the registered base-image measurement policy;
- loads and validates the registered `WorkloadSpec`;
- checks GCP vTPM AK and AMD ARK roots against the verifier contracts;
- resolves the active AMD SEV-SNP registry default for the exact CPUID
  in a verified report;
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

For AMD SEV-SNP, call `resolve_amd_snp_security_policy` with the exact
family-model-stepping value extracted from the signed report. The result is an
input to `atakit-attestation`; it is not selected by portal evidence. A missing
or inactive exact-CPUID record fails verification.

The base-image measurement policy preserves custom attributes and all six
reserved TEE attributes from both `PlatformProfile.attributes` and
`MeasurementVariant.attributes`. When the selected variant and profile contain
the same key, the variant value is effective. Missing reserved values use the
same safe defaults as on-chain registration: `false` for Boolean states and
`ok` only for Intel TDX TCB status. A missing AMD SEV-SNP packed value resolves
to the active exact-CPUID registry default. An explicit value replaces the
default on its policy side; the registry value is not an independent mandatory
floor.

## Verify a current session

`verified_portal_tls` fixes the trust authority before the portal is contacted.
The current-session workflow uses the workload policy and trust inputs from
that same authority. Session binding is separate. Chain authority also supplies
verifier-selected chain coordinates for checking a chain-bound session, while
a local-bound session does not use those coordinates. The caller may use
`required_binding` to add an independent local-versus-chain policy. The current
trust-pack and explicit inputs contain no trusted chain coordinates, so a
chain-bound session fails closed under those authorities.

References are publisher-qualified: `<publisher>/<name>:<version>`, where the
publisher is the owner fingerprint as `0x` and 64 lowercase hexadecimal
characters. A two-part `name:version` reference is rejected.

```rust,ignore
let result = client
    .verify_current_session(
        &verified_portal_tls,
        "203.0.113.10",
        2024,
        "0x9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f/storage-service:v0.1.0",
        None,
    )
    .await?;
```

This method resolves the `WorkloadSpec`, generates a fresh 32-byte challenge,
fetches `GET /session/evidence-bundle`, resolves the committed Azure MAA key
when required, constructs `SessionVerificationInputs`, and calls
`atakit_attestation::verify_session_bundle` on a blocking worker. The success
response from `GET /session/evidence-bundle` is limited to 8 MiB. An error
response is limited to 64 KiB.

The complete portal TLS plus current-session workflow is
`atakit_attestation_client::workflow::verify_portal_session`. Services that
must retain their own resource permit after an HTTP timeout can use the exposed
preparation phases. After `prepare_portal_session_tls_verification`, move the
prepared portal TLS verification and the permit into a blocking worker. Then
call `VerifiedPortalSessionTls::fetch_session`, move the fetched response and
the permit into a blocking worker for
`FetchedPortalSessionVerification::parse`, call
`ParsedPortalSessionVerification::prepare`, and finally move the prepared
session verification and permit into its blocking worker.

When the caller already holds the exact response from
`GET /session/evidence-bundle`, use
`atakit_attestation_client::verify_supplied_session_bundle`. This workflow
resolves policy and collateral from one `SessionVerificationMode`, verifies the
caller-supplied 32-byte challenge, applies the request's optional
`required_binding` policy after normal binding verification, and makes no
portal network request. `required_binding = None` accepts either valid binding
mode and does not skip cryptographic binding checks. It runs
the final synchronous cryptographic verification on a blocking worker. Services
that must retain their own resource permit after an HTTP timeout can call
`prepare_supplied_session_bundle`, then move both the prepared verification and
that permit into their bounded blocking worker.

Use `atakit_attestation::verify_session_bundle` directly when all typed inputs
are already available and no network access is required.

## Boundary decision, 2026-08-08

Portal TLS collection lives in this crate. This reverses the boundary set on
2026-08-03 in `atakit-ng` pull request 58 (merge
`0dafb670dbca18920b1e143ca7a2d2d87c0a0a0c`, topic
`e68c0245cba0d3c418d3be38d7dd4b20780b2abd`), which stated that
`atakit_cloud::session::verify_portal_session` owned the complete order and
that platform-specific portal TLS collection remained outside this crate.

This is a recorded change of mind, not the old rule failing to apply. The
operator authored both the topic commit and the merge, and directed the
reversal five days later.

The reason: a consumer that wants the complete verification workflow needed
exactly one function from `atakit-cloud` and received `aws/`, `azure/`, `gcp/`,
`qemu/`, disk-image handling, and their dependencies with it. The platform
branching involved is not cloud deployment code — it reads
`response.platform.cloud` and `response.platform.tee` to decide which
collateral a given piece of evidence requires, and uses no cloud provider SDK,
no credentials, and no deployment module.

`atakit-cloud` keeps deployment — the `POST /init` upload and portal lifecycle
waiting — and re-exports every moved name, so `atakit cloud verify-session`,
`atakit cloud deploy`, and `atakit cloud session status` are unchanged.
`atakit-attestation` remains free of network access.
