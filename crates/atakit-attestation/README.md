# atakit-attestation

`atakit-attestation` verifies portal TLS evidence and current-session evidence
from explicit typed inputs. It performs no network access. The caller chooses
the measurement policy, workload policy, platform trust roots, Azure MAA keys,
global AMD SEV-SNP policies, expected chain binding, and current time.

## Verified TEE attribute policy

The verifier first checks the vendor-signed Intel TDX quote or AMD SEV-SNP
report. It then extracts the report-bound security state:

- Intel TDX: debug and the one-hot DCAP TCB status
- AMD SEV-SNP: debug, `POLICY.MIGRATE_MA`, four TCB values,
  `PLATFORM_INFO`, and exact family-model-stepping CPUID

The effective base-image attributes are the signed platform-profile
attributes with measurement-variant values replacing matching keys. The
verified state must match this effective declaration. A missing Boolean
declaration means `false`. A missing Intel TDX TCB mask means `ok` only. A
missing AMD SEV-SNP packed value means packed zero.

`verify_tls_attestation_with_workload_attributes` also applies the selected
format 6 manifest's `config.attributes`. `verify_tls_attestation` has no
selected workload map and therefore uses the same safe missing-requirement
defaults. Ordinary custom requirements keep their existing behavior.

For AMD SEV-SNP, `TrustAnchors.amd_snp_security_policies` must contain one
active policy for the exact signed CPUID. The effective minimum TCB is the
lane-by-lane maximum of the global, base-image, and workload minimums. The
effective `PLATFORM_INFO` policy combines their required-set and
required-clear masks and rejects conflicts.

The verifier still rejects report states that policy cannot authorize. These
include Intel TDX reserved attribute bits, missing `SEPT_VE_DISABLE`, nonzero
TDX 1.5 `MR_SERVICETD`, AMD SEV-SNP `VMPL`, any `REPORT_ID_MA` other than
the all-zero or all-`0xff` no-association sentinel, invalid
reserved fields, invalid TCB order, unsupported CPUID values, and invalid
cryptographic or collateral verification.

The canonical wire formats and policy rules live in:

- [`TLS attestation specification`](../../../docs/specs/tls-attestation-spec.md)
- [`session attestation specification`](../../../docs/specs/session-attestation-spec.md)
- [`AMD SEV-SNP security policy specification`](../../../docs/specs/amd-sev-snp-security-policy-spec.md)
