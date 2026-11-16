# Security notice: workload startup is not verification

**A successfully started workload MUST NOT be considered verified solely
because startup succeeded. Before provisioning any secret, the provisioner
MUST verify the claimed workload and its measurements against an independently
trusted measurement policy.**

The provisioner is the person or service that releases a secret, such as a
disk passphrase, decryption key, API credential, or private application data.
The provisioner owns the decision to trust the recipient.

## Startup status does not authorize secret release

A successful deployment, Portal's `Running` state, an application health
response, or Portal's report that its startup checks passed is not sufficient
evidence for secret release. A claimed workload ID, PCR value, session ID, or
registration transaction is also insufficient by itself.

Portal's local checks help enforce startup policy. They do not replace the
provisioner's verification. This remains true if Portal also performs local
hardware verification. A system cannot establish its trustworthiness merely
by reporting that it verified itself.

## Use a trusted source of expected measurements

The provisioner MUST select the expected workload identity, accepted base-image
policy, and measurement authority independently of the recipient's claims.
It MUST NOT accept measurements supplied by the workload, Portal, deployment
operator, or an arbitrary RPC endpoint solely because they were supplied.

Accepted policy sources can include:

- Publisher-signed policies or measurement packs, after verifying the
  signatures and binding the publisher keys and policy contents to the
  workload and base-image identities the provisioner accepts. The workload
  and base-image publishers may be different entities.
- A chain and registry selected by the provisioner, using a chain-access
  method the provisioner trusts. A contract address alone does not
  authenticate an RPC response.
- Expected measurements explicitly approved and pinned by the provisioner.

The transport need not be trusted when the provisioner independently
authenticates the policy. For example, Portal may deliver a publisher-signed
policy, but the provisioner must verify it rather than trust Portal's verdict.
A valid publisher signature proves approval of those policy bytes; it does
not by itself prove freshness, current registration, or non-revocation.
The provisioner must enforce any such requirements in its own policy.

Hardware certificate roots and other attestation trust inputs must also come
from sources accepted by the provisioner. Matching expected PCR values alone
does not authenticate a TPM or establish hardware security.

## Required checks before provisioning

Before releasing a secret, the provisioner MUST:

1. Select the intended workload and accepted base-image policies from trusted
   sources, and authenticate those policies.
2. Verify attestation evidence, including hardware signatures, certificate
   chains, the TPM-to-hardware binding, and required hardware security settings.
3. Verify that the authenticated measurements satisfy the selected base-image
   and workload policies, including the workload's manifest binding in PCR23.
   Pre-initialization verification of the base image alone does not verify the
   subsequently installed workload.
4. Check freshness using its own challenge and the protocol's evidence and
   session validity rules. Reject replayed or expired evidence as required by
   its policy.
5. Bind the verified identity and evidence to the exact recipient key or
   authenticated channel used to deliver the secret. Do not verify one VM and
   send the secret to another endpoint or an unbound application port.
6. Withhold the secret if any required check fails, is unavailable, or cannot
   be established. Startup success must never override a verification failure.

A provisioner may use a verification service it explicitly trusts, provided
the authenticated result covers the same policy, freshness and recipient
binding. A recipient's self-reported verification result is not such a service.

These requirements apply on first provisioning and whenever a new boot,
session, recipient key, or policy falls outside the scope of an earlier
verification. Do not put secrets into workload archives or startup
configuration before the required recipient verification has completed.

## Disk-unlock implications

For passphrase delivery, verify the current recipient and workload before
sending the passphrase. A LUKS passphrase keyslot allows its holder to unlock
independently of TPM measurements; it is not an additional TPM requirement.

Local TPM unsealing is a separate mechanism: it uses the original TPM's secret
key material and sealed PCR policy. A successful unseal is not a general
attestation result authorizing a remote provisioner to release more secrets.

## Related specifications

- [TLS attestation and recipient-channel binding](tls-attestation-spec.md)
- [Session attestation](session-attestation-spec.md)
- [Workload disk unlock](disk-unlock-spec.md)
- [Trust-pack sources and authorities](atatp-archive-spec.md)
- [Attestation guarantees and limits](threat-model.md#7-meaning-of-attestation)
