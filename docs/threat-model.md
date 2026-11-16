# Attestation guarantees and limits

## 7. Meaning of attestation

### 7.1 Evidence and its limits

Attestation provides evidence of platform identity and the workload identity
and policy bound by that platform's verified execution path. The verifier
must also check freshness, session binding, and the relevant trust policy.

It does not prove that arbitrary workload code is benign or that dynamic baby
contents never change. Baby images are not automatically part of the current
workload's PCR23 measurement. PCR23 is the measurement register used to bind
the workload manifest in the existing design.

If a baby permits runtime software changes, its original image ID identifies
the starting image, not the complete current filesystem. Any stronger claim
about current contents needs separate evidence defined by the contract.

Neither an application signature nor an undisclosed launch history should be
presented as proof of complete runtime behavior.

### 7.2 A weaker platform cannot satisfy stronger requirements

A platform is weaker for a particular verification policy if it lacks any
guarantee that policy requires. Strength is assessed against those individual
requirements, not a platform name or a single ranking. A debug console,
administrative access, disabled isolation checks, or a boot configuration that
allows unapproved code can each invalidate a required guarantee.

Verification must enforce all of the following:

- Check authenticated evidence for the platform code and effective security
  configuration, including relevant boot settings, debug access, enforcement
  policy, and required hardware and firmware security properties. These may
  be established by measurements mapped to independently reviewed properties
  or by authenticated attestation fields. A self-reported label is insufficient.
- Distinguish every security-relevant difference needed by the accepted
  policy. If strong and weak configurations produce indistinguishable accepted
  evidence, that evidence cannot establish the stronger guarantee. Reject it
  when the stronger guarantee is required.
- Apply the relying party's independently selected policy, including accepted
  measurements, trust anchors, minimum security versions, and revocations where
  required. A valid signature or registry entry proves neither that all these
  requirements hold nor that a debug platform is sealed.
- Bind the accepted platform, workload, policy, session, and recipient or
  signing key together. A weaker platform cannot borrow a stronger platform's
  report, relay its verification result, or reuse its identity keys to pass off
  execution on the weaker platform as execution on the stronger platform.
  Caller-supplied report data alone cannot establish that execution binding.
- Reject missing, unknown, contradictory, or unsupported evidence for a
  required property. Verification errors must not trigger acceptance under a
  weaker policy. Cached results must retain their policy, identity, freshness,
  and session limits.

These rules apply wherever platform trust is consumed: direct verification,
on-chain verification, proofs derived from attestation, session acceptance,
secret release, and recovery of protected state. Each path must preserve the
required checks and bindings. Protecting an initial launch is insufficient if
a later path accepts weaker evidence or releases protected keys to a weaker
platform.

A debug platform may be identified and accepted for a separate testing purpose.
That acceptance must explicitly describe its weaker guarantees. It cannot
satisfy a sealed-platform requirement or claim conformance with this model
while granting either party platform administration. Renaming the image,
sharing a signing authority, or obtaining both parties' consent cannot change
that result.
