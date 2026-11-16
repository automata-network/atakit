# Trust Chain Specification (Retired Surface)

The cryptographic trust chain remains:

```text
TEE hardware -> attestation key -> transient TPM signing key -> session key
```

Its current wire format, startup ordering, lifecycle behavior, and offline
verification rules are normative in
[session-attestation-spec.md](session-attestation-spec.md). The on-chain side is
specified in [cvm-registry/](cvm-registry/README.md).

The former `GET /trust-chain`, `GET /chain-submission`,
`POST /chain-submission`, and `POST /chain-submission/submitted` endpoints are
removed. Servers return an ordinary
`404`; there are no aliases, redirects, `405`, or `410` migration responses.
Consumers obtain immutable current-session material from
`GET /session/evidence-bundle?challenge=...`. Prepared transaction calldata is
internal to atakit-portal.

Every session candidate owns a fresh in-memory ES256K application key and a
fresh transient TPM signing key. Neither private key nor a reloadable
TPM-wrapped key is persisted. A candidate becomes visible only after complete
evidence construction and an application-level successful supervisor commit;
abort and replacement flush the TPM handle and zeroize the application secret.

TLS bootstrap attestation is a distinct pre-init protocol and remains
specified in [tls-attestation-spec.md](tls-attestation-spec.md).
