# GCP SEV-SNP attestation fixture

These base64-encoded files make the `atakit-attestation` tests self-contained.
They are byte-for-byte copies of the public evidence bundle added by
`automata-network/automata-tee-workload-measurement` commit
`6805bc6f03ef96b83435fddba8d57167e0322af7` under
`evidence/fedora-oci-gcp-n2d-standard-4/`.

| Decoded file | SHA-256 |
|---|---|
| `report.bin` | `023584c715aa7c6050e292325d423518adaf64e0387a340031cb47d2e914dd96` |
| `ark.der` | `69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd` |
| `ask.der` | `67d303bd3905fd38db8b20e0793699870e7fa612eaad5dec358293fd8c0bac1b` |
| `vcek.der` | `89da33cab9d09cdee01ffb7ce7ad1d73d0564fd4f5c08ed42f25d210243ac104` |
