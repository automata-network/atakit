# Verification test inputs

`automata-dcap/` contains unmodified public upstream quote samples. See its
README for the public source revision and license.

`supplied-session-bundle-gcp-snp.json` combines synthetic keys, test certificates
and fixed example policies with the public AMD report and vendor certificates
listed in `../../atakit-attestation/testdata/fedora-oci-gcp-n2d-standard-4/`.
Its session and publisher values are synthetic. The request-binding signature
is intentionally invalid to test rejection. No cloud account or instance
metadata is included.
