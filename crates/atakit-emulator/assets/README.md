The two runtime artifacts are compiled from the companion contract repository's
`test/mocks/EmulatorDcapAttestation.sol` and `EmulatorTpmAttestation.sol`. They patch
hardware verification backends only. Base contract revision: 0e0991b656fd7568ebfff9a9cf3554899695073a.
See `../scripts/refresh-mocks.py` to regenerate and record hashes.

`gcp-ak-certs.json` and `gcp-ak-pub.hex` contain public certificate/public-key fixture
data from `atakit-dev/crates/automata-cvm-agent/src/mock/mock_device_data.json`.
They contain no private AK key. Software session and TPM delegation keys are
generated independently at runtime. The Portal ABI helpers are pinned in Cargo.toml
to atakit-portal revision 079cb59c3434926890f0017a19b9684f86dddfb5.
