# Atakit CLI v0.7.8

Atakit creates, deploys, and manages workloads on confidential virtual machines.
This release targets Automata Linux v0.3.8 and v0.3.8-debug with workload
manifest format 16.

## Features

- Build and inspect workload archives.
- Manage base images and workload publication.
- Deploy and manage workloads on AWS, Azure, and Google Cloud.
- Verify attestation evidence and session identity.
- Configure supported workload disks and runtime settings.
- Stream unmeasured data during initialization and owner-authorized updates.

## Installation

Choose the binary for your operating system from this release:

- `atakit-v0.7.8-linux-amd64`
- `atakit-v0.7.8-macos-arm64`

Verify the binary against its matching `.sha256` file before installation.
After installation, `atakit --version` must print `atakit 0.7.8`.
Use `atakit --help` to list commands.

## Compatibility

Automata Linux v0.3.8 and v0.3.8-debug require workload manifest format 16.
Cloud machine types and disk options must be supported by the selected image
and cloud provider. Operators supply their own cloud credentials and keys.
