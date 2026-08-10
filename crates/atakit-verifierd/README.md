# atakit-verifierd

`atakit-verifierd` verifies the current atakit session at a request-selected
portal endpoint. The portal endpoint is routing input. Portal TLS attestation
and current-session evidence establish the verified identity. The daemon
serves `POST /v1/verify`, `GET /v1/health`, and `GET /v1/config` over HTTP.
The canonical API and configuration rules are in
`docs/specs/atakit-verifierd-spec.md` in the atakit suite repository.

## Package the container image

The package script builds a static x86-64 GNU/Linux binary and places it in a
pinned distroless runtime image:

```bash
./crates/atakit-verifierd/package-image.sh
```

The default output is `target/atakit-verifierd.tar`, in Open Container
Initiative archive format. Pass another output path as the first argument when
a workload project expects the archive elsewhere:

```bash
./crates/atakit-verifierd/package-image.sh /path/to/workload/images/atakit-verifierd.tar
```

The script refuses to overwrite an existing archive. It also refuses a binary
with a dynamic program interpreter or a shared library dependency. Before it
starts the build, it checks the pinned runtime image's platform, non-root user,
and certificate path. It writes normalized archive metadata so the same image
contents produce the same archive checksum.
