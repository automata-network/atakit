# atakit-verifierd

`atakit-verifierd` verifies the current atakit session at a request-selected
portal endpoint, or verifies a challenge-bound session evidence bundle received
through a caller-owned transport. The portal endpoint is routing input for
`POST /v1/verify`. Portal TLS attestation and current-session evidence establish
that path's verified identity. `POST /v1/verify-session-bundle` makes no peer
connection and verifies the supplied bundle against the caller's exact 32-byte
challenge. The daemon also serves `GET /v1/health` and `GET /v1/config` over
HTTP.
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
and certificate path. The packaged process runs as UID and GID 1000, which fit
inside atakit-portal's 2,000-ID mapping for each workload service. Its working
directory is `/`, rather than the pinned distroless image's `/home/nonroot`,
which UID 1000 cannot enter. The script checks both final image settings before
it writes normalized archive metadata so the same image contents produce the
same archive checksum.
