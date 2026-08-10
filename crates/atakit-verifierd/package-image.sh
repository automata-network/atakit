#!/bin/sh
set -eu

workspace_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output=${1:-"$workspace_root/target/atakit-verifierd.tar"}
target=x86_64-unknown-linux-gnu
binary="$workspace_root/target/$target/release/atakit-verifierd"
runtime_image=gcr.io/distroless/static-debian12@sha256:7a2bd171a18bdd39a4729600d0dca5f16e779d41156a6908b4f8a9a289e76d92
image_tag=localhost/atakit-verifierd:dev

for command in cargo rustc file readelf sha256sum podman tar; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required command is missing: $command" >&2
        exit 1
    }
done

cd "$workspace_root"

if [ -e "$output" ]; then
    echo "output already exists: $output" >&2
    exit 1
fi

echo "repository branch: $(git branch --show-current)"
echo "repository state:"
git status --short
echo "bundled input checksums:"
sha256sum Cargo.toml Cargo.lock crates/atakit-verifierd/Cargo.toml crates/atakit-verifierd/Containerfile
echo "build tool versions:"
cargo --version
rustc --version
echo "builder image: none; this build uses the host Rust toolchain"

runtime_user=$(podman image inspect "$runtime_image" --format '{{.Config.User}}' 2>/dev/null || true)
if [ "$runtime_user" != "65532" ]; then
    podman pull "$runtime_image" >/dev/null
    runtime_user=$(podman image inspect "$runtime_image" --format '{{.Config.User}}')
fi
runtime_platform=$(podman image inspect "$runtime_image" --format '{{.Os}}/{{.Architecture}}')
if [ "$runtime_platform" != "linux/amd64" ]; then
    echo "runtime image platform is $runtime_platform, expected linux/amd64" >&2
    exit 1
fi
if [ "$runtime_user" != "65532" ]; then
    echo "runtime image user is $runtime_user, expected 65532" >&2
    exit 1
fi
runtime_ssl_cert_file=$(podman image inspect "$runtime_image" --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^SSL_CERT_FILE=//p')
if [ "$runtime_ssl_cert_file" != "/etc/ssl/certs/ca-certificates.crt" ]; then
    echo "runtime image SSL_CERT_FILE is $runtime_ssl_cert_file, expected /etc/ssl/certs/ca-certificates.crt" >&2
    exit 1
fi
echo "runtime image: $runtime_image"
echo "runtime image platform: $runtime_platform"
echo "runtime image user: $runtime_user"
echo "runtime image SSL_CERT_FILE: $runtime_ssl_cert_file"

CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS='-C target-feature=+crt-static -C strip=symbols' \
    cargo build --release --target "$target" -p atakit-verifierd

file "$binary"
if readelf -l "$binary" | grep -q 'INTERP'; then
    echo "atakit-verifierd has a dynamic program interpreter" >&2
    exit 1
fi
if readelf -d "$binary" 2>/dev/null | grep -q 'NEEDED'; then
    echo "atakit-verifierd has a shared-library dependency" >&2
    exit 1
fi
sha256sum "$binary"

context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT HUP INT TERM
cp "$binary" "$context/atakit-verifierd"
cp crates/atakit-verifierd/Containerfile "$context/Containerfile"
podman build --pull=never --timestamp 0 --format oci --tag "$image_tag" "$context"
packaged_user=$(podman image inspect "$image_tag" --format '{{.Config.User}}')
if [ "$packaged_user" != "1000:1000" ]; then
    echo "packaged image user is $packaged_user, expected 1000:1000" >&2
    exit 1
fi
echo "packaged image user: $packaged_user"

mkdir -p "$(dirname -- "$output")"
oci_directory="$context/image"
podman save --format oci-dir --output "$oci_directory" "$image_tag"
tar --format=gnu --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -C "$oci_directory" -cf "$output" blobs index.json oci-layout
sha256sum "$output"
echo "wrote $output"
