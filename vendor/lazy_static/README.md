# Patched lazy_static 1.5.0

This is the source of `lazy_static` 1.5.0, used under its MIT/Apache-2.0
license, with the optional `spin` dependency updated from the yanked 0.9.8
release to 0.12.2. The `spin_no_std` return lifetime is also written explicitly
to satisfy the current Rust compiler's `mismatched_lifetime_syntaxes` lint; it
does not change the signature's meaning.

The upstream crate and its current `master` branch still require
`spin = "0.9.8"`. `num-bigint-dig` enables `lazy_static/spin_no_std` through
RSA 0.9, so a lockfile-only update cannot select a newer `spin` release.

When upstream publishes a compatible fix, remove this directory and the
workspace `[patch.crates-io]` entry, then update the lockfile normally.

Upstream: <https://github.com/rust-lang-nursery/lazy-static.rs>
