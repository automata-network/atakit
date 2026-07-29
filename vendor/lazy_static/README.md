# Patched lazy_static 1.5.0

This is the source of `lazy_static` 1.5.0, used under its MIT/Apache-2.0
license, with the optional `spin` dependency updated from the yanked 0.9.8
release to 0.12.2. The standard and `spin_no_std` return lifetimes are also
written explicitly to satisfy the current Rust compiler's
`mismatched_lifetime_syntaxes` lint; they do not change the signatures'
meaning.

The upstream crate and its current `master` branch still require
`spin = "0.9.8"`. The current atakit dependency graph does not enable
`lazy_static/spin_no_std`; the vendored copy remains to keep the standard
backend free of the current Rust compiler's `mismatched_lifetime_syntaxes`
warning and to avoid restoring the withdrawn optional dependency.

When upstream publishes a compatible fix, remove this directory and the
workspace `[patch.crates-io]` entry, then update the lockfile normally.

Upstream: <https://github.com/rust-lang-nursery/lazy-static.rs>
