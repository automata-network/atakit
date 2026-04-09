//! Integration tests for the strict-vs-best-effort cardinality rule.
//!
//! With exactly one target in the fan-out (whether from `--repo` /
//! `--repository` or from a one-entry config), credential and probe
//! failures must be FATAL with the real cause -- never downgraded to
//! a warning that masks the real problem behind a misleading
//! "no images found" / "not found in any configured repository".
//!
//! These run the actual `atakit` binary as a subprocess so the full
//! command flow is exercised. The binary path comes from Cargo's
//! `CARGO_BIN_EXE_atakit` env var (set at test compile time).

use std::process::Command;

use tempfile::TempDir;

/// Build a temp config dir with the given config.toml contents and
/// matching empty data/cache dirs. Returns the dirs (kept alive by
/// the caller for the duration of the test) and the absolute path
/// strings.
fn temp_env(config_toml: &str) -> (TempDir, TempDir, TempDir, String, String, String) {
    let config_dir = TempDir::new().unwrap();
    let data_dir = TempDir::new().unwrap();
    let cache_dir = TempDir::new().unwrap();
    std::fs::write(config_dir.path().join("config.toml"), config_toml).unwrap();
    let config_path = config_dir.path().to_string_lossy().into_owned();
    let data_path = data_dir.path().to_string_lossy().into_owned();
    let cache_path = cache_dir.path().to_string_lossy().into_owned();
    (config_dir, data_dir, cache_dir, config_path, data_path, cache_path)
}

fn run_atakit(config_dir: &str, data_dir: &str, cache_dir: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_atakit"))
        .args(args)
        .env("ATAKIT_CONFIG_DIR", config_dir)
        .env("ATAKIT_DATA_DIR", data_dir)
        .env("ATAKIT_CACHE_DIR", cache_dir)
        // Wipe any inherited override that would change repository
        // resolution and confuse the test.
        .env_remove("ATAKIT_DEFAULT_REPO")
        .env_remove("ATAKIT_DEFAULT_PLATFORMS")
        .env_remove("ATAKIT_LIST_LIMIT")
        // Wipe any inherited token-source env var the test
        // happens to expect to be unset.
        .env_remove("ATAKIT_TEST_BROKEN_TOKEN")
        .output()
        .expect("failed to spawn atakit binary")
}

// ── image ls --remote ────────────────────────────────────────────

#[test]
fn image_ls_remote_with_one_broken_credential_repo_errors_strictly() {
    // One configured repo, credential references an unset env var.
    // With cardinality-based strictness, the credential failure
    // must be a hard error (non-zero exit) that surfaces the real
    // cause -- NOT "no images found" with the credential failure
    // hidden in a stderr warning that the user might miss.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { env = "ATAKIT_TEST_BROKEN_TOKEN" }

        [image.repositories]
        only = { repo = "myorg/private-only", credential = "broken" }
        "#,
    );

    let out = run_atakit(&cfg, &dat, &cache, &["image", "ls", "--remote"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "expected non-zero exit; got success.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("broken") || stdout.contains("broken"),
        "expected the credential name to surface in the error.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("ATAKIT_TEST_BROKEN_TOKEN")
            || stderr.contains("not set")
            || stdout.contains("ATAKIT_TEST_BROKEN_TOKEN"),
        "expected the underlying env-var error to surface.\nstderr: {stderr}"
    );
    // Critical: must NOT bottom out at the misleading "No images found"
    // success path, which is what the old behavior produced.
    assert!(
        !stdout.contains("No images found"),
        "broken credential leaked through to 'No images found' path.\nstdout: {stdout}"
    );
}

#[test]
fn image_ls_remote_with_one_repo_no_credential_succeeds_locally() {
    // Sanity check: a one-entry config WITHOUT a credential is
    // anonymous-public, and `image ls` (no --remote) is a local-only
    // command that must not touch the network or trigger any
    // credential resolution. This guards against the regression
    // where credential resolution moved out of the remote branch.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [image.repositories]
        only = { repo = "automata-network/automata-linux" }
        "#,
    );

    let out = run_atakit(&cfg, &dat, &cache, &["image", "ls"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "expected success on local-only ls.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // No credential should ever be resolved here.
    assert!(
        !stderr.contains("credential"),
        "local-only ls should not touch credentials.\nstderr: {stderr}"
    );
}

// ── workload pull ────────────────────────────────────────────────

#[test]
fn workload_pull_with_one_broken_credential_repo_errors_strictly() {
    // Mirror of the image-ls test for the workload-pull side. A
    // single configured workload repo with a broken credential
    // must produce a hard error naming the credential -- not the
    // generic "not found in any configured repository" message.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { env = "ATAKIT_TEST_BROKEN_TOKEN" }

        [image.repositories]
        x = { repo = "a/b" }

        [workload.repositories]
        only = { type = "github", repo = "myorg/private-workloads", credential = "broken" }
        "#,
    );

    let out = run_atakit(
        &cfg,
        &dat,
        &cache,
        &["workload", "pull", "doesnt-matter:v0.0.1"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "expected non-zero exit; got success.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("broken") || stderr.contains("ATAKIT_TEST_BROKEN_TOKEN"),
        "expected the credential name or env var name in stderr.\nstderr: {stderr}"
    );
    // Critical: must NOT bottom out at the misleading "not found in
    // any configured repository" path, which is what the old
    // best-effort downgrade produced.
    assert!(
        !stderr.contains("not found in any configured repository"),
        "broken credential leaked through to the generic not-found path.\nstderr: {stderr}"
    );
}

// ── workload ls --remote ─────────────────────────────────────────

#[test]
fn workload_ls_remote_with_one_broken_credential_repo_errors_strictly() {
    // Regression: `workload ls --remote` used to hard-code
    // best-effort credential resolution, so a one-entry config
    // with a broken credential printed warnings and "No workloads
    // found." with exit 0, matching neither image-ls nor
    // workload-pull behavior. The cardinality rule now applies
    // here too: exactly one target -> strict -> the credential
    // failure surfaces with a non-zero exit and the real cause.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { env = "ATAKIT_TEST_BROKEN_TOKEN" }

        [image.repositories]
        x = { repo = "a/b" }

        [workload.repositories]
        only = { type = "github", repo = "myorg/private-workloads", credential = "broken" }
        "#,
    );

    let out = run_atakit(&cfg, &dat, &cache, &["workload", "ls", "--remote"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "expected non-zero exit; got success.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("broken") || stderr.contains("ATAKIT_TEST_BROKEN_TOKEN"),
        "expected the credential name or env var name in stderr.\nstderr: {stderr}"
    );
    // Critical: must NOT bottom out at the misleading "No
    // workloads found." success path with exit 0.
    assert!(
        !stdout.contains("No workloads found"),
        "broken credential leaked through to 'No workloads found' path.\nstdout: {stdout}"
    );
}

#[test]
fn workload_ls_remote_with_pinned_broken_repository_errors_strictly() {
    // Same test but reaching "single target" via `--repository`
    // instead of a one-entry config. Both paths should produce
    // the same strict behavior now.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { env = "ATAKIT_TEST_BROKEN_TOKEN" }

        [image.repositories]
        x = { repo = "a/b" }

        [workload.repositories]
        public = { type = "http", url = "https://example.com" }
        private = { type = "github", repo = "myorg/private-workloads", credential = "broken" }
        "#,
    );

    let out = run_atakit(
        &cfg,
        &dat,
        &cache,
        &["workload", "ls", "--remote", "--repository", "private"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "expected non-zero exit; got success.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("broken") || stderr.contains("ATAKIT_TEST_BROKEN_TOKEN"),
        "expected the credential name or env var name in stderr.\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("No workloads found"),
        "broken credential leaked through to 'No workloads found' path.\nstdout: {stdout}"
    );
}
