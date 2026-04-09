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

// ── multi-repo best-effort path ──────────────────────────────────

#[test]
fn image_ls_remote_with_two_repos_and_one_broken_credential_warns_and_continues() {
    // Exercise the best-effort path: more than one configured
    // target, one with a broken credential. The credential failure
    // must be a per-credential warning + per-repo skip, not a hard
    // error. The working repo should still be queried. We can't
    // assert network success without live GitHub, so the passing
    // signal is: (a) the credential-failure warning fires, (b) the
    // skip-repo warning names the broken entry, and (c) the
    // command makes it past credential resolution without exiting
    // non-zero on the credential issue alone.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { env = "ATAKIT_TEST_BROKEN_TOKEN" }

        [image.repositories]
        ok     = { repo = "automata-network/automata-linux" }
        broken = { repo = "myorg/private-images", credential = "broken" }
        "#,
    );

    let out = run_atakit(&cfg, &dat, &cache, &["image", "ls", "--remote"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("credential 'broken' failed") || stderr.contains("broken"),
        "expected per-credential warning naming the broken credential.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("skipping") && stderr.contains("broken"),
        "expected per-repo skip warning naming the broken entry.\nstderr: {stderr}"
    );
}

#[test]
fn workload_ls_remote_with_two_repos_and_one_broken_credential_warns_and_continues() {
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { env = "ATAKIT_TEST_BROKEN_TOKEN" }

        [image.repositories]
        x = { repo = "a/b" }

        [workload.repositories]
        http-ok = { type = "http",   url  = "https://definitely-not-a-real-registry.invalid" }
        broken  = { type = "github", repo = "myorg/private-workloads", credential = "broken" }
        "#,
    );

    let out = run_atakit(&cfg, &dat, &cache, &["workload", "ls", "--remote"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("credential 'broken' failed") || stderr.contains("broken"),
        "expected per-credential warning naming the broken credential.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("skipping") && stderr.contains("broken"),
        "expected per-repo skip warning naming the broken entry.\nstderr: {stderr}"
    );
    // The http-ok entry SHOULD also fail (no such host) -- that's
    // an API error, and the docs promise it's warn-and-continue in
    // multi-target mode. Make sure at least one "warning:" line
    // mentioning "http-ok" appears.
    assert!(
        stderr.contains("http-ok"),
        "expected a per-repo warning for the unreachable http-ok entry.\nstderr: {stderr}"
    );
}

// ── --tag mode with broken credential ─────────────────────────────

#[test]
fn image_ls_tag_routes_to_matching_configured_entry() {
    // Regression: `--tag debug-linux:v0.5` used to query the
    // first-declared repository regardless of what the tag's
    // `repository` component said. With two configured entries
    // and a broken credential on the SECOND entry, the old code
    // would hit the FIRST entry for the network call (and then
    // fail on the fake token). After the fix, `--tag` looks up
    // the entry by the ref's repository component, so pointing
    // at "debug-linux" must route to the second entry and
    // surface its broken credential.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { env = "ATAKIT_TEST_BROKEN_TOKEN" }

        [image.repositories]
        automata = { repo = "automata-network/automata-linux" }
        debug    = { repo = "owner/debug-linux", credential = "broken" }
        "#,
    );

    let out = run_atakit(
        &cfg,
        &dat,
        &cache,
        &["image", "ls", "--tag", "debug-linux:v0.5"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !out.status.success(),
        "expected non-zero exit; got success.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // Must reach the `debug` entry and surface its broken
    // credential, not silently query `automata` instead.
    assert!(
        stderr.contains("broken") || stderr.contains("ATAKIT_TEST_BROKEN_TOKEN"),
        "expected the `debug` entry's credential failure to surface.\nstderr: {stderr}"
    );
}

#[test]
fn image_ls_tag_errors_on_unknown_repository() {
    // --tag with a local name that doesn't match any configured
    // entry should produce a helpful error listing the configured
    // entries, not silently query the first one.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [image.repositories]
        automata = { repo = "automata-network/automata-linux" }
        "#,
    );

    let out = run_atakit(
        &cfg,
        &dat,
        &cache,
        &["image", "ls", "--tag", "nonexistent:v0.5"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success());
    assert!(
        stderr.contains("no configured repository matches")
            && stderr.contains("nonexistent"),
        "expected helpful unknown-repo error.\nstderr: {stderr}"
    );
}

#[test]
fn image_ls_tag_with_broken_credential_errors_strictly() {
    // --tag mode targets exactly one repository and makes a direct
    // GitHub API call to fetch that release. A broken credential
    // on the chosen entry must be fatal with the real cause, not
    // silently skipped.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { env = "ATAKIT_TEST_BROKEN_TOKEN" }

        [image.repositories]
        private = { repo = "myorg/private-images", credential = "broken" }
        "#,
    );

    let out = run_atakit(
        &cfg,
        &dat,
        &cache,
        &["image", "ls", "--tag", "private-images:v0.0.1"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !out.status.success(),
        "expected non-zero exit; got success.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("broken") || stderr.contains("ATAKIT_TEST_BROKEN_TOKEN"),
        "expected the credential name or env var name in the error.\nstderr: {stderr}"
    );
}

// ── file / command credential sources in cardinality context ──────

#[test]
fn image_ls_remote_with_missing_file_credential_errors_strictly() {
    // Exercises the `file` credential source in the cardinality
    // path. The previous cardinality tests all used `env`
    // credentials; this one points at a chmod 600 file that
    // doesn't exist and asserts the full io error cause chain
    // reaches the user.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { file = "/nonexistent/atakit-test/credential-file" }

        [image.repositories]
        private = { repo = "myorg/private-images", credential = "broken" }
        "#,
    );

    let out = run_atakit(&cfg, &dat, &cache, &["image", "ls", "--remote"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success());
    assert!(
        stderr.contains("broken")
            && (stderr.contains("No such file") || stderr.contains("cannot find")),
        "expected file source error with underlying io cause.\nstderr: {stderr}"
    );
}

#[test]
fn image_ls_remote_with_failing_command_credential_errors_strictly() {
    // Exercises the `command` credential source in the cardinality
    // path. The helper exits 1 with stderr output; the poll-loop
    // runner must surface the exit status and stderr snippet
    // through the strict single-target error, not panic or hang.
    let (_c, _d, _ca, cfg, dat, cache) = temp_env(
        r#"
        [github.credentials]
        broken = { command = ["sh", "-c", "echo 'nope: no such entry' >&2; exit 7"] }

        [image.repositories]
        private = { repo = "myorg/private-images", credential = "broken" }
        "#,
    );

    let out = run_atakit(&cfg, &dat, &cache, &["image", "ls", "--remote"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success());
    assert!(
        stderr.contains("broken") && stderr.contains("exited with status"),
        "expected command-source error naming the credential and exit status.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("7") || stderr.contains("nope"),
        "expected the exit code 7 or the stderr snippet in the error.\nstderr: {stderr}"
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
