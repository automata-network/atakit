//! Shared path rules for baby storage validation and runtime mounts.
use std::path::{Path, PathBuf};

fn path_key(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Inputs must have passed manifest path and scope validation.
pub fn scoped_path(
    base: &Path,
    scope: &str,
    slot: &str,
    image: &str,
    instance: &str,
) -> Result<PathBuf, &'static str> {
    match scope {
        "slot" => Ok(base.join(path_key(slot))),
        "image" => Ok(base.join(path_key(image))),
        "instance" => Ok(base.join(path_key(instance))),
        scope if scope.starts_with("key:") => Ok(base.join("key").join(&scope[4..])),
        _ => Err("unsupported storage scope"),
    }
}

/// Check overlap before the image and instance are selected. Dynamic scopes
/// conservatively cover all possible children of the declared base directory.
pub fn may_overlap_parent(parent: &Path, base: &Path, scope: &str, slot: &str) -> bool {
    let baby = match scope {
        "image" | "instance" => base.to_path_buf(),
        _ => match scoped_path(base, scope, slot, "", "") {
            Ok(path) => path,
            Err(_) => return true,
        },
    };
    parent.starts_with(&baby) || baby.starts_with(parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_paths_and_parent_overlap() {
        let base = Path::new("/data");
        assert_eq!(
            scoped_path(base, "slot", "tools", "", "").unwrap(),
            Path::new("/data/tools")
        );
        assert_eq!(
            scoped_path(base, "image", "", "sha256:abc", "").unwrap(),
            Path::new("/data/sha256_abc")
        );
        assert_eq!(
            scoped_path(base, "instance", "", "", "job.1").unwrap(),
            Path::new("/data/job_1")
        );
        assert_eq!(
            scoped_path(base, "key:shared", "", "", "").unwrap(),
            Path::new("/data/key/shared")
        );
        assert!(scoped_path(base, "unknown", "", "", "").is_err());
        for (scope, actual) in [("slot", "/data/tools"), ("key:shared", "/data/key/shared")] {
            for parent in ["/", "/data", actual, &format!("{actual}/child")] {
                assert!(may_overlap_parent(Path::new(parent), base, scope, "tools"));
            }
            for parent in ["/data/parent", "/database", "/elsewhere"] {
                assert!(!may_overlap_parent(Path::new(parent), base, scope, "tools"));
            }
        }
        for scope in ["image", "instance"] {
            assert!(may_overlap_parent(
                Path::new("/data/parent"),
                base,
                scope,
                "tools"
            ));
            assert!(!may_overlap_parent(
                Path::new("/elsewhere"),
                base,
                scope,
                "tools"
            ));
        }
    }
}
