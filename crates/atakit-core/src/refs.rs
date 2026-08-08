//! Canonical reference and identifier forms.

/// Whether a string is a canonical 32-byte identifier: `0x` followed by 64
/// lowercase hexadecimal characters.
///
/// Base-image identifiers, workload identifiers, and publisher owner
/// fingerprints all share this shape, and several layers need to recognise it —
/// to key a store directory, to validate a manifest entry, to tell an
/// identifier from a name-and-version reference on a command line. One
/// implementation so those cannot drift apart.
///
/// Uppercase is rejected rather than accepted case-insensitively: the canonical
/// form is lowercase, and accepting both would make two spellings of one
/// identifier that compare unequal as strings.
pub fn is_canonical_id(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_canonical_form() {
        assert!(is_canonical_id(&format!("0x{}", "ab".repeat(32))));
        assert!(is_canonical_id(&format!("0x{}", "0".repeat(64))));
    }

    #[test]
    fn rejects_everything_else() {
        for bad in [
            "",
            "0x",
            "0xab",
            &"ab".repeat(32),                    // no prefix
            &format!("0x{}", "AB".repeat(32)),   // uppercase
            &format!("0x{}", "ab".repeat(31)),   // too short
            &format!("0x{}ab", "ab".repeat(32)), // too long
            &format!("0x{}zz", "ab".repeat(31)), // non-hexadecimal
            "name:version",
        ] {
            assert!(!is_canonical_id(bad), "must reject {bad:?}");
        }
    }
}

/// Whether a reference name is well formed: nonempty ASCII alphanumeric and
/// `-`, not starting with `-`.
///
/// This is the canonical grammar for the name half of a reference, shared by
/// every layer that validates one — the command line, the registry client, and
/// the manifest validator. Three copies of it would be three chances to
/// disagree about what a published name may contain.
pub fn is_valid_ref_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

/// Whether a reference version is well formed: `v` followed by at least one
/// ASCII alphanumeric, `.`, `-`, or `_`.
pub fn is_valid_ref_version(version: &str) -> bool {
    version.len() >= 2
        && version.starts_with('v')
        && version[1..].chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

#[cfg(test)]
mod grammar_tests {
    use super::*;

    #[test]
    fn names_accept_the_published_grammar() {
        for good in ["a", "fedora-oci", "storage-service", "app1"] {
            assert!(is_valid_ref_name(good), "must accept {good:?}");
        }
        for bad in [
            "",
            "-leading",
            "has_underscore",
            "has/slash",
            "has.dot",
            "UPPER OK?",
        ] {
            assert!(!is_valid_ref_name(bad), "must reject {bad:?}");
        }
    }

    #[test]
    fn versions_require_the_v_prefix() {
        for good in ["v1", "v0.0.16", "v0.2.8-debug", "v1_2"] {
            assert!(is_valid_ref_version(good), "must accept {good:?}");
        }
        for bad in ["", "v", "1.0", "x1", "v1/2", "v1 2"] {
            assert!(!is_valid_ref_version(bad), "must reject {bad:?}");
        }
    }
}
