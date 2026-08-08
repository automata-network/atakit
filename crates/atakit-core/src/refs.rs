//! Path encoding for canonical reference components.

/// Encode one canonical reference component as a collision-free path segment.
///
/// The fixed prefix prevents empty values, `.` and `..` from becoming special
/// filesystem paths. Bytes outside the readable safe set use `~HH` hex escapes;
/// `~` itself is always escaped, so the mapping is reversible and collision-free.
///
/// The encoding is reference-neutral: base-image and workload references share
/// one component grammar, so both use this function rather than each carrying a
/// separate encoder that could drift.
pub fn encode_ref_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut output = String::with_capacity(value.len() + 4);
    output.push_str("ref~");
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            output.push(char::from(byte));
        } else {
            output.push('~');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_path_segments_are_safe_and_collision_free() {
        assert_eq!(encode_ref_path_segment("foo_bar"), "ref~foo_bar");
        assert_eq!(encode_ref_path_segment("foo@bar"), "ref~foo~40bar");
        assert_ne!(
            encode_ref_path_segment("foo@bar"),
            encode_ref_path_segment("foo_bar")
        );
        assert_eq!(encode_ref_path_segment(""), "ref~");
        assert_eq!(encode_ref_path_segment(".."), "ref~..");
        assert_eq!(encode_ref_path_segment("a/b"), "ref~a~2Fb");
    }
}
