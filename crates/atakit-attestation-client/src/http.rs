//! Bounded response reading for the endpoints this crate contacts.
//!
//! `atakit-cloud` keeps its own copy for the deployment endpoints it still
//! owns. The duplication is deliberate: sharing would mean either exporting a
//! response limiter from this crate for a crate that depends on it, or moving
//! `reqwest` and `futures-util` into `atakit-core`, which every crate in the
//! workspace depends on.

use futures_util::TryStreamExt;

pub(crate) async fn read_response_bytes_limited(
    response: reqwest::Response,
    maximum_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream
        .try_next()
        .await
        .map_err(|error| format!("read {label}: {error}"))?
    {
        append_response_chunk_limited(&mut body, &chunk, maximum_bytes, label)?;
    }
    Ok(body)
}

pub(crate) fn append_response_chunk_limited(
    body: &mut Vec<u8>,
    chunk: &[u8],
    maximum_bytes: usize,
    label: &str,
) -> Result<(), String> {
    let new_length = body
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| format!("{label} length overflow"))?;
    if new_length > maximum_bytes {
        return Err(format!("{label} exceeds the {maximum_bytes}-byte limit"));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_body_limit_rejects_the_first_excess_byte() {
        let mut body = Vec::new();
        append_response_chunk_limited(&mut body, b"1234", 4, "test response").unwrap();
        let error = append_response_chunk_limited(&mut body, b"5", 4, "test response").unwrap_err();
        assert_eq!(body, b"1234");
        assert!(error.contains("4-byte limit"), "{error}");
    }
}
