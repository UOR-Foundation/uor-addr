//! The C ABI honours the σ-axis it is asked for, and its default is BLAKE3.
//!
//! - **CL-C-FFI-05**: `uor_addr_<r>` (no selector) mints the default axis,
//!   `blake3:`; `uor_addr_<r>_with_hash(UOR_ADDR_HASH_SHA256, …)` mints
//!   `sha256:`, and each equals the in-crate entry point for that axis. A
//!   binding whose SHA-256 arm forwarded to the default would return a
//!   blake3 label for a sha256 request; this is the test that refuses it.

#![allow(non_snake_case)]

use core::ptr;

use uor_addr_c::*;

const KAPPA_BYTES: usize = 71;
const DOC: &[u8] = br#"{"axis":"selection"}"#;

fn with_hash(algo: u8) -> Vec<u8> {
    let mut buf = vec![0u8; UOR_ADDR_MAX_LABEL_BYTES];
    let mut written = 0usize;
    let rc = unsafe {
        uor_addr_json_with_hash(
            algo,
            DOC.as_ptr(),
            DOC.len(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut written,
        )
    };
    assert_eq!(rc, UOR_ADDR_OK);
    buf.truncate(written);
    buf
}

#[test]
fn cl_c_ffi_05__default_is_blake3_and_sha256_is_honoured() {
    let mut default = [0u8; KAPPA_BYTES];
    let rc = unsafe {
        uor_addr_json(
            DOC.as_ptr(),
            DOC.len(),
            default.as_mut_ptr(),
            default.len(),
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, UOR_ADDR_OK);
    assert!(
        default.starts_with(b"blake3:"),
        "the default axis is blake3"
    );
    assert_eq!(
        &default[..],
        uor_addr::json::address(DOC)
            .unwrap()
            .address
            .as_str()
            .as_bytes()
    );

    let blake3 = with_hash(UOR_ADDR_HASH_BLAKE3);
    assert_eq!(blake3, default, "an explicit blake3 request is the default");

    let sha256 = with_hash(UOR_ADDR_HASH_SHA256);
    assert!(
        sha256.starts_with(b"sha256:"),
        "a sha256 request must mint sha256, not the default"
    );
    assert_eq!(
        sha256,
        uor_addr::json::address_sha256(DOC)
            .unwrap()
            .address
            .as_str()
            .as_bytes()
    );
}
