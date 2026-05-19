//! **`uor-addr-c` — C ABI bindings for `uor-addr`**.
//!
//! Exposes each UOR-ADDR realization through a stable `extern "C"`
//! entry point. The crate is `no_std` and `no_alloc` (mirrors
//! `uor-addr`'s defaults); the staticlib / cdylib outputs are
//! consumable from embedded C/C++ toolchains plus any language with
//! a C FFI (Python `cffi`, Go `cgo`, Ruby `FFI`, .NET P/Invoke).
//!
//! # API shape
//!
//! Every realization exposes one entry point of the form
//!
//! ```c
//! int32_t uor_addr_<realization>(
//!     const uint8_t *input,
//!     size_t input_len,
//!     uint8_t *out_label,
//!     size_t out_label_len,
//!     size_t *out_written);
//! ```
//!
//! - `input` / `input_len` — caller-owned input byte sequence.
//! - `out_label` / `out_label_len` — caller-owned output buffer; must
//!   be at least [`UOR_ADDR_LABEL_BYTES`] = 71 bytes.
//! - `out_written` — written with the number of bytes the function
//!   emitted (always 71 on success). May be `NULL` (the count is
//!   then discarded; the buffer is still filled).
//!
//! Return value is one of:
//!
//! - `UOR_ADDR_OK` (`0`) — success.
//! - `UOR_ADDR_ERR_NULL_POINTER` (`-1`) — invalid pointer.
//! - `UOR_ADDR_ERR_BUFFER_TOO_SMALL` (`-2`) — output buffer too small.
//! - `UOR_ADDR_ERR_INVALID_INPUT` (`-3`) — input rejected by parser.
//! - `UOR_ADDR_ERR_TOO_LARGE` (`-4`) — input exceeded a bound.
//! - `UOR_ADDR_ERR_PIPELINE` (`-5`) — substrate-level failure.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::slice;

use uor_addr::{
    asn1, codemodule, json, ring, schema, sexp, xml, AddressOutcome, ADDRESS_LABEL_BYTES,
};

/// Wire-format κ-label byte width — `len("sha256:") + 64`.
#[no_mangle]
pub static UOR_ADDR_LABEL_BYTES: usize = ADDRESS_LABEL_BYTES;

/// Success.
pub const UOR_ADDR_OK: i32 = 0;
/// `input == NULL && input_len > 0`, or `out_label == NULL`.
pub const UOR_ADDR_ERR_NULL_POINTER: i32 = -1;
/// `out_label_len < UOR_ADDR_LABEL_BYTES`.
pub const UOR_ADDR_ERR_BUFFER_TOO_SMALL: i32 = -2;
/// Input failed the realization's host-boundary parser.
pub const UOR_ADDR_ERR_INVALID_INPUT: i32 = -3;
/// Input exceeded a typed-input ceiling.
pub const UOR_ADDR_ERR_TOO_LARGE: i32 = -4;
/// Defensive — substrate-level pipeline failure.
pub const UOR_ADDR_ERR_PIPELINE: i32 = -5;

/// Marshal a successful `AddressOutcome` into the caller's output
/// buffer. Returns the appropriate error code on buffer overflow / null
/// pointer.
///
/// # Safety
///
/// `out_label` must be writable for at least `out_label_len` bytes;
/// `out_written` if non-null must point to a writable `usize`.
unsafe fn write_outcome(
    outcome: AddressOutcome,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    if out_label.is_null() {
        return UOR_ADDR_ERR_NULL_POINTER;
    }
    if out_label_len < ADDRESS_LABEL_BYTES {
        return UOR_ADDR_ERR_BUFFER_TOO_SMALL;
    }
    let bytes = outcome.address.as_bytes();
    debug_assert_eq!(bytes.len(), ADDRESS_LABEL_BYTES);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_label, ADDRESS_LABEL_BYTES);
        if !out_written.is_null() {
            *out_written = ADDRESS_LABEL_BYTES;
        }
    }
    UOR_ADDR_OK
}

/// Borrow the caller's `input` slice safely.
///
/// # Safety
///
/// `input` must be null (with `input_len == 0`) or readable for
/// `input_len` bytes.
unsafe fn borrow_input<'a>(input: *const u8, input_len: usize) -> Result<&'a [u8], i32> {
    if input_len == 0 {
        return Ok(&[]);
    }
    if input.is_null() {
        return Err(UOR_ADDR_ERR_NULL_POINTER);
    }
    Ok(unsafe { slice::from_raw_parts(input, input_len) })
}

// ─── JSON realization ──────────────────────────────────────────────

/// JSON realization (RFC 8785 JCS + Unicode NFC + SHA-256).
///
/// # Safety
///
/// - `input` must be null (with `input_len == 0`) or readable for
///   `input_len` bytes.
/// - `out_label` must be writable for at least `out_label_len` bytes.
/// - `out_written` if non-null must point to a writable `size_t`.
#[no_mangle]
pub unsafe extern "C" fn uor_addr_json(
    input: *const u8,
    input_len: usize,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match json::address(s) {
        Ok(outcome) => unsafe { write_outcome(outcome, out_label, out_label_len, out_written) },
        Err(json::AddressFailure::InvalidJson) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(json::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(json::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

// ─── S-expression realization ──────────────────────────────────────

/// S-expression realization (Rivest 1997 canonical form + SHA-256).
///
/// # Safety
///
/// Same pointer-validity requirements as [`uor_addr_json`].
#[no_mangle]
pub unsafe extern "C" fn uor_addr_sexp(
    input: *const u8,
    input_len: usize,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match sexp::address(s) {
        Ok(outcome) => unsafe { write_outcome(outcome, out_label, out_label_len, out_written) },
        Err(sexp::AddressFailure::InvalidSExpr) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(sexp::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(sexp::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

// ─── XML realization ───────────────────────────────────────────────

/// XML realization (W3C XML-C14N 1.1 subset + SHA-256).
///
/// # Safety
///
/// Same pointer-validity requirements as [`uor_addr_json`].
#[no_mangle]
pub unsafe extern "C" fn uor_addr_xml(
    input: *const u8,
    input_len: usize,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match xml::address(s) {
        Ok(outcome) => unsafe { write_outcome(outcome, out_label, out_label_len, out_written) },
        Err(xml::AddressFailure::InvalidXml) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(xml::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(xml::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

// ─── ASN.1 realization ─────────────────────────────────────────────

/// ASN.1 realization (ITU-T X.690 DER + SHA-256).
///
/// # Safety
///
/// Same pointer-validity requirements as [`uor_addr_json`].
#[no_mangle]
pub unsafe extern "C" fn uor_addr_asn1(
    input: *const u8,
    input_len: usize,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match asn1::address(s) {
        Ok(outcome) => unsafe { write_outcome(outcome, out_label, out_label_len, out_written) },
        Err(asn1::AddressFailure::InvalidDer) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(asn1::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(asn1::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

// ─── Ring realization ──────────────────────────────────────────────

/// Ring realization (UOR-Framework Amendment 43 §2 + SHA-256).
///
/// # Safety
///
/// Same pointer-validity requirements as [`uor_addr_json`].
#[no_mangle]
pub unsafe extern "C" fn uor_addr_ring(
    input: *const u8,
    input_len: usize,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match ring::address(s) {
        Ok(outcome) => unsafe { write_outcome(outcome, out_label, out_label_len, out_written) },
        Err(ring::AddressFailure::InvalidRingElement) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(ring::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(ring::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

// ─── Code-module realization ───────────────────────────────────────

/// Code-module realization (CCMAS canonical AST + SHA-256).
///
/// # Safety
///
/// Same pointer-validity requirements as [`uor_addr_json`].
#[no_mangle]
pub unsafe extern "C" fn uor_addr_codemodule(
    input: *const u8,
    input_len: usize,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match codemodule::address(s) {
        Ok(outcome) => unsafe { write_outcome(outcome, out_label, out_label_len, out_written) },
        Err(codemodule::AddressFailure::InvalidCcmas) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(codemodule::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(codemodule::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

// ─── Schema-pinned descendants ─────────────────────────────────────

/// schema.org/Photograph descendant — admits only schema.org/Photograph
/// JSON-LD inputs; routes canonical form through the JSON realization.
///
/// # Safety
///
/// Same pointer-validity requirements as [`uor_addr_json`].
#[no_mangle]
pub unsafe extern "C" fn uor_addr_schema_photo(
    input: *const u8,
    input_len: usize,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match schema::photo::address(s) {
        Ok(outcome) => unsafe { write_outcome(outcome, out_label, out_label_len, out_written) },
        Err(schema::photo::AddressFailure::SchemaViolation) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(schema::photo::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(schema::photo::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// schema.org/Article descendant — admits only schema.org/Article
/// JSON-LD inputs (plus subtypes); routes canonical form through JSON.
///
/// # Safety
///
/// Same pointer-validity requirements as [`uor_addr_json`].
#[no_mangle]
pub unsafe extern "C" fn uor_addr_schema_document(
    input: *const u8,
    input_len: usize,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match schema::document::address(s) {
        Ok(outcome) => unsafe { write_outcome(outcome, out_label, out_label_len, out_written) },
        Err(schema::document::AddressFailure::SchemaViolation) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(schema::document::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(schema::document::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// in-toto Statement v1 descendant — admits only in-toto Statement v1
/// JSON envelopes (sigstore / SLSA / SCAI / SPDX SBOM predicates).
///
/// # Safety
///
/// Same pointer-validity requirements as [`uor_addr_json`].
#[no_mangle]
pub unsafe extern "C" fn uor_addr_schema_codemodule_signed(
    input: *const u8,
    input_len: usize,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match schema::codemodule_signed::address(s) {
        Ok(outcome) => unsafe { write_outcome(outcome, out_label, out_label_len, out_written) },
        Err(schema::codemodule_signed::AddressFailure::SchemaViolation) => {
            UOR_ADDR_ERR_INVALID_INPUT
        }
        Err(schema::codemodule_signed::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(schema::codemodule_signed::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

// ─── Grounded witness (TC-05 cross-language replay) ────────────────
//
// Mirrors the WIT `resource grounded` exposed by the WASM Component
// Model surface. Each `uor_addr_<realization>_with_witness` mint
// produces an opaque heap-allocated handle the caller owns; the
// caller verifies via `uor_addr_grounded_verify` (which replays
// through `prism_verify::certify_from_trace` without re-invoking
// SHA-256) and releases via `uor_addr_grounded_free`.
//
// The witness API requires an allocator and is gated behind the
// `alloc` feature. Embedded bare-metal builds (`--no-default-features
// --target thumbv7em-none-eabihf`) get only the κ-label-only
// functions above.

/// Verify-error codes — 1:1 with WIT `verify-error` variants. Returned
/// by [`uor_addr_grounded_verify`]. All five are *defensive* against
/// substrate corruption; unreachable for a handle the C ABI itself
/// minted.
pub const UOR_ADDR_ERR_VERIFY_EMPTY_TRACE: i32 = -10;
pub const UOR_ADDR_ERR_VERIFY_OUT_OF_ORDER_EVENT: i32 = -11;
pub const UOR_ADDR_ERR_VERIFY_ZERO_TARGET: i32 = -12;
pub const UOR_ADDR_ERR_VERIFY_NON_CONTIGUOUS_STEPS: i32 = -13;
pub const UOR_ADDR_ERR_VERIFY_CAPACITY_EXCEEDED: i32 = -14;

/// Opaque handle to a Rust-side `AddressOutcome` carrying a sealed
/// `Grounded<AddressLabel>` witness. Construct via any of the
/// `uor_addr_<realization>_with_witness` functions; release via
/// [`uor_addr_grounded_free`].
///
/// **Lifetime**: the handle is valid until `uor_addr_grounded_free`
/// is called. Calling any `uor_addr_grounded_*` accessor on a freed
/// handle is undefined behaviour. The witness lives only in the
/// process that minted it — there is no cross-process serialization
/// (the underlying `Trace<256>` constructor is `pub(crate)` in
/// `uor-foundation`).
#[cfg(feature = "alloc")]
#[repr(C)]
pub struct UorAddrGrounded {
    // `pub(crate)` body — the struct is *strictly opaque* from the C
    // side. The contained `AddressOutcome` carries both the κ-label
    // and the sealed `Grounded<AddressLabel>` witness.
    pub(crate) outcome: AddressOutcome,
}

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// Internal helper: marshal an `AddressOutcome` into a heap-allocated
/// `UorAddrGrounded` and hand the raw pointer back to the caller.
///
/// # Safety
///
/// `out_handle` must be a valid writable pointer to a `*mut
/// UorAddrGrounded`.
#[cfg(feature = "alloc")]
unsafe fn write_grounded(outcome: AddressOutcome, out_handle: *mut *mut UorAddrGrounded) -> i32 {
    if out_handle.is_null() {
        return UOR_ADDR_ERR_NULL_POINTER;
    }
    let boxed = Box::new(UorAddrGrounded { outcome });
    let ptr = Box::into_raw(boxed);
    unsafe {
        *out_handle = ptr;
    }
    UOR_ADDR_OK
}

/// Free a Grounded handle. Calling with a null pointer is a no-op.
/// After this call returns, `handle` is invalid; any further use is
/// undefined behaviour.
///
/// # Safety
///
/// `handle` must be either null or a pointer previously returned by
/// any `uor_addr_<realization>_with_witness` call. Each handle must
/// be freed exactly once.
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_grounded_free(handle: *mut UorAddrGrounded) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Read the κ-label this Grounded carries into `out_label`. Returns
/// the number of bytes written (always 71 on success) via
/// `out_written` (may be NULL).
///
/// # Safety
///
/// - `handle` must be a valid live handle returned by a
///   `*_with_witness` call.
/// - `out_label` must be writable for at least `out_label_len` bytes.
/// - `out_written` if non-null must point to a writable `size_t`.
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_grounded_kappa_label(
    handle: *const UorAddrGrounded,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    if handle.is_null() {
        return UOR_ADDR_ERR_NULL_POINTER;
    }
    let g = unsafe { &*handle };
    if out_label.is_null() {
        return UOR_ADDR_ERR_NULL_POINTER;
    }
    if out_label_len < ADDRESS_LABEL_BYTES {
        return UOR_ADDR_ERR_BUFFER_TOO_SMALL;
    }
    let bytes = g.outcome.address.as_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_label, ADDRESS_LABEL_BYTES);
        if !out_written.is_null() {
            *out_written = ADDRESS_LABEL_BYTES;
        }
    }
    UOR_ADDR_OK
}

/// Read the 32-byte SHA-256 content fingerprint into `out_digest`.
///
/// # Safety
///
/// Same as [`uor_addr_grounded_kappa_label`], with `out_digest`
/// writable for at least 32 bytes.
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_grounded_content_fingerprint(
    handle: *const UorAddrGrounded,
    out_digest: *mut u8,
    out_digest_len: usize,
    out_written: *mut usize,
) -> i32 {
    if handle.is_null() {
        return UOR_ADDR_ERR_NULL_POINTER;
    }
    let g = unsafe { &*handle };
    if out_digest.is_null() {
        return UOR_ADDR_ERR_NULL_POINTER;
    }
    if out_digest_len < 32 {
        return UOR_ADDR_ERR_BUFFER_TOO_SMALL;
    }
    let bytes = g.outcome.witness.grounded().content_fingerprint();
    let arr = bytes.as_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(arr.as_ptr(), out_digest, 32);
        if !out_written.is_null() {
            *out_written = 32;
        }
    }
    UOR_ADDR_OK
}

/// Verify the witness by replaying its derivation through
/// `prism_verify::certify_from_trace` and writing the recovered
/// κ-label into `out_label`. SHA-256 is **not** re-invoked.
///
/// On `UOR_ADDR_OK` the bytes in `out_label[..71]` are byte-identical
/// to those `uor_addr_grounded_kappa_label` would write (QS-05 replay
/// equivalence; CL-R\* in CONFORMANCE.md).
///
/// # Safety
///
/// Same as [`uor_addr_grounded_kappa_label`].
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_grounded_verify(
    handle: *const UorAddrGrounded,
    out_label: *mut u8,
    out_label_len: usize,
    out_written: *mut usize,
) -> i32 {
    if handle.is_null() {
        return UOR_ADDR_ERR_NULL_POINTER;
    }
    let g = unsafe { &*handle };
    if out_label.is_null() {
        return UOR_ADDR_ERR_NULL_POINTER;
    }
    if out_label_len < ADDRESS_LABEL_BYTES {
        return UOR_ADDR_ERR_BUFFER_TOO_SMALL;
    }
    let grounded = g.outcome.witness.grounded();
    let trace: prism_verify::Trace<256> = grounded.derivation().replay();
    match prism_verify::certify_from_trace(&trace) {
        Ok(certified) => {
            // Defensive: the replayed certificate's fingerprint must
            // match the source `Grounded`'s. Pinned by CL-R01/CL-R02.
            if certified.certificate().content_fingerprint() != grounded.content_fingerprint() {
                return UOR_ADDR_ERR_PIPELINE;
            }
            let bytes = g.outcome.address.as_bytes();
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_label, ADDRESS_LABEL_BYTES);
                if !out_written.is_null() {
                    *out_written = ADDRESS_LABEL_BYTES;
                }
            }
            UOR_ADDR_OK
        }
        Err(prism_verify::ReplayError::EmptyTrace) => UOR_ADDR_ERR_VERIFY_EMPTY_TRACE,
        Err(prism_verify::ReplayError::OutOfOrderEvent { .. }) => {
            UOR_ADDR_ERR_VERIFY_OUT_OF_ORDER_EVENT
        }
        Err(prism_verify::ReplayError::ZeroTarget { .. }) => UOR_ADDR_ERR_VERIFY_ZERO_TARGET,
        Err(prism_verify::ReplayError::NonContiguousSteps { .. }) => {
            UOR_ADDR_ERR_VERIFY_NON_CONTIGUOUS_STEPS
        }
        Err(prism_verify::ReplayError::CapacityExceeded { .. }) => {
            UOR_ADDR_ERR_VERIFY_CAPACITY_EXCEEDED
        }
        // `#[non_exhaustive]` upstream — defensive fallback.
        Err(_) => UOR_ADDR_ERR_PIPELINE,
    }
}

// ─── Per-realization `*_with_witness` constructors ─────────────────
//
// Each function is written out explicitly (rather than via a
// `macro_rules!` template) because cbindgen's parser is syntactic and
// does not expand macros. Keeping the declarations literal lets the
// auto-generated `uor_addr.h` carry every prototype.

/// JSON realization, returning a verifiable witness handle.
///
/// # Safety
///
/// - `input` must be null (with `input_len == 0`) or readable for
///   `input_len` bytes.
/// - `out_handle` must be a valid writable pointer to a
///   `*mut UorAddrGrounded`.
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_json_with_witness(
    input: *const u8,
    input_len: usize,
    out_handle: *mut *mut UorAddrGrounded,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match json::address(s) {
        Ok(outcome) => unsafe { write_grounded(outcome, out_handle) },
        Err(json::AddressFailure::InvalidJson) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(json::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(json::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// S-expression realization, returning a verifiable witness handle.
///
/// # Safety
///
/// Same as [`uor_addr_json_with_witness`].
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_sexp_with_witness(
    input: *const u8,
    input_len: usize,
    out_handle: *mut *mut UorAddrGrounded,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match sexp::address(s) {
        Ok(outcome) => unsafe { write_grounded(outcome, out_handle) },
        Err(sexp::AddressFailure::InvalidSExpr) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(sexp::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(sexp::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// XML realization, returning a verifiable witness handle.
///
/// # Safety
///
/// Same as [`uor_addr_json_with_witness`].
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_xml_with_witness(
    input: *const u8,
    input_len: usize,
    out_handle: *mut *mut UorAddrGrounded,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match xml::address(s) {
        Ok(outcome) => unsafe { write_grounded(outcome, out_handle) },
        Err(xml::AddressFailure::InvalidXml) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(xml::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(xml::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// ASN.1 realization, returning a verifiable witness handle.
///
/// # Safety
///
/// Same as [`uor_addr_json_with_witness`].
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_asn1_with_witness(
    input: *const u8,
    input_len: usize,
    out_handle: *mut *mut UorAddrGrounded,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match asn1::address(s) {
        Ok(outcome) => unsafe { write_grounded(outcome, out_handle) },
        Err(asn1::AddressFailure::InvalidDer) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(asn1::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(asn1::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// Ring realization, returning a verifiable witness handle.
///
/// # Safety
///
/// Same as [`uor_addr_json_with_witness`].
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_ring_with_witness(
    input: *const u8,
    input_len: usize,
    out_handle: *mut *mut UorAddrGrounded,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match ring::address(s) {
        Ok(outcome) => unsafe { write_grounded(outcome, out_handle) },
        Err(ring::AddressFailure::InvalidRingElement) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(ring::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(ring::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// Code-module realization, returning a verifiable witness handle.
///
/// # Safety
///
/// Same as [`uor_addr_json_with_witness`].
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_codemodule_with_witness(
    input: *const u8,
    input_len: usize,
    out_handle: *mut *mut UorAddrGrounded,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match codemodule::address(s) {
        Ok(outcome) => unsafe { write_grounded(outcome, out_handle) },
        Err(codemodule::AddressFailure::InvalidCcmas) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(codemodule::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(codemodule::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// schema.org/Photograph realization, returning a verifiable witness handle.
///
/// # Safety
///
/// Same as [`uor_addr_json_with_witness`].
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_schema_photo_with_witness(
    input: *const u8,
    input_len: usize,
    out_handle: *mut *mut UorAddrGrounded,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match schema::photo::address(s) {
        Ok(outcome) => unsafe { write_grounded(outcome, out_handle) },
        Err(schema::photo::AddressFailure::SchemaViolation) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(schema::photo::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(schema::photo::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// schema.org/Article realization, returning a verifiable witness handle.
///
/// # Safety
///
/// Same as [`uor_addr_json_with_witness`].
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_schema_document_with_witness(
    input: *const u8,
    input_len: usize,
    out_handle: *mut *mut UorAddrGrounded,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match schema::document::address(s) {
        Ok(outcome) => unsafe { write_grounded(outcome, out_handle) },
        Err(schema::document::AddressFailure::SchemaViolation) => UOR_ADDR_ERR_INVALID_INPUT,
        Err(schema::document::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(schema::document::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

/// in-toto Statement v1 realization, returning a verifiable witness handle.
///
/// # Safety
///
/// Same as [`uor_addr_json_with_witness`].
#[cfg(feature = "alloc")]
#[no_mangle]
pub unsafe extern "C" fn uor_addr_schema_codemodule_signed_with_witness(
    input: *const u8,
    input_len: usize,
    out_handle: *mut *mut UorAddrGrounded,
) -> i32 {
    let s = match unsafe { borrow_input(input, input_len) } {
        Ok(s) => s,
        Err(code) => return code,
    };
    match schema::codemodule_signed::address(s) {
        Ok(outcome) => unsafe { write_grounded(outcome, out_handle) },
        Err(schema::codemodule_signed::AddressFailure::SchemaViolation) => {
            UOR_ADDR_ERR_INVALID_INPUT
        }
        Err(schema::codemodule_signed::AddressFailure::TooLarge) => UOR_ADDR_ERR_TOO_LARGE,
        Err(schema::codemodule_signed::AddressFailure::PipelineFailure) => UOR_ADDR_ERR_PIPELINE,
    }
}

// ─── Panic handler for `no_std` builds without `std` ───────────────

// Panic handler is required on any `no_std` target. With `--features std`
// the standard library provides one and this stub is suppressed. The
// no_alloc surface never panics on well-formed input (bound checks
// return error codes); the handler is a safety net for unreachable
// arms.
// On bare-metal targets (`target_os = "none"`, e.g.
// `thumbv7em-none-eabihf`) no `std`-provided panic handler is
// linkable, so the crate must supply one. Hosted targets
// (`linux`, `macos`, `windows`, …) take `std::panic`'s default.
// We key off `target_os = "none"` rather than `feature = "std"` so
// cargo's workspace feature-unification (which can enable `std` in
// transitive deps for `--all-targets` test builds) doesn't cause a
// duplicate `panic_impl` lang item.
// Embedded bare-metal builds get our panic handler; hosted builds
// (`target_os = linux/macos/windows/…`) pull `std`'s default via the
// `std` feature.
#[cfg(all(not(feature = "std"), target_os = "none"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
