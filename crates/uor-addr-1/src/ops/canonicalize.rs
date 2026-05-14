//! JCS-RFC8785 + Unicode-NFC canonicalisation — the **host-boundary
//! transform** that converts an unstructured JSON byte sequence into
//! the canonical-form bytes the typed `JsonInput` carries.
//!
//! Architectural placement per wiki ADR-035: this is a host-boundary
//! transform run by [`crate::pipeline::address`] before constructing
//! the typed `Input` payload of the `PrismModel<H, B, A, R>`. It is
//! **not** part of the ψ-pipeline transform — no σ-residuals leak
//! into the typed-iso surface per ADR-035's verb-body discipline.
//! ADR-023 names the canonical-byte-sequence requirement that
//! `IntoBindingValue::into_binding_bytes` carries downstream; this
//! function produces those canonical bytes for the JSON domain.
//!
//! The algorithm:
//!
//! 1. Parse `input_bytes` as UTF-8 JSON.
//! 2. Recursively NFC-normalise every string key and value.
//! 3. Re-serialise to JSON with sorted keys and no whitespace.
//!
//! Output is the canonical-form UTF-8 bytes. The 12 fixtures harvested
//! by Maura Clark from `mcp.uor.foundation/tools/encode_address` (v0.2.1,
//! algorithm `uor-sha256-v1`, canonicalisation `jcs-rfc8785+nfc`) are
//! reproduced byte-for-byte by this function — see `tests/byte_identity.rs`.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use unicode_normalization::UnicodeNormalization;

use uor_foundation::enforcement::ShapeViolation;
use uor_foundation::ViolationKind;

/// JSON-parse-failure ShapeViolation. The host-boundary canonicaliser
/// rejects inputs that are not valid UTF-8 JSON before they enter the
/// ψ-pipeline.
const INVALID_JSON_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonInput",
    constraint_iri: "https://uor.foundation/addr/JsonInput/validUtf8Json",
    property_iri: "https://uor.foundation/addr/inputBytes",
    expected_range: "https://uor.foundation/addr/ValidUtf8Json",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

/// JCS-RFC8785 + Unicode-NFC canonicalisation of a raw JSON byte
/// sequence.
///
/// # Errors
///
/// Returns [`INVALID_JSON_VIOLATION`] when `input_bytes` is not valid
/// UTF-8 JSON.
pub fn jcs_nfc(input_bytes: &[u8]) -> Result<Vec<u8>, ShapeViolation> {
    let parsed: serde_json::Value =
        serde_json::from_slice(input_bytes).map_err(|_| INVALID_JSON_VIOLATION)?;
    let nfc = nfc_recursive(&parsed);
    Ok(serde_json::to_vec(&nfc).expect(
        "nfc-normalised serde_json::Value re-serialises (only failure mode is non-finite \
         numbers, which serde_json rejects at parse time)",
    ))
}

/// Recursively NFC-normalise every string key and value within a
/// `serde_json::Value`. Numbers, booleans, and nulls pass through
/// unchanged. Map key ordering relies on `serde_json::Map`'s default
/// alphabetical ordering when `preserve_order` is disabled (the
/// default in this crate's `Cargo.toml`).
fn nfc_recursive(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(s.nfc().collect::<String>()),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(nfc_recursive).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut new_obj = serde_json::Map::new();
            for (k, v) in obj {
                let nfc_k: String = k.nfc().collect();
                new_obj.insert(nfc_k, nfc_recursive(v));
            }
            serde_json::Value::Object(new_obj)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_sorts_keys() {
        let canon = jcs_nfc(br#"{"b": 1, "a": 2}"#).expect("valid JSON");
        assert_eq!(canon, br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn canonicalize_strips_whitespace() {
        let canon = jcs_nfc(b"{ \"foo\" : \"bar\" }").expect("valid JSON");
        assert_eq!(canon, br#"{"foo":"bar"}"#);
    }

    #[test]
    fn canonicalize_nfc_normalises_decomposed_strings() {
        // composed "café" (U+00E9) vs decomposed "cafe\u0301" — both
        // normalise to the same canonical UTF-8 bytes.
        let composed = jcs_nfc(b"{\"name\":\"caf\xc3\xa9\"}").expect("valid JSON");
        let decomposed = jcs_nfc(b"{\"name\":\"cafe\xcc\x81\"}").expect("valid JSON");
        assert_eq!(composed, decomposed);
    }

    #[test]
    fn canonicalize_rejects_invalid_json() {
        let err = jcs_nfc(b"not json").expect_err("invalid JSON must fail");
        assert_eq!(err.shape_iri, INVALID_JSON_VIOLATION.shape_iri);
    }
}
