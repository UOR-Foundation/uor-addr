//! **`uor_addr::schema::photo` — Photo content-addressing**
//! (ARCHITECTURE.md "Schema-pinned descendants" § `uor-addr-photo`).
//!
//! Schema-pinned descendant of [`crate::json`]. The host-boundary
//! parser admits only JSON values that satisfy the Photo schema's
//! required structure; ψ-pipeline and κ-derivation are inherited
//! from the JSON realization without modification.
//!
//! ## Photo schema (required JSON-object structure)
//!
//! The input must be a JSON object with **all** of the following
//! string-keyed fields:
//!
//! - `subject` — string, the photo's subject description.
//! - `captured_at` — integer (Unix epoch seconds) or
//!   ISO-8601 date-time string.
//! - `location` — JSON object with required `latitude` (number) and
//!   `longitude` (number) numeric fields.
//! - `camera_make` — string.
//! - `camera_model` — string.
//! - `content_hash` — string (SHA-256 hex digest of the
//!   raw image bytes, lowercase).
//! - `provenance` — string or JSON object describing the chain of
//!   custody.
//!
//! ## Authoritative sources
//!
//! - [RFC 8259](https://datatracker.ietf.org/doc/rfc8259/) JSON syntax.
//! - [RFC 8785](https://datatracker.ietf.org/doc/rfc8785/) JCS canonical form.
//! - The schema above is normative within this module; conformance
//!   fixtures live in `tests` below.

extern crate alloc;

use alloc::vec::Vec;

use prism::pipeline::{ShapeViolation, ViolationKind};

use crate::json::value::canonicalize_into_slice as json_canonicalize_into_slice;
use crate::json::JsonValue;

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

const PHOTO_SCHEMA_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/PhotoValue",
    constraint_iri: "https://uor.foundation/addr/PhotoValue/schemaConformance",
    property_iri: "https://uor.foundation/addr/PhotoValue/json",
    expected_range: "https://uor.foundation/addr/PhotoSchema",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

/// Required top-level fields the Photo schema demands.
pub const REQUIRED_FIELDS: &[&str] = &[
    "subject",
    "captured_at",
    "location",
    "camera_make",
    "camera_model",
    "content_hash",
    "provenance",
];

/// Required sub-fields within the `location` object.
pub const REQUIRED_LOCATION_FIELDS: &[&str] = &["latitude", "longitude"];

/// Typed Photo content-addressing input. Wraps a [`JsonValue`] whose
/// runtime JSON structure satisfies the Photo schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhotoValue {
    inner: JsonValue,
}

impl PhotoValue {
    /// Parse + admit. Accepts raw JSON bytes; admits only inputs
    /// that satisfy the Photo schema.
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| PHOTO_SCHEMA_VIOLATION)?;
        // Schema-admission predicate: top-level must be a JSON object
        // carrying all required fields.
        let obj = value.as_object().ok_or(PHOTO_SCHEMA_VIOLATION)?;
        for field in REQUIRED_FIELDS {
            if !obj.contains_key(*field) {
                return Err(PHOTO_SCHEMA_VIOLATION);
            }
        }
        // location must be an object with required sub-fields.
        let location = obj
            .get("location")
            .and_then(|v| v.as_object())
            .ok_or(PHOTO_SCHEMA_VIOLATION)?;
        for sub in REQUIRED_LOCATION_FIELDS {
            if location.get(*sub).and_then(|v| v.as_f64()).is_none() {
                return Err(PHOTO_SCHEMA_VIOLATION);
            }
        }
        // content_hash must be a 64-char lowercase-hex string.
        let content_hash = obj
            .get("content_hash")
            .and_then(|v| v.as_str())
            .ok_or(PHOTO_SCHEMA_VIOLATION)?;
        if content_hash.len() != 64
            || !content_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(PHOTO_SCHEMA_VIOLATION);
        }
        // captured_at must be a number or a string.
        match obj.get("captured_at") {
            Some(v) if v.is_number() || v.is_string() => {}
            _ => return Err(PHOTO_SCHEMA_VIOLATION),
        }
        // The four name fields must be strings.
        for field in &["subject", "camera_make", "camera_model"] {
            if obj.get(*field).and_then(|v| v.as_str()).is_none() {
                return Err(PHOTO_SCHEMA_VIOLATION);
            }
        }
        // provenance: string or object.
        match obj.get("provenance") {
            Some(v) if v.is_string() || v.is_object() => {}
            _ => return Err(PHOTO_SCHEMA_VIOLATION),
        }
        // All admission predicates satisfied — parse through the JSON
        // realization to obtain the typed JsonValue.
        let inner = JsonValue::parse(raw).map_err(|_| PHOTO_SCHEMA_VIOLATION)?;
        Ok(Self { inner })
    }

    /// Borrow the inner JSON tagged bytes.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        self.inner.tagged_bytes()
    }
}

/// Mint a κ-label over a Photo-schema-admitted JSON value. The
/// κ-label is byte-identical to [`crate::json::address`]'s κ-label
/// for the same JSON input — schema admission applies at parse
/// time, not in the ψ-pipeline.
pub fn address(raw: &[u8]) -> Result<crate::json::AddressOutcome, AddressFailure> {
    PhotoValue::parse(raw).map_err(|_| AddressFailure::SchemaViolation)?;
    crate::json::address(raw).map_err(|e| match e {
        crate::json::AddressFailure::InvalidJson => AddressFailure::SchemaViolation,
        crate::json::AddressFailure::TooLarge => AddressFailure::TooLarge,
        crate::json::AddressFailure::PipelineFailure => AddressFailure::PipelineFailure,
    })
}

/// Failure modes from [`address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    /// Input did not satisfy the Photo schema.
    SchemaViolation,
    /// Input exceeded the JSON realization's typed-input bounds.
    TooLarge,
    /// Defensive: substrate-level shape violation. Unreachable.
    PipelineFailure,
}

/// Canonical-bytes accessor. The Photo schema applies at admission;
/// the canonical bytes are JCS-RFC8785 + NFC per the JSON realization.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, AddressFailure> {
    PhotoValue::parse(raw).map_err(|_| AddressFailure::SchemaViolation)?;
    crate::json::canonicalize(raw).map_err(|_| AddressFailure::PipelineFailure)
}

/// Internal canonicalize_into_slice — used by an `AddressInput` impl
/// if downstream realizations want to wire `PhotoValue` directly into
/// the ψ-pipeline (instead of routing through `crate::json`'s
/// canonicalizer). Currently the descendant inherits the JSON
/// realization's resolver tuple, so this is exposed for parity.
#[allow(dead_code)]
pub(crate) fn canonicalize_into(raw: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
    json_canonicalize_into_slice(raw, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PHOTO: &[u8] = br#"{
        "subject": "skyline at dawn",
        "captured_at": 1700000000,
        "location": {"latitude": 40.7128, "longitude": -74.0060},
        "camera_make": "Acme",
        "camera_model": "X-1000",
        "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "provenance": "uor.foundation:test"
    }"#;

    #[test]
    fn admits_valid_photo_schema() {
        let p = PhotoValue::parse(VALID_PHOTO).expect("valid");
        assert!(!p.tagged_bytes().is_empty());
    }

    #[test]
    fn rejects_missing_required_field() {
        let missing = br#"{
            "subject": "x",
            "location": {"latitude": 0.0, "longitude": 0.0},
            "camera_make": "y",
            "camera_model": "z",
            "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "provenance": "p"
        }"#;
        let err = PhotoValue::parse(missing).expect_err("missing captured_at");
        assert_eq!(err.constraint_iri, PHOTO_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_malformed_location() {
        let bad = br#"{
            "subject": "x",
            "captured_at": 0,
            "location": "not an object",
            "camera_make": "y",
            "camera_model": "z",
            "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "provenance": "p"
        }"#;
        let err = PhotoValue::parse(bad).expect_err("must reject");
        assert_eq!(err.constraint_iri, PHOTO_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_malformed_content_hash() {
        let bad = br#"{
            "subject": "x",
            "captured_at": 0,
            "location": {"latitude": 0.0, "longitude": 0.0},
            "camera_make": "y",
            "camera_model": "z",
            "content_hash": "tooshort",
            "provenance": "p"
        }"#;
        let err = PhotoValue::parse(bad).expect_err("must reject");
        assert_eq!(err.constraint_iri, PHOTO_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn address_matches_json_realization_for_admitted_input() {
        // Schema admission applies at parse time, but the κ-label is
        // computed by the JSON realization. The outcome κ-label must
        // be byte-identical between `schema::photo::address` and
        // `json::address` for the same input.
        let from_photo = address(VALID_PHOTO).expect("κ-label").address;
        let from_json = crate::json::address(VALID_PHOTO).expect("κ-label").address;
        assert_eq!(from_photo, from_json);
    }
}
