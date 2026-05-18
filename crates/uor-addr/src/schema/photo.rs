//! **`uor_addr::schema::photo` — Photo content-addressing**
//! (ARCHITECTURE.md "Schema-pinned descendants" § `uor-addr-photo`).
//!
//! Schema-pinned descendant of [`crate::json`]. **Imports
//! schema.org's `Photograph` type** — the host-boundary parser
//! admits only JSON-LD values that conform to schema.org's published
//! Photograph taxon. ψ-pipeline and κ-derivation are inherited from
//! the JSON realization without modification.
//!
//! Per UOR's schema-import discipline (per the
//! [UOR-Framework wiki](https://github.com/UOR-Foundation/UOR-Framework/wiki)
//! and consistent with the architectural principle that well-known
//! kinds/types map to existing standards rather than UOR-native
//! inventions), this module does **not** define a custom photo
//! schema; it imports `https://schema.org/Photograph` and applies
//! the schema-validation rules schema.org publishes.
//!
//! ## Authoritative sources
//!
//! - **schema.org Photograph type** — <https://schema.org/Photograph>.
//!   Extends [`ImageObject`](https://schema.org/ImageObject) →
//!   [`MediaObject`](https://schema.org/MediaObject) →
//!   [`CreativeWork`](https://schema.org/CreativeWork) →
//!   [`Thing`](https://schema.org/Thing).
//! - **JSON-LD 1.1** — W3C REC — <https://www.w3.org/TR/json-ld11/>.
//! - **RFC 8259** JSON syntax + **RFC 8785** JCS canonical form +
//!   **UAX #15** NFC canonicalization (inherited from
//!   [`crate::json`]).
//!
//! ## Admission predicate (the schema.org/Photograph contract)
//!
//! The input must be a JSON-LD object satisfying:
//!
//! 1. `@context` is `"https://schema.org"` or `"http://schema.org"`
//!    (schema.org's canonical context IRIs).
//! 2. `@type` is `"Photograph"` (the schema.org type IRI).
//! 3. `contentUrl` — string URL, the photograph's content reference
//!    (schema.org/MediaObject required-for-content property).
//! 4. `creator` — string (Person name) or object with
//!    `@type` in {`Person`, `Organization`} and a `name` string.

extern crate alloc;

use alloc::vec::Vec;

use prism::pipeline::{ShapeViolation, ViolationKind};

use crate::json::JsonValue;

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

const PHOTO_SCHEMA_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://schema.org/Photograph",
    constraint_iri: "https://schema.org/Photograph/schemaOrgConformance",
    property_iri: "https://schema.org/Photograph",
    expected_range: "https://schema.org/Photograph",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

/// schema.org canonical context IRIs (HTTP + HTTPS variants).
pub const SCHEMA_ORG_CONTEXTS: &[&str] = &["https://schema.org", "http://schema.org"];

/// schema.org Photograph type IRI fragment (used in the `@type` field).
pub const PHOTOGRAPH_TYPE: &str = "Photograph";

/// Required properties for a schema.org/Photograph instance:
/// `@context`, `@type`, `contentUrl`, `creator`. The latter two are
/// MediaObject + CreativeWork "expected" properties; UOR-ADDR's
/// schema-pin promotes them to required-for-admission per the
/// schema-import discipline.
pub const REQUIRED_PROPERTIES: &[&str] = &["@context", "@type", "contentUrl", "creator"];

/// Typed Photo content-addressing input. Wraps a [`JsonValue`] whose
/// runtime JSON structure conforms to schema.org/Photograph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhotoValue {
    inner: JsonValue,
}

impl PhotoValue {
    /// Parse + admit. Accepts raw JSON bytes; admits only inputs
    /// that conform to schema.org/Photograph.
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| PHOTO_SCHEMA_VIOLATION)?;
        let obj = value.as_object().ok_or(PHOTO_SCHEMA_VIOLATION)?;

        // @context must be schema.org.
        let context = obj
            .get("@context")
            .and_then(|v| v.as_str())
            .ok_or(PHOTO_SCHEMA_VIOLATION)?;
        if !SCHEMA_ORG_CONTEXTS.contains(&context) {
            return Err(PHOTO_SCHEMA_VIOLATION);
        }

        // @type must be Photograph.
        let ty = obj
            .get("@type")
            .and_then(|v| v.as_str())
            .ok_or(PHOTO_SCHEMA_VIOLATION)?;
        if ty != PHOTOGRAPH_TYPE {
            return Err(PHOTO_SCHEMA_VIOLATION);
        }

        // contentUrl — string (schema.org/MediaObject property).
        if obj.get("contentUrl").and_then(|v| v.as_str()).is_none() {
            return Err(PHOTO_SCHEMA_VIOLATION);
        }

        // creator — string OR object with @type in {Person, Organization} and name.
        match obj.get("creator") {
            Some(serde_json::Value::String(_)) => {}
            Some(serde_json::Value::Object(creator)) => {
                let ct = creator
                    .get("@type")
                    .and_then(|v| v.as_str())
                    .ok_or(PHOTO_SCHEMA_VIOLATION)?;
                if ct != "Person" && ct != "Organization" {
                    return Err(PHOTO_SCHEMA_VIOLATION);
                }
                if creator.get("name").and_then(|v| v.as_str()).is_none() {
                    return Err(PHOTO_SCHEMA_VIOLATION);
                }
            }
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

/// Mint a κ-label over a schema.org/Photograph-admitted JSON value.
/// The κ-label is byte-identical to [`crate::json::address`]'s
/// κ-label for the same JSON input — schema admission applies at
/// parse time per SD2 Grounding, not in the ψ-pipeline.
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
    /// Input did not conform to schema.org/Photograph.
    SchemaViolation,
    /// Input exceeded the JSON realization's typed-input bounds.
    TooLarge,
    /// Defensive: substrate-level shape violation.
    PipelineFailure,
}

/// Canonical-bytes accessor. The schema admission applies at
/// admission; the canonical bytes are JCS-RFC8785 + NFC per the
/// JSON realization.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, AddressFailure> {
    PhotoValue::parse(raw).map_err(|_| AddressFailure::SchemaViolation)?;
    crate::json::canonicalize(raw).map_err(|_| AddressFailure::PipelineFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal schema.org/Photograph JSON-LD instance.
    const VALID_PHOTO: &[u8] = br#"{
        "@context": "https://schema.org",
        "@type": "Photograph",
        "contentUrl": "https://example.org/photo.jpg",
        "creator": {"@type": "Person", "name": "Ada Lovelace"}
    }"#;

    #[test]
    fn admits_valid_schema_org_photograph() {
        let p = PhotoValue::parse(VALID_PHOTO).expect("valid");
        assert!(!p.tagged_bytes().is_empty());
    }

    #[test]
    fn admits_string_creator() {
        let raw = br#"{
            "@context": "https://schema.org",
            "@type": "Photograph",
            "contentUrl": "https://example.org/photo.jpg",
            "creator": "Ada Lovelace"
        }"#;
        let p = PhotoValue::parse(raw).expect("valid");
        assert!(!p.tagged_bytes().is_empty());
    }

    #[test]
    fn admits_http_context() {
        // schema.org canonical context is also valid in HTTP form.
        let raw = br#"{
            "@context": "http://schema.org",
            "@type": "Photograph",
            "contentUrl": "https://example.org/photo.jpg",
            "creator": "Ada Lovelace"
        }"#;
        PhotoValue::parse(raw).expect("valid");
    }

    #[test]
    fn rejects_wrong_context() {
        let raw = br#"{
            "@context": "https://example.org/custom",
            "@type": "Photograph",
            "contentUrl": "https://example.org/photo.jpg",
            "creator": "Ada Lovelace"
        }"#;
        let err = PhotoValue::parse(raw).expect_err("not schema.org");
        assert_eq!(err.constraint_iri, PHOTO_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_wrong_type() {
        let raw = br#"{
            "@context": "https://schema.org",
            "@type": "Article",
            "contentUrl": "https://example.org/photo.jpg",
            "creator": "Ada Lovelace"
        }"#;
        let err = PhotoValue::parse(raw).expect_err("not Photograph");
        assert_eq!(err.constraint_iri, PHOTO_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_missing_content_url() {
        let raw = br#"{
            "@context": "https://schema.org",
            "@type": "Photograph",
            "creator": "Ada Lovelace"
        }"#;
        let err = PhotoValue::parse(raw).expect_err("missing contentUrl");
        assert_eq!(err.constraint_iri, PHOTO_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_creator_with_unsupported_type() {
        let raw = br#"{
            "@context": "https://schema.org",
            "@type": "Photograph",
            "contentUrl": "https://example.org/photo.jpg",
            "creator": {"@type": "Robot", "name": "A.L.I.C.E."}
        }"#;
        let err = PhotoValue::parse(raw).expect_err("unsupported creator @type");
        assert_eq!(err.constraint_iri, PHOTO_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn address_matches_json_realization_for_admitted_input() {
        let from_photo = address(VALID_PHOTO).expect("κ-label").address;
        let from_json = crate::json::address(VALID_PHOTO).expect("κ-label").address;
        assert_eq!(from_photo, from_json);
    }
}
