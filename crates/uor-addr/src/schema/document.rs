//! **`uor_addr::schema::document` — Document content-addressing**
//! (ARCHITECTURE.md "Schema-pinned descendants" § `uor-addr-document`).
//!
//! Schema-pinned descendant of [`crate::json`]. Admits only JSON
//! values satisfying the Document schema's required structure.
//!
//! ## Document schema
//!
//! - `title` — string.
//! - `authors` — JSON array of strings (≥ 1 element).
//! - `version` — string (semver-like).
//! - `sections` — JSON array of section objects, each with required
//!   `heading` (string) and `body` (string).
//! - `citations` — JSON array of citation objects, each with
//!   required `key` (string) and `url` (string).

extern crate alloc;

use alloc::vec::Vec;

use prism::pipeline::{ShapeViolation, ViolationKind};

use crate::json::JsonValue;

const DOC_SCHEMA_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/DocumentValue",
    constraint_iri: "https://uor.foundation/addr/DocumentValue/schemaConformance",
    property_iri: "https://uor.foundation/addr/DocumentValue/json",
    expected_range: "https://uor.foundation/addr/DocumentSchema",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

pub const REQUIRED_FIELDS: &[&str] = &["title", "authors", "version", "sections", "citations"];

/// Typed Document content-addressing input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentValue {
    inner: JsonValue,
}

impl DocumentValue {
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| DOC_SCHEMA_VIOLATION)?;
        let obj = value.as_object().ok_or(DOC_SCHEMA_VIOLATION)?;
        for f in REQUIRED_FIELDS {
            if !obj.contains_key(*f) {
                return Err(DOC_SCHEMA_VIOLATION);
            }
        }
        // title, version: strings.
        for f in &["title", "version"] {
            if obj.get(*f).and_then(|v| v.as_str()).is_none() {
                return Err(DOC_SCHEMA_VIOLATION);
            }
        }
        // authors: non-empty array of strings.
        let authors = obj
            .get("authors")
            .and_then(|v| v.as_array())
            .ok_or(DOC_SCHEMA_VIOLATION)?;
        if authors.is_empty() {
            return Err(DOC_SCHEMA_VIOLATION);
        }
        for a in authors {
            if a.as_str().is_none() {
                return Err(DOC_SCHEMA_VIOLATION);
            }
        }
        // sections: array of {heading: str, body: str}.
        let sections = obj
            .get("sections")
            .and_then(|v| v.as_array())
            .ok_or(DOC_SCHEMA_VIOLATION)?;
        for s in sections {
            let so = s.as_object().ok_or(DOC_SCHEMA_VIOLATION)?;
            if so.get("heading").and_then(|v| v.as_str()).is_none()
                || so.get("body").and_then(|v| v.as_str()).is_none()
            {
                return Err(DOC_SCHEMA_VIOLATION);
            }
        }
        // citations: array of {key: str, url: str}.
        let citations = obj
            .get("citations")
            .and_then(|v| v.as_array())
            .ok_or(DOC_SCHEMA_VIOLATION)?;
        for c in citations {
            let co = c.as_object().ok_or(DOC_SCHEMA_VIOLATION)?;
            if co.get("key").and_then(|v| v.as_str()).is_none()
                || co.get("url").and_then(|v| v.as_str()).is_none()
            {
                return Err(DOC_SCHEMA_VIOLATION);
            }
        }
        let inner = JsonValue::parse(raw).map_err(|_| DOC_SCHEMA_VIOLATION)?;
        Ok(Self { inner })
    }

    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        self.inner.tagged_bytes()
    }
}

pub fn address(raw: &[u8]) -> Result<crate::json::AddressOutcome, AddressFailure> {
    DocumentValue::parse(raw).map_err(|_| AddressFailure::SchemaViolation)?;
    crate::json::address(raw).map_err(|e| match e {
        crate::json::AddressFailure::InvalidJson => AddressFailure::SchemaViolation,
        crate::json::AddressFailure::TooLarge => AddressFailure::TooLarge,
        crate::json::AddressFailure::PipelineFailure => AddressFailure::PipelineFailure,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    SchemaViolation,
    TooLarge,
    PipelineFailure,
}

pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, AddressFailure> {
    DocumentValue::parse(raw).map_err(|_| AddressFailure::SchemaViolation)?;
    crate::json::canonicalize(raw).map_err(|_| AddressFailure::PipelineFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_DOC: &[u8] = br#"{
        "title": "Example Paper",
        "authors": ["Ada Lovelace", "Alan Turing"],
        "version": "1.0.0",
        "sections": [
            {"heading": "Introduction", "body": "Hello."},
            {"heading": "Conclusion", "body": "Goodbye."}
        ],
        "citations": [
            {"key": "knuth1968", "url": "https://example.org/knuth"}
        ]
    }"#;

    #[test]
    fn admits_valid_document() {
        let d = DocumentValue::parse(VALID_DOC).expect("valid");
        assert!(!d.tagged_bytes().is_empty());
    }

    #[test]
    fn rejects_empty_authors() {
        let bad = br#"{
            "title": "x", "authors": [], "version": "1.0.0",
            "sections": [], "citations": []
        }"#;
        let err = DocumentValue::parse(bad).expect_err("must reject");
        assert_eq!(err.constraint_iri, DOC_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_section_without_heading() {
        let bad = br#"{
            "title": "x", "authors": ["a"], "version": "1.0",
            "sections": [{"body": "no heading"}],
            "citations": []
        }"#;
        let err = DocumentValue::parse(bad).expect_err("must reject");
        assert_eq!(err.constraint_iri, DOC_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn address_matches_json_realization() {
        let from_doc = address(VALID_DOC).expect("κ-label").address;
        let from_json = crate::json::address(VALID_DOC).expect("κ-label").address;
        assert_eq!(from_doc, from_json);
    }
}
