//! **`uor_addr::schema::document` — Document content-addressing**
//! (ARCHITECTURE.md "Schema-pinned descendants" § `uor-addr-document`).
//!
//! Schema-pinned descendant of [`crate::json`]. **Imports
//! schema.org's `Article` type** (extending `CreativeWork`) — the
//! host-boundary parser admits only JSON-LD values conforming to
//! schema.org's published Article taxon.
//!
//! Per UOR's schema-import discipline, this module does **not** define
//! a custom document schema; it imports `https://schema.org/Article`
//! and applies the schema-validation rules schema.org publishes.
//!
//! ## Authoritative sources
//!
//! - **schema.org Article type** — <https://schema.org/Article>.
//!   Extends [`CreativeWork`](https://schema.org/CreativeWork) →
//!   [`Thing`](https://schema.org/Thing).
//! - **JSON-LD 1.1** — W3C REC — <https://www.w3.org/TR/json-ld11/>.
//!
//! ## Admission predicate (the schema.org/Article contract)
//!
//! The input must be a JSON-LD object satisfying:
//!
//! 1. `@context` is `"https://schema.org"` or `"http://schema.org"`.
//! 2. `@type` is `"Article"` (or one of its subtypes:
//!    `NewsArticle`, `Report`, `ScholarlyArticle`, etc.).
//! 3. `headline` — string (schema.org/Article required-for-content
//!    property).
//! 4. `author` — string (Person name) or object with
//!    `@type` in {`Person`, `Organization`} and a `name` string.
//! 5. `datePublished` — string (ISO 8601 / RFC 3339 date or
//!    date-time per schema.org/Date).

extern crate alloc;

use alloc::vec::Vec;

use prism::pipeline::{ShapeViolation, ViolationKind};

use crate::json::JsonValue;

const DOC_SCHEMA_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://schema.org/Article",
    constraint_iri: "https://schema.org/Article/schemaOrgConformance",
    property_iri: "https://schema.org/Article",
    expected_range: "https://schema.org/Article",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

pub const SCHEMA_ORG_CONTEXTS: &[&str] = &["https://schema.org", "http://schema.org"];

/// Admissible `@type` values — `Article` plus its standard subtypes
/// per <https://schema.org/Article>.
pub const ARTICLE_TYPES: &[&str] = &[
    "Article",
    "NewsArticle",
    "Report",
    "ScholarlyArticle",
    "SocialMediaPosting",
    "TechArticle",
    "BlogPosting",
    "AdvertiserContentArticle",
    "AnalysisNewsArticle",
    "AskPublicNewsArticle",
    "BackgroundNewsArticle",
    "OpinionNewsArticle",
    "ReportageNewsArticle",
    "ReviewNewsArticle",
    "SatiricalArticle",
];

/// Required JSON-LD properties for a schema.org/Article instance:
/// `@context`, `@type`, `headline`, `author`, `datePublished`.
pub const REQUIRED_PROPERTIES: &[&str] =
    &["@context", "@type", "headline", "author", "datePublished"];

/// Typed Document content-addressing input. Wraps a [`JsonValue`]
/// whose runtime JSON structure conforms to schema.org/Article.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentValue {
    inner: JsonValue,
}

impl DocumentValue {
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| DOC_SCHEMA_VIOLATION)?;
        let obj = value.as_object().ok_or(DOC_SCHEMA_VIOLATION)?;

        // @context must be schema.org.
        let context = obj
            .get("@context")
            .and_then(|v| v.as_str())
            .ok_or(DOC_SCHEMA_VIOLATION)?;
        if !SCHEMA_ORG_CONTEXTS.contains(&context) {
            return Err(DOC_SCHEMA_VIOLATION);
        }

        // @type must be Article or one of its subtypes.
        let ty = obj
            .get("@type")
            .and_then(|v| v.as_str())
            .ok_or(DOC_SCHEMA_VIOLATION)?;
        if !ARTICLE_TYPES.contains(&ty) {
            return Err(DOC_SCHEMA_VIOLATION);
        }

        // headline — string.
        if obj.get("headline").and_then(|v| v.as_str()).is_none() {
            return Err(DOC_SCHEMA_VIOLATION);
        }

        // author — string, Person/Organization object, or non-empty
        // array of either (per schema.org's multi-value-property
        // pattern in JSON-LD).
        validate_author(obj.get("author"))?;

        // datePublished — string (ISO 8601). We don't fully parse the
        // date; we require a non-empty string per schema.org's Date
        // value-space.
        let date = obj
            .get("datePublished")
            .and_then(|v| v.as_str())
            .ok_or(DOC_SCHEMA_VIOLATION)?;
        if date.is_empty() {
            return Err(DOC_SCHEMA_VIOLATION);
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

fn validate_author(value: Option<&serde_json::Value>) -> Result<(), ShapeViolation> {
    let v = value.ok_or(DOC_SCHEMA_VIOLATION)?;
    match v {
        serde_json::Value::String(_) => Ok(()),
        serde_json::Value::Object(_) => validate_author_object(v),
        serde_json::Value::Array(arr) if !arr.is_empty() => {
            for item in arr {
                validate_author_item(item)?;
            }
            Ok(())
        }
        _ => Err(DOC_SCHEMA_VIOLATION),
    }
}

fn validate_author_item(value: &serde_json::Value) -> Result<(), ShapeViolation> {
    match value {
        serde_json::Value::String(_) => Ok(()),
        serde_json::Value::Object(_) => validate_author_object(value),
        _ => Err(DOC_SCHEMA_VIOLATION),
    }
}

fn validate_author_object(value: &serde_json::Value) -> Result<(), ShapeViolation> {
    let author = value.as_object().ok_or(DOC_SCHEMA_VIOLATION)?;
    let at = author
        .get("@type")
        .and_then(|v| v.as_str())
        .ok_or(DOC_SCHEMA_VIOLATION)?;
    if at != "Person" && at != "Organization" {
        return Err(DOC_SCHEMA_VIOLATION);
    }
    if author.get("name").and_then(|v| v.as_str()).is_none() {
        return Err(DOC_SCHEMA_VIOLATION);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ARTICLE: &[u8] = br#"{
        "@context": "https://schema.org",
        "@type": "Article",
        "headline": "On Typed Content Addressing",
        "author": {"@type": "Person", "name": "Ada Lovelace"},
        "datePublished": "2025-01-15"
    }"#;

    #[test]
    fn admits_valid_schema_org_article() {
        let d = DocumentValue::parse(VALID_ARTICLE).expect("valid");
        assert!(!d.tagged_bytes().is_empty());
    }

    #[test]
    fn admits_scholarly_article_subtype() {
        let raw = br#"{
            "@context": "https://schema.org",
            "@type": "ScholarlyArticle",
            "headline": "P vs. NP",
            "author": "Anonymous",
            "datePublished": "2025-01-15T12:00:00Z"
        }"#;
        DocumentValue::parse(raw).expect("valid");
    }

    #[test]
    fn admits_news_article_subtype() {
        let raw = br#"{
            "@context": "http://schema.org",
            "@type": "NewsArticle",
            "headline": "Breaking news",
            "author": "Newsdesk",
            "datePublished": "2025-01-15"
        }"#;
        DocumentValue::parse(raw).expect("valid");
    }

    #[test]
    fn rejects_non_schema_org_context() {
        let raw = br#"{
            "@context": "https://example.org",
            "@type": "Article",
            "headline": "x",
            "author": "y",
            "datePublished": "2025-01-15"
        }"#;
        let err = DocumentValue::parse(raw).expect_err("not schema.org");
        assert_eq!(err.constraint_iri, DOC_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_non_article_type() {
        let raw = br#"{
            "@context": "https://schema.org",
            "@type": "Photograph",
            "headline": "x",
            "author": "y",
            "datePublished": "2025-01-15"
        }"#;
        let err = DocumentValue::parse(raw).expect_err("not Article");
        assert_eq!(err.constraint_iri, DOC_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_missing_headline() {
        let raw = br#"{
            "@context": "https://schema.org",
            "@type": "Article",
            "author": "y",
            "datePublished": "2025-01-15"
        }"#;
        let err = DocumentValue::parse(raw).expect_err("missing headline");
        assert_eq!(err.constraint_iri, DOC_SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn address_matches_json_realization() {
        let from_doc = address(VALID_ARTICLE).expect("κ-label").address;
        let from_json = crate::json::address(VALID_ARTICLE)
            .expect("κ-label")
            .address;
        assert_eq!(from_doc, from_json);
    }
}
