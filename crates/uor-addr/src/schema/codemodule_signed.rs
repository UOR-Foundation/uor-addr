//! **`uor_addr::schema::codemodule_signed` — signed-code-module
//! content-addressing** (ARCHITECTURE.md "Schema-pinned descendants"
//! § `uor-addr-codemodule-signed`).
//!
//! Schema-pinned descendant of [`crate::json`] that **imports the
//! in-toto Statement v1 attestation format** — the host-boundary
//! parser admits only JSON-LD-style values conforming to in-toto's
//! published Statement contract per
//! <https://in-toto.io/Statement/v1>.
//!
//! Per UOR's schema-import discipline, this module does **not**
//! invent a custom signed-code-module schema; it imports the
//! industry-standard in-toto Statement v1 envelope used by sigstore,
//! SLSA, and the broader software-supply-chain attestation
//! ecosystem.
//!
//! ## Authoritative sources
//!
//! - **in-toto Statement v1** —
//!   <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>.
//!   Defines the
//!   `https://in-toto.io/Statement/v1` envelope shape.
//! - **in-toto Attestation Framework v1.0** —
//!   <https://github.com/in-toto/attestation/blob/main/spec/v1/README.md>.
//! - **SLSA Provenance v1** —
//!   <https://slsa.dev/spec/v1.0/provenance> (one common
//!   `predicateType` carried in the in-toto Statement).
//! - **sigstore signature spec** —
//!   <https://docs.sigstore.dev/cosign/signature_specification/>.
//!
//! ## Admission predicate (the in-toto Statement v1 contract)
//!
//! The input must be a JSON object satisfying in-toto Statement v1's
//! shape:
//!
//! 1. `_type` is `"https://in-toto.io/Statement/v1"`.
//! 2. `subject` is a non-empty array; each element is an object with:
//!    - `name` — string identifier for the subject.
//!    - `digest` — object whose entries are hex-encoded digest
//!      strings keyed by algorithm IRI (e.g. `"sha256"`). At least
//!      one digest must be a 64-character lowercase-hex SHA-256
//!      digest.
//! 3. `predicateType` — string IRI naming the predicate format
//!    carried in `predicate`.
//! 4. `predicate` — JSON object whose contents are defined by
//!    `predicateType`.

extern crate alloc;

use alloc::vec::Vec;

use prism::pipeline::{ShapeViolation, ViolationKind};

use crate::json::JsonValue;

const SCHEMA_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://in-toto.io/Statement/v1",
    constraint_iri: "https://in-toto.io/Statement/v1/schemaConformance",
    property_iri: "https://in-toto.io/Statement/v1",
    expected_range: "https://in-toto.io/Statement/v1",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

/// in-toto Statement v1 `_type` IRI.
pub const STATEMENT_TYPE_IRI: &str = "https://in-toto.io/Statement/v1";

/// SHA-256 digest hex byte width (64 lowercase-hex chars for a 32-byte
/// digest).
pub const SHA256_HEX_BYTES: usize = 64;

/// Required top-level properties for an in-toto v1 Statement.
pub const REQUIRED_PROPERTIES: &[&str] = &["_type", "subject", "predicateType", "predicate"];

/// Typed signed-code-module input shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCodeModuleValue {
    inner: JsonValue,
}

impl SignedCodeModuleValue {
    /// Parse + admit. Accepts raw JSON bytes; admits only inputs
    /// satisfying the in-toto Statement v1 envelope.
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let value: serde_json::Value = serde_json::from_slice(raw).map_err(|_| SCHEMA_VIOLATION)?;
        let obj = value.as_object().ok_or(SCHEMA_VIOLATION)?;

        // _type must be the in-toto Statement v1 IRI.
        let ty = obj
            .get("_type")
            .and_then(|v| v.as_str())
            .ok_or(SCHEMA_VIOLATION)?;
        if ty != STATEMENT_TYPE_IRI {
            return Err(SCHEMA_VIOLATION);
        }

        // subject must be a non-empty array of {name, digest} objects.
        let subjects = obj
            .get("subject")
            .and_then(|v| v.as_array())
            .ok_or(SCHEMA_VIOLATION)?;
        if subjects.is_empty() {
            return Err(SCHEMA_VIOLATION);
        }
        for s in subjects {
            let so = s.as_object().ok_or(SCHEMA_VIOLATION)?;
            // name — non-empty string.
            let name = so
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or(SCHEMA_VIOLATION)?;
            if name.is_empty() {
                return Err(SCHEMA_VIOLATION);
            }
            // digest — object with at least one algorithm entry whose
            // value is a hex string. Require sha256 for UOR-ADDR's
            // typed environment.
            let digest = so
                .get("digest")
                .and_then(|v| v.as_object())
                .ok_or(SCHEMA_VIOLATION)?;
            if digest.is_empty() {
                return Err(SCHEMA_VIOLATION);
            }
            let sha256 = digest
                .get("sha256")
                .and_then(|v| v.as_str())
                .ok_or(SCHEMA_VIOLATION)?;
            if sha256.len() != SHA256_HEX_BYTES
                || !sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(SCHEMA_VIOLATION);
            }
        }

        // predicateType — string (typically an IRI).
        let pt = obj
            .get("predicateType")
            .and_then(|v| v.as_str())
            .ok_or(SCHEMA_VIOLATION)?;
        if pt.is_empty() {
            return Err(SCHEMA_VIOLATION);
        }

        // predicate — object.
        if !obj.get("predicate").is_some_and(|v| v.is_object()) {
            return Err(SCHEMA_VIOLATION);
        }

        let inner = JsonValue::parse(raw).map_err(|_| SCHEMA_VIOLATION)?;
        Ok(Self { inner })
    }

    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        self.inner.tagged_bytes()
    }
}

/// Mint a κ-label over an in-toto-v1-Statement-admitted JSON value.
/// The κ-label is byte-identical to [`crate::json::address`] for the
/// same input — schema admission applies at parse time.
pub fn address(raw: &[u8]) -> Result<crate::json::AddressOutcome, AddressFailure> {
    SignedCodeModuleValue::parse(raw).map_err(|_| AddressFailure::SchemaViolation)?;
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
    SignedCodeModuleValue::parse(raw).map_err(|_| AddressFailure::SchemaViolation)?;
    crate::json::canonicalize(raw).map_err(|_| AddressFailure::PipelineFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid in-toto Statement v1 attestation.
    const VALID_STATEMENT: &[u8] = br#"{
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "uor-addr-v0.1.0",
                "digest": {
                    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": "uor:test"},
            "runDetails": {"builder": {"id": "uor:test-builder"}}
        }
    }"#;

    #[test]
    fn admits_valid_in_toto_statement() {
        let s = SignedCodeModuleValue::parse(VALID_STATEMENT).expect("valid");
        assert!(!s.tagged_bytes().is_empty());
    }

    #[test]
    fn admits_multiple_subjects() {
        let raw = br#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "a", "digest": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
                {"name": "b", "digest": {"sha256": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}}
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }"#;
        SignedCodeModuleValue::parse(raw).expect("valid");
    }

    #[test]
    fn rejects_wrong_statement_type_iri() {
        let raw = br#"{
            "_type": "https://example.org/CustomStatement",
            "subject": [{"name": "x", "digest": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}],
            "predicateType": "x",
            "predicate": {}
        }"#;
        let err = SignedCodeModuleValue::parse(raw).expect_err("wrong _type");
        assert_eq!(err.constraint_iri, SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_empty_subject() {
        let raw = br#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [],
            "predicateType": "x",
            "predicate": {}
        }"#;
        let err = SignedCodeModuleValue::parse(raw).expect_err("empty subject");
        assert_eq!(err.constraint_iri, SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_subject_without_sha256_digest() {
        let raw = br#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "x", "digest": {"md5": "deadbeef"}}],
            "predicateType": "x",
            "predicate": {}
        }"#;
        let err = SignedCodeModuleValue::parse(raw).expect_err("no sha256");
        assert_eq!(err.constraint_iri, SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_sha256_with_wrong_length() {
        let raw = br#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "x", "digest": {"sha256": "tooshort"}}],
            "predicateType": "x",
            "predicate": {}
        }"#;
        let err = SignedCodeModuleValue::parse(raw).expect_err("short hex");
        assert_eq!(err.constraint_iri, SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_missing_predicate_type() {
        let raw = br#"{
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "x", "digest": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}],
            "predicate": {}
        }"#;
        let err = SignedCodeModuleValue::parse(raw).expect_err("missing predicateType");
        assert_eq!(err.constraint_iri, SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn address_matches_json_realization() {
        let from_signed = address(VALID_STATEMENT).expect("κ-label").address;
        let from_json = crate::json::address(VALID_STATEMENT)
            .expect("κ-label")
            .address;
        assert_eq!(from_signed, from_json);
    }
}
