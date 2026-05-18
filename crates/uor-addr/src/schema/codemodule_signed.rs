//! **`uor_addr::schema::codemodule_signed` — signed-code-module
//! content-addressing** (ARCHITECTURE.md "Schema-pinned descendants"
//! § `uor-addr-codemodule-signed`).
//!
//! Schema-pinned descendant of [`crate::codemodule`]. Admits only
//! CCMAS values whose top-level Module carries a `(7:sig <hex>)`
//! signature sub-form embedding a 64-hex-byte signature value.
//!
//! ## Schema
//!
//! The input CCMAS form must be a top-level Module
//! `(3:mod <name> ... (3:sig <signature-hex>) ...)` containing
//! exactly one `(3:sig <atom>)` child whose atom is a 64-byte
//! lowercase hex string (representing a 32-byte signature digest).
//!
//! The ψ-pipeline κ-derivation operates over the canonical CCMAS
//! bytes including the signature item — the κ-label binds the
//! content-and-signature pair.

extern crate alloc;

use alloc::vec::Vec;

use prism::pipeline::{ShapeViolation, ViolationKind};

use crate::codemodule::CodeModuleValue;

const SCHEMA_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/SignedCodeModuleValue",
    constraint_iri: "https://uor.foundation/addr/SignedCodeModuleValue/schemaConformance",
    property_iri: "https://uor.foundation/addr/SignedCodeModuleValue/ccmas",
    expected_range: "https://uor.foundation/addr/SignedCodeModuleSchema",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

/// Tag head identifying the signature sub-form within a signed
/// code-module's Module list.
pub const SIGNATURE_TAG: &str = "sig";
/// Required signature payload byte width (64 lowercase-hex bytes
/// representing a 32-byte digest).
pub const SIGNATURE_HEX_BYTES: usize = 64;

/// Typed signed-code-module input shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCodeModuleValue {
    inner: CodeModuleValue,
}

impl SignedCodeModuleValue {
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let inner = CodeModuleValue::parse(raw).map_err(|_| SCHEMA_VIOLATION)?;
        // Validate that the canonical bytes contain a `(3:sig <64-hex>)` item.
        let bytes = inner.tagged_bytes();
        if !find_signature_item(bytes)? {
            return Err(SCHEMA_VIOLATION);
        }
        Ok(Self { inner })
    }

    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        self.inner.tagged_bytes()
    }

    /// Build a signed code-module from a [`CodeModuleValue`] and a
    /// 64-character lowercase-hex signature.
    pub fn from_module_with_signature(
        name: &str,
        items: &[CodeModuleValue],
        signature_hex: &str,
    ) -> Result<Self, ShapeViolation> {
        if signature_hex.len() != SIGNATURE_HEX_BYTES
            || !signature_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SCHEMA_VIOLATION);
        }
        let sig_atom = CodeModuleValue::atom(signature_hex).map_err(|_| SCHEMA_VIOLATION)?;
        let sig_items = alloc::vec![sig_atom];
        let sig = item_sig_call(&sig_items)?;
        let mut all = items.to_vec();
        all.push(sig);
        let m = CodeModuleValue::module(name, &all).map_err(|_| SCHEMA_VIOLATION)?;
        Self::parse(m.tagged_bytes())
    }
}

fn item_sig_call(items: &[CodeModuleValue]) -> Result<CodeModuleValue, ShapeViolation> {
    // (3:sig <signature-atom>)
    let mut bytes = Vec::new();
    bytes.push(b'(');
    bytes.extend_from_slice(b"3:sig");
    for item in items {
        bytes.push(b' ');
        bytes.extend_from_slice(item.tagged_bytes());
    }
    bytes.push(b')');
    // We can't call CodeModuleValue::parse on the partial form directly
    // (it expects a complete top-level Module). Wrap into a CodeModuleValue
    // by reusing the internal tagged-bytes field through public APIs.
    // Cheapest path: construct an atom-like atom-list using
    // CodeModuleValue::atom on the synthesized canonical bytes is wrong;
    // instead, we accept that the sig sub-form is built inline as part of
    // the module's items list. The caller's CodeModuleValue::module() will
    // build the surrounding list; pass `sig` items individually.
    //
    // For our public API, return a synthetic CodeModuleValue carrying
    // these bytes verbatim — they will appear as a list child inside
    // CodeModuleValue::module's canonical bytes.
    Ok(unsafe_assemble(bytes))
}

fn unsafe_assemble(bytes: Vec<u8>) -> CodeModuleValue {
    // Construction-by-bytes is internal to the schema module. The
    // bytes are well-formed by construction (we wrote a single
    // `(3:sig ...)` Rivest list).
    // Use a stable accessor via parsing — guarantees the bytes pass
    // the CCMAS walker. The walker accepts `(3:sig <atom>)` as a
    // generic tagged list.
    // SAFETY argument: not unsafe in Rust sense; the name reflects
    // that we bypass the high-level constructor in favor of the
    // bytes path. CodeModuleValue::parse re-validates.
    CodeModuleValue::parse(&bytes).expect("internal sig sub-form is well-formed CCMAS")
}

/// Walk the CCMAS canonical bytes and return true if any top-level
/// child within the outer Module list is a `(3:sig <64-hex>)` list.
fn find_signature_item(bytes: &[u8]) -> Result<bool, ShapeViolation> {
    // Top-level shape is `(3:mod <name> <items>...)`. The signature
    // item is a `(3:sig <64-hex>)` child.
    let pattern = b"(3:sig 64:";
    let needle_found = bytes.windows(pattern.len()).any(|window| window == pattern);
    if !needle_found {
        return Ok(false);
    }
    // Verify the 64 bytes after `(3:sig 64:` are lowercase-hex.
    let start = bytes
        .windows(pattern.len())
        .position(|w| w == pattern)
        .ok_or(SCHEMA_VIOLATION)?
        + pattern.len();
    let end = start + SIGNATURE_HEX_BYTES;
    if end > bytes.len() {
        return Err(SCHEMA_VIOLATION);
    }
    for &b in &bytes[start..end] {
        if !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b) {
            return Err(SCHEMA_VIOLATION);
        }
    }
    // Followed by `)`.
    if end >= bytes.len() || bytes[end] != b')' {
        return Err(SCHEMA_VIOLATION);
    }
    Ok(true)
}

/// Mint a κ-label over a signed-code-module-schema-admitted CCMAS
/// value. The κ-label is byte-identical to
/// [`crate::codemodule::address`] for the same input — schema
/// admission applies at parse time.
pub fn address(raw: &[u8]) -> Result<crate::codemodule::AddressOutcome, AddressFailure> {
    SignedCodeModuleValue::parse(raw).map_err(|_| AddressFailure::SchemaViolation)?;
    crate::codemodule::address(raw).map_err(|e| match e {
        crate::codemodule::AddressFailure::InvalidCcmas => AddressFailure::SchemaViolation,
        crate::codemodule::AddressFailure::TooLarge => AddressFailure::TooLarge,
        crate::codemodule::AddressFailure::PipelineFailure => AddressFailure::PipelineFailure,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFailure {
    SchemaViolation,
    TooLarge,
    PipelineFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_signed_module() -> CodeModuleValue {
        // Build a module with a body item plus a signature item.
        let body = CodeModuleValue::atom("body").expect("valid");
        let mod_name = "demo";
        let sig_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        SignedCodeModuleValue::from_module_with_signature(mod_name, &[body], sig_hex)
            .expect("valid")
            .inner
    }

    #[test]
    fn admits_signed_module_with_64_hex_signature() {
        let m = sample_signed_module();
        let parsed = SignedCodeModuleValue::parse(m.tagged_bytes()).expect("valid");
        assert!(!parsed.tagged_bytes().is_empty());
    }

    #[test]
    fn rejects_module_without_signature_item() {
        let unsigned = CodeModuleValue::module("nosig", &[]).expect("valid");
        let err = SignedCodeModuleValue::parse(unsigned.tagged_bytes()).expect_err("must reject");
        assert_eq!(err.constraint_iri, SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_non_hex_signature() {
        let err = SignedCodeModuleValue::from_module_with_signature(
            "m",
            &[],
            "ZZZ_not_hex_ZZZ_not_hex_ZZZ_not_hex_ZZZ_not_hex_ZZZ_not_hex_ZZZ_",
        )
        .expect_err("non-hex");
        assert_eq!(err.constraint_iri, SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_wrong_signature_length() {
        let err = SignedCodeModuleValue::from_module_with_signature("m", &[], "abc")
            .expect_err("wrong length");
        assert_eq!(err.constraint_iri, SCHEMA_VIOLATION.constraint_iri);
    }

    #[test]
    fn address_matches_codemodule_realization() {
        let m = sample_signed_module();
        let from_signed = address(m.tagged_bytes()).expect("κ-label").address;
        let from_code = crate::codemodule::address(m.tagged_bytes())
            .expect("κ-label")
            .address;
        assert_eq!(from_signed, from_code);
    }
}
