//! **`uor_addr::json` — the JSON realization of UOR-ADDR**
//! (ARCHITECTURE.md "Format-specific realizations" § `uor-addr-json`).
//!
//! JSON typed-input content-addressing under JCS-RFC8785 §3 + Unicode
//! NFC, with the σ-projection bound to `prism::crypto::Sha256Hasher`.
//!
//! ## Authoritative sources
//!
//! - **JSON syntax** — IETF RFC 8259 *The JavaScript Object Notation
//!   (JSON) Data Interchange Format*
//!   (<https://datatracker.ietf.org/doc/rfc8259/>).
//! - **Canonical form (JCS)** — IETF RFC 8785 *JSON Canonicalization
//!   Scheme (JCS)* (<https://datatracker.ietf.org/doc/rfc8785/>).
//! - **Unicode NFC normalization** — Unicode Standard Annex #15
//!   *Unicode Normalization Forms* (<https://www.unicode.org/reports/tr15/>).
//! - **ECMA-262 numeric serialization** — invoked by JCS-RFC8785
//!   §3.2.2.3 (<https://datatracker.ietf.org/doc/html/rfc8785#section-3.2.2.3>).
//! - **SHA-256 σ-projection** — NIST FIPS 180-4
//!   (<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>).
//! - **Reference baseline** —
//!   <https://mcp.uor.foundation/tools/encode_address> κ-label fixtures.
//!
//! ## End-to-end through prism's typed-iso surface
//!
//! 1. The host-boundary parser [`JsonValue::parse`] consumes raw JSON
//!    bytes, validates every typed-input bound declared in
//!    [`shapes::bounds`], and emits a typed [`JsonValue`].
//! 2. [`AddressModel`]'s `forward()` invokes the ψ-chain verb
//!    [`address_inference`] end-to-end via foundation's catamorphism.
//!    The catamorphism dispatches each resolver-bound ψ-Term through
//!    [`AddressResolverTuple`] (ADR-036).
//! 3. The terminal ψ_9 resolver
//!    ([`AddressKInvariantResolver`]) calls
//!    [`crate::common::AddressInput::canonicalize_into`] on
//!    [`JsonValue`] inside its body (ADR-046's resolver-body
//!    iterative-resolution discipline) to materialize the
//!    JCS-RFC8785 plus Unicode-NFC canonical-form bytes, then
//!    projects them through `Sha256Hasher` in one σ-projection to
//!    derive the κ-label.
//! 4. [`address`] returns the [`crate::AddressLabel`] κ-label —
//!    well-formed `JsonValue` always yields exactly one label.
//!
//! ## Why this module exists
//!
//! Per ARCHITECTURE.md, UOR-ADDR is **a body of `PrismModel`
//! declarations** specialized to typed content-addressing across
//! formats with bounded recursive structural typing. Each format
//! ships its concrete specialization (this module for JSON;
//! [`crate::sexp`] for S-expressions; future modules per the
//! demand-driven clause of ADR-031). The common surface
//! ([`crate::common`]) names the shared trait, output shape, and
//! cost-model commitment; each format declares its own concrete
//! `prism_model!`, `verb!`, and `resolver!` invocations because the
//! SDK macros emit per-declaration types.

pub mod model;
pub mod pipeline;
pub mod resolvers;
pub mod shapes;
pub mod value;
pub mod verbs;

pub use model::{AddressModel, AddressRoute};
pub use pipeline::{address, AddressFailure, AddressOutcome, AddressWitness};
pub use resolvers::{
    AddressChainComplexResolver, AddressCochainComplexResolver, AddressCohomologyGroupResolver,
    AddressHomologyGroupResolver, AddressHomotopyGroupResolver, AddressKInvariantResolver,
    AddressNerveResolver, AddressPostnikovResolver, AddressResolverTuple,
};
pub use shapes::{
    AddrBounds, Sha256Hasher, JSON_VALUE_MAX_BYTES, MAX_ARRAY_ELEMENTS, MAX_JSON_DEPTH,
    MAX_NUMBER_DIGITS, MAX_OBJECT_KEYS, MAX_STRING_BYTES,
};
pub use value::{canonicalize, JsonValue, JsonValueRegistry};
pub use verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};
