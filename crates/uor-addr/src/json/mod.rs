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
//! ## End-to-end through prism's typed-iso surface (ADR-060)
//!
//! 1. [`canonicalize`] parses raw JSON and emits the JCS-RFC8785 +
//!    Unicode-NFC canonical-form bytes into an `alloc` buffer at the host
//!    boundary (object members sorted by key; no width / count caps).
//! 2. [`address`] wraps those bytes in the borrowed [`JsonCarrier`] and
//!    runs [`AddressModel`]'s `forward()`: the ψ-chain verb
//!    [`address_inference`] threads the carrier through the shared
//!    [`AddressResolverTuple`] (ADR-036), and ψ₉ folds the canonical
//!    bytes through `Sha256Hasher` in one σ-projection to derive the
//!    κ-label.
//! 3. [`address`] returns the [`crate::AddressOutcome`] carrying the
//!    [`crate::AddressLabel`] κ-label + replayable TC-05 witness —
//!    well-formed JSON always yields exactly one label.
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
pub mod shapes;
pub mod value;
pub mod verbs;

pub use model::{
    AddressModel, AddressModelBlake3, AddressModelKeccak256, AddressModelSha3_256, AddressRoute,
};
#[cfg(feature = "alloc")]
pub use pipeline::{address, address_blake3, address_keccak256, address_sha3_256};
pub use pipeline::{AddressFailure, AddressOutcome, AddressWitness, VerifyError};
pub use shapes::{Sha256Hasher, MAX_JSON_DEPTH};
pub use value::JsonCarrier;
#[cfg(feature = "alloc")]
pub use value::{canonicalize, ArrayIter, JsonValue, JsonValueRef, ObjectIter};
pub use verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

/// The shared `AddrBounds` capacity profile (re-exported for the wiki
/// cross-references; canonical path is [`crate::bounds::AddrBounds`]).
pub use crate::bounds::AddrBounds;
/// The shared, format-independent ψ-tower (re-exported for convenience;
/// canonical path is [`crate::resolvers::AddressResolverTuple`]).
pub use crate::resolvers::AddressResolverTuple;
