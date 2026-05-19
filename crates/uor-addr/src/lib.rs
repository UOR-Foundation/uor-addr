//! `uor-addr` — UOR-ADDR, the typed reference vocabulary for typed
//! content-addressing across recursively-grammared formats.
//!
//! UOR-ADDR sits at the standard-library layer per ADR-031: every
//! format-specific addressing realization shares the [`common`]
//! architectural surface — the [`AddressInput`] trait, the
//! [`AddressLabel`] output shape, the resolver-tuple shape, and the
//! `address_inference` verb body — while supplying its own concrete
//! `prism_model!`, `verb!`, `resolver!`, and `output_shape!`
//! specializations.
//!
//! ## Authoritative sources
//!
//! Every realization shipped in this crate cites the authoritative
//! standard for the canonical form it implements. The complete index
//! lives in [`STANDARDS.md`](https://github.com/UOR-Foundation/uor-addr/blob/main/STANDARDS.md);
//! each module's docstring carries the same citation inline.
//!
//! - JSON realization — RFC 8259 (syntax), RFC 8785 (canonical form),
//!   UAX #15 (NFC), FIPS 180-4 (SHA-256).
//! - S-expression realization — Rivest 1997 canonical S-expressions
//!   (`Sexp.txt`), RFC 2693 §3 (SPKI canonical form citation),
//!   FIPS 180-4 (SHA-256).
//! - Storage cost-model variant — ADR-048 typed-commitment surface,
//!   ADR-047 U6 bandwidth-additivity, QS-06 storage-tier admission
//!   exemplar.
//!
//! ## Module layout
//!
//! - [`common`] — the shared architectural surface (trait, V&V
//!   framing).
//! - [`label`] — the shared `AddressLabel` output shape
//!   (`https://uor.foundation/addr/AddressLabel/sha256`).
//! - **Format-specific realizations** — [`json`] (JCS-RFC8785 + NFC),
//!   [`sexp`] (Rivest 1997), [`xml`] (W3C XML-C14N 1.1 subset),
//!   [`asn1`] (X.690 DER), [`ring`] (UOR-Framework Amendment 43 §2),
//!   [`codemodule`] (CCMAS).
//! - **Schema-pinned descendants** — [`schema::photo`],
//!   [`schema::document`], [`schema::codemodule_signed`].
//! - **Cost-model-bearing variants** — [`variant::storage`]
//!   (`AndCommitment<…, LexicographicLessEqThreshold>`),
//!   [`variant::signed`] (`SingletonCommitment<UltrametricCloseTo<2>>`).
//!
//! ## What's shipped
//!
//! The full UOR-ADDR architectural surface — common trait + six
//! format-specific realizations + three schema-pinned descendants +
//! two cost-model-bearing variants. See
//! [`ARCHITECTURE.md`](https://github.com/UOR-Foundation/uor-addr/blob/main/ARCHITECTURE.md)
//! for the architectural commitments each realization upholds and
//! [`STANDARDS.md`](https://github.com/UOR-Foundation/uor-addr/blob/main/STANDARDS.md)
//! for the authoritative-source citations.
//!
//! ## Validation & verification against the wiki specification
//!
//! Each architectural commitment names the wiki ADR or concept it
//! satisfies. The wiki at
//! `https://github.com/UOR-Foundation/UOR-Framework/wiki` is the
//! normative source.
//!
//! | Wiki commitment                                            | Crate realisation                                                  |
//! |------------------------------------------------------------|--------------------------------------------------------------------|
//! | ADR-007 / ADR-010 pluggable Hasher (substrate ships none)  | [`json::Sha256Hasher`] — re-export of `prism::crypto::Sha256Hasher` |
//! | ADR-031 Prism standard library (`uor-prism` façade)        | `prism::pipeline` / `vocabulary` / `seal` / `crypto`                |
//! | ADR-018 / ADR-037 HostBounds capacity ceilings             | [`json::AddrBounds`] for the JSON realization                       |
//! | ADR-020 PrismModel<H, B, A, R, C> declaration              | [`json::AddressModel`] (and one per realization)                    |
//! | ADR-023 typed-iso input shape                              | [`json::JsonValue`] (and one per format)                            |
//! | ADR-024 implementation closure (verb!-emitted bodies)      | [`json::address_inference`] (one per realization)                   |
//! | ADR-027 sealed Output shape (output_shape!-emitted)        | [`AddressLabel`] (single sha256-axis specialization, shared)        |
//! | ADR-035 canonical k-invariants branch ψ_1 → ψ_7 → ψ_8 → ψ_9 | every realization's `address_inference` body                       |
//! | ADR-035 verb-body ψ-residuals discipline                   | `verb_arena_contains_no_sigma_residuals` test per realization       |
//! | ADR-036 ResolverTuple (eight resolver categories)          | [`json::AddressResolverTuple<H>`] (one per realization)             |
//! | ADR-041 typed-coordinate carriers                          | `SimplicialComplexBytes` … `HomotopyGroupsBytes` chain              |
//! | ADR-046 resolver-body iterative-resolution discipline      | `canonicalize_into` inside ψ_9's resolver body                      |
//! | ADR-048 TypedCommitment (5th model parameter)              | [`EmptyCommitment`] default; [`variant::storage`] non-default       |
//! | ADR-057 bounded recursive structural typing                | [`json::JsonValueRegistry`] (the `register_shape!`-emitted registry)|
//! | TC-02 mechanism sealing                                    | `AddressWitness` per realization borrows the sealed `Grounded<…>`    |
//! | TC-05 replay round-trip (anamorphism)                      | `tests/replay.rs` via `prism_verify::certify_from_trace`            |
//! | Algebraic closure (ADR-024 / ADR-026)                      | 71 disjoint `Site` constraints; χ(N(C)) = 71 = SITE_COUNT           |
//!
//! ## Quick reference
//!
//! - [`json::address`] — the JSON entry point: parses raw JSON bytes
//!   into a typed [`json::JsonValue`] and invokes the model's
//!   `forward()` method.
//! - [`sexp::address`] — the S-expression entry point.
//! - [`AddressInput`] — the common trait every realization implements.
//! - [`AddressLabel`] — the ψ-pipeline label (71 W8 sites — the
//!   wire-format `sha256:<64hex>` width).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
// Public docstrings link to crate-private symbols (UCD tables,
// resolver-internal ShapeViolation constants) to keep the wiki-style
// cross-references readable. These are intra-crate links, not broken
// links — the doc-check axis still denies `broken-intra-doc-links`,
// which catches actual rot.
#![allow(rustdoc::private_intra_doc_links)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod asn1;
pub mod canonical;
pub mod codemodule;
pub mod common;
pub mod json;
pub mod label;
pub mod outcome;
pub mod ring;
pub mod schema;
pub mod sexp;
pub mod variant;
pub mod xml;

// Common architectural surface re-exports (per ARCHITECTURE.md
// "What UOR-ADDR provides"). Downstream realizations consume these.
pub use common::AddressInput;
pub use label::{AddressLabel, KappaLabel, LabelDecodeError, ADDRESS_LABEL_BYTES};
pub use outcome::{AddressOutcome, AddressWitness};
pub use prism::pipeline::EmptyCommitment;

// JSON-realization re-exports at the crate root for backward
// compatibility and for the conventional "import the default
// realization at the root" pattern. Canonical path is
// `uor_addr::json::*`.
#[cfg(feature = "alloc")]
pub use json::canonicalize;
pub use json::{
    address, address_inference, AddrBounds, AddressFailure, AddressModel, AddressResolverTuple,
    AddressRoute, JsonValue, JsonValueRegistry, Sha256Hasher, JSON_VALUE_MAX_BYTES,
    MAX_ARRAY_ELEMENTS, MAX_JSON_DEPTH, MAX_NUMBER_DIGITS, MAX_OBJECT_KEYS, MAX_STRING_BYTES,
    VERB_TERMS_ADDRESS_INFERENCE,
};
