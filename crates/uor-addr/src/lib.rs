//! `uor-addr` — UOR-ADDR, the typed reference vocabulary for typed
//! content-addressing across recursively-grammared formats.
//!
//! UOR-ADDR sits at the standard-library layer per ADR-031: every
//! format-specific addressing realization shares the [`common`]
//! architectural surface — the [`AddressInput`] trait, the single
//! [`AddrBounds`] capacity profile, the single [`AddressLabel`] output
//! shape, and the single format-independent [`AddressResolverTuple`]
//! ψ-tower — while supplying its own concrete `prism_model!` + `verb!`
//! plus a canonical-form input handle (ADR-060: the handle's
//! `as_binding_value` produces the canonical bytes as a source-
//! polymorphic [`prism::operation::TermValue`] carrier, so the ψ-tower is
//! shared verbatim and there is no fixed input buffer or size cap).
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
//! | ADR-018 / ADR-037 HostBounds capacity profile              | the single shared [`AddrBounds`] (every realization binds it)       |
//! | ADR-020 PrismModel<H, B, A, R, C> declaration              | [`json::AddressModel`] (and one per realization)                    |
//! | ADR-023 typed-iso input shape                              | [`json::JsonValue`] (and one per format)                            |
//! | ADR-024 implementation closure (verb!-emitted bodies)      | [`json::address_inference`] (one per realization)                   |
//! | ADR-027 sealed Output shape (output_shape!-emitted)        | [`AddressLabel`] (single sha256-axis specialization, shared)        |
//! | ADR-035 canonical k-invariants branch ψ_1 → ψ_7 → ψ_8 → ψ_9 | every realization's `address_inference` body                       |
//! | ADR-035 verb-body ψ-residuals discipline                   | `verb_arena_contains_no_sigma_residuals` test per realization       |
//! | ADR-036 ResolverTuple (eight resolver categories)          | the single shared [`AddressResolverTuple`] (format-independent)     |
//! | ADR-046 canonicalization at carrier production             | each input handle's `as_binding_value` (host boundary, not ψ_9)     |
//! | ADR-048 TypedCommitment (5th model parameter)              | [`EmptyCommitment`] default; [`variant::storage`] non-default       |
//! | ADR-057 bounded recursive structural typing                | the recursive parsers' native-stack depth guards (`MAX_*_DEPTH`)    |
//! | ADR-060 source-polymorphic value carrier (no fixed buffer) | input handles yield `Inline`/`Borrowed`/`Stream` [`prism::operation::TermValue`] |
//! | TC-02 mechanism sealing                                    | [`AddressWitness`] owns the replayable `Trace<256>` + fingerprint   |
//! | TC-05 replay round-trip (anamorphism)                      | [`AddressWitness::verify`] via `prism::replay::certify_from_trace`   |
//! | Algebraic closure (ADR-024 / ADR-026)                      | 71 disjoint `Site` constraints; χ(N(C)) = 71 = SITE_COUNT           |
//!
//! ## Quick reference
//!
//! - [`json::address`] — the JSON entry point: canonicalizes raw JSON
//!   bytes (JCS-RFC8785 + NFC) and folds the borrowed canonical form
//!   through the model's `forward()` method.
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

// ── Shared architectural surface (ADR-060 single capacity profile +
//    format-independent ψ-tower). ──
pub mod bounds;
pub mod canonical;
pub mod common;
pub mod label;
pub mod outcome;
pub mod resolvers;

// ── Format-specific realizations. ──
// Each binds the shared `bounds::AddrBounds` + `resolvers` ψ-tower and
// supplies a canonical-form input handle whose `as_binding_value`
// produces the ADR-060 carrier (Inline / Borrowed / Stream). `gguf` and
// `onnx` are feature-gated (they pull the `uor-prism-tensor` dtype dep
// and need `alloc` for their skeleton buffers).
pub mod asn1;
pub mod codemodule;
#[cfg(feature = "gguf")]
pub mod gguf;
pub mod json;
#[cfg(feature = "onnx")]
pub mod onnx;
pub mod ring;
pub mod schema;
pub mod sexp;
pub mod variant;
pub mod xml;

// Common architectural surface re-exports.
pub use bounds::{AddrBounds, ADDR_INLINE_BYTES};
pub use common::AddressInput;
pub use label::{AddressLabel, KappaLabel, LabelDecodeError, ADDRESS_LABEL_BYTES};
pub use outcome::{AddressOutcome, AddressWitness, VerifyError};
pub use prism::pipeline::EmptyCommitment;
pub use resolvers::AddressResolverTuple;

/// Canonical `Hasher<32>` σ-axis selection (re-export of
/// `prism::crypto::Sha256Hasher`); every shipped realization binds it.
pub use prism::crypto::Sha256Hasher;
