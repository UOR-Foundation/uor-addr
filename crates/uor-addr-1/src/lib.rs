//! `uor-addr-1` — the prism implementor for JSON content addressing.
//!
//! Content-address derivation end-to-end through prism's typed-iso
//! surface. The PrismModel's `Input` is the typed [`JsonValue`] —
//! an RFC 8259 JSON value of bounded depth and width, carried as a
//! structurally-tagged byte serialization. The address transform is
//! the canonical k-invariant branch of the ψ-pipeline (wiki ADR-035);
//! foundation's catamorphism dispatches each resolver-bound ψ-stage
//! through [`resolvers::AddressResolverTuple`] (ADR-036). The
//! JCS-RFC8785 plus Unicode NFC canonicalisation runs **inside** the
//! typed-iso surface (admitted by the ψ_9 resolver body per ADR-046);
//! the verb body contains no σ-residuals per ADR-035.
//!
//! ## Validation & verification against the wiki specification
//!
//! Each architectural commitment names the wiki ADR or concept it
//! satisfies. The wiki at
//! `https://github.com/UOR-Foundation/UOR-Framework/wiki` is the
//! normative source; this crate is one V&V instance on the JSON
//! content-addressing problem.
//!
//! | Wiki commitment                                            | Crate realisation                                         |
//! |------------------------------------------------------------|-----------------------------------------------------------|
//! | ADR-007 / ADR-010 pluggable Hasher (substrate ships none)  | [`Sha256Hasher`] — re-export of `prism::crypto::Sha256Hasher` |
//! | ADR-031 Prism standard library (`uor-prism` façade)        | `prism::pipeline` / `vocabulary` / `seal` / `crypto`       |
//! | ADR-018 / ADR-037 HostBounds capacity ceilings             | [`AddrBounds`] (24 ADR-037 constants + typed-input bounds) |
//! | ADR-020 PrismModel<H, B, A, R, C> declaration              | [`AddressModel`] (via `prism_model!`); `C = EmptyCommitment` |
//! | ADR-023 typed-iso input shape                              | [`JsonValue`] — partition-coproduct over the 6 JSON cases  |
//! | ADR-024 implementation closure (verb!-emitted bodies)      | [`address_inference`] (via `verb!`)                       |
//! | ADR-027 sealed Output shape (output_shape!-emitted)        | [`AddressLabel`] (via `output_shape!`)                    |
//! | ADR-035 canonical k-invariants branch ψ_1 → ψ_7 → ψ_8 → ψ_9 | the verb body                                            |
//! | ADR-035 verb-body ψ-residuals discipline                   | `verbs::tests::verb_arena_contains_no_sigma_residuals`    |
//! | ADR-036 ResolverTuple (eight resolver categories)          | [`AddressResolverTuple<H>`] (via `resolver!`)             |
//! | ADR-041 typed-coordinate carriers                          | `SimplicialComplexBytes` … `HomotopyGroupsBytes` chain    |
//! | ADR-046 resolver-body iterative-resolution discipline      | JCS+NFC canonicalisation + hash-axis invocation inside [`AddressKInvariantResolver`] |
//! | ADR-048 TypedCommitment (5th model parameter)              | [`EmptyCommitment`] — UOR-ADDR-1 carries no auxiliary cost surface beyond the κ-derivation |
//! | TC-02 mechanism sealing                                    | [`AddressWitness`] borrows the sealed `Grounded<…>`       |
//! | TC-05 replay round-trip (anamorphism)                      | `tests/replay.rs` via `prism_verify::certify_from_trace`  |
//! | Algebraic closure (ADR-024 / ADR-026)                      | 71 disjoint `Site` constraints; χ(N(C)) = 71 = SITE_COUNT |
//!
//! ## Quick reference
//!
//! - [`address`] — the public entry point: parses raw JSON bytes
//!   into a typed [`JsonValue`] (validating depth + width bounds) and
//!   invokes the model's `forward()` method.
//! - [`AddressModel`] — `PrismModel<HostTypes, HostBounds, Hasher,
//!   ResolverTuple, TypedCommitment>` whose route is
//!   `address_inference(input)` and whose `C = EmptyCommitment`.
//! - [`JsonValue`] — the typed JSON-value input shape.
//! - [`AddressLabel`] — the ψ-pipeline label (71 W8 sites — the
//!   wire-format `sha256:<64hex>` width).
//! - [`Sha256Hasher`] — the canonical hash axis (content-addressing
//!   primitive).
//! - [`AddrBounds`] — the `HostBounds` profile (`WITT_LEVEL_MAX_BITS = 32`,
//!   `NERVE_SITES_MAX = 71`) plus typed-input bounds
//!   (`MAX_JSON_DEPTH`, `MAX_STRING_BYTES`, …).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod model;
pub mod pipeline;
pub mod resolvers;
pub mod shapes;
pub mod value;
pub mod verbs;

// Public façade — typed surface.
pub use model::{AddressLabel, AddressModel, AddressRoute, ADDRESS_LABEL_BYTES};
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
pub use value::{canonicalize, JsonValue};

// Re-export the cost-model commitment selection so downstream
// consumers can reach the wiki ADR-048 type without depending on
// `uor-prism` directly.
pub use prism::pipeline::EmptyCommitment;

// Layer-3 verb declaration. `address_inference_term_arena()` returns
// the ψ-chain term-tree fragment foundation evaluates.
pub use verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};
