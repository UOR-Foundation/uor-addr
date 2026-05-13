//! `uor-addr-1` — the prism implementor for JSON content addressing.
//!
//! Content-address derivation end-to-end through prism's typed-iso
//! surface. The address transform is the canonical k-invariant branch
//! of the ψ-pipeline (wiki ADR-035) applied to the canonical-form JSON
//! byte sequence; foundation's catamorphism dispatches each
//! resolver-bound ψ-stage through [`resolvers::AddressResolverTuple`]
//! (ADR-036). No σ-enumeration in the verb body per ADR-035's
//! ψ-residuals discipline.
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
//! | ADR-007 / ADR-010 pluggable Hasher (foundation ships none) | [`Sha256Hasher`] (`impl Hasher<32>`, FIPS-180-4)          |
//! | ADR-018 / ADR-037 HostBounds capacity ceilings             | [`AddrBounds`] (24 ADR-037 constants)                     |
//! | ADR-020 PrismModel<H, B, A, R> declaration                 | [`AddressModel`] (via `prism_model!`)                     |
//! | ADR-024 implementation closure (verb!-emitted bodies)      | [`address_inference`] (via `verb!`)                       |
//! | ADR-027 sealed Output shape (output_shape!-emitted)        | [`AddressLabel`] (via `output_shape!`)                    |
//! | ADR-035 canonical k-invariants branch ψ_1 → ψ_7 → ψ_8 → ψ_9 | the verb body                                            |
//! | ADR-035 verb-body ψ-residuals discipline                   | `verbs::tests::verb_arena_contains_no_sigma_residuals`    |
//! | ADR-036 ResolverTuple (eight resolver categories)          | [`AddressResolverTuple<H>`] (via `resolver!`)             |
//! | ADR-041 typed-coordinate carriers                          | `SimplicialComplexBytes` … `HomotopyGroupsBytes` chain    |
//! | ADR-046 resolver-body iterative-resolution discipline      | hash-axis invocation inside [`AddressKInvariantResolver`] |
//! | TC-02 mechanism sealing                                    | [`AddressWitness`] borrows the sealed `Grounded<…>`       |
//! | Algebraic closure (ADR-024 / ADR-026)                      | 71 disjoint `Site` constraints; χ(N(C)) = 71 = SITE_COUNT |
//!
//! ## Quick reference
//!
//! - [`address`] — the public entry point: canonicalises raw JSON
//!   bytes, builds a [`JsonInput`], and invokes
//!   [`AddressModel::forward`].
//! - [`AddressModel`] — `PrismModel<HostTypes, HostBounds, Hasher,
//!   ResolverTuple>` whose route is `address_inference(input)`.
//! - [`JsonInput`] — the canonical-form JCS+NFC JSON byte sequence.
//! - [`AddressLabel`] — the ψ-pipeline label (71 W8 sites — the
//!   wire-format `sha256:<64hex>` width).
//! - [`Sha256Hasher`] — the canonical hash axis (content-addressing
//!   primitive).
//! - [`AddrBounds`] — the `HostBounds` profile (`WITT_LEVEL_MAX_BITS = 32`,
//!   `NERVE_SITES_MAX = 71`).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod model;
pub mod ops;
pub mod pipeline;
pub mod resolvers;
pub mod shapes;
pub mod verbs;

// Public façade — typed surface.
pub use model::{
    AddressLabel, AddressModel, AddressRoute, JsonInput, ADDRESS_LABEL_BYTES, JSON_INPUT_MAX_BYTES,
};
pub use pipeline::{address, AddressFailure, AddressOutcome, AddressWitness};
pub use resolvers::{
    AddressChainComplexResolver, AddressCochainComplexResolver, AddressCohomologyGroupResolver,
    AddressHomologyGroupResolver, AddressHomotopyGroupResolver, AddressKInvariantResolver,
    AddressNerveResolver, AddressPostnikovResolver, AddressResolverTuple,
};
pub use shapes::{AddrBounds, Sha256Hasher};

// Layer-3 verb declaration. `address_inference_term_arena()` returns
// the ψ-chain term-tree fragment foundation evaluates.
pub use verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

// Boundary helpers — not part of the ψ-pipeline transform.
pub use ops::canonicalize::jcs_nfc;
pub use ops::sha256::{sha256, SHA256_INITIAL_STATE};
