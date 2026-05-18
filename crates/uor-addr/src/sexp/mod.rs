//! **`uor_addr::sexp` — the S-expression realization of UOR-ADDR**
//! (ARCHITECTURE.md "Format-specific realizations" § `uor-addr-sexp`).
//!
//! S-expression typed-input content-addressing under Rivest's
//! canonical S-expression form, with the σ-projection bound to
//! `prism::crypto::Sha256Hasher`.
//!
//! ## Authoritative sources
//!
//! - **Canonical S-expressions** — Ronald L. Rivest,
//!   *S-expressions*, May 4 1997 draft, archived at
//!   <https://people.csail.mit.edu/rivest/Sexp.txt>. I-D form at
//!   <https://datatracker.ietf.org/doc/html/draft-rivest-sexp-00>.
//! - **SPKI canonical form citation** — IETF RFC 2693 §3
//!   *SPKI Certificate Theory*
//!   (<https://datatracker.ietf.org/doc/html/rfc2693#section-3>).
//!   Test vectors at
//!   <https://datatracker.ietf.org/doc/html/rfc2693#section-11>.
//! - **SHA-256 σ-projection** — NIST FIPS 180-4
//!   (<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>).
//!
//! ## Why a second concrete realization?
//!
//! UOR-ADDR's architectural commitment is **one verb arena across
//! formats** — the canonical k-invariants branch (ADR-035) composing
//! ψ_1 + ψ_7 + ψ_8 + ψ_9. This module ships a second concrete
//! realization to prove the multi-format architecture works: the same
//! verb body, the same resolver-tuple shape (ψ_2..ψ_6 off-path with
//! identity-shaped carriers, ψ_1 + ψ_7 + ψ_8 + ψ_9 on-path through
//! the format's canonicalization), the same κ-derivation surface, the
//! same TC-05 replay round-trip. Only the typed-input shape `V`, the
//! canonicalization, the parser, and the `HostBounds` profile vary.
//!
//! ## Grammar
//!
//! ```text
//! SExprValue ::= Atom(bytes)            — symbolic atoms (UTF-8 bytes)
//!              | Cons(SExprValue, SExprValue)
//!              | Nil
//! ```
//!
//! The wire-format input is canonical S-expression syntax — atoms as
//! `[<length>]<bytes>` length-prefixed byte sequences (Rivest's
//! canonical S-expression form, mirroring SHA-512 personal sigs and
//! the `urn:ietf:rfc:2693` canonical form), cons as `(car cdr)`
//! parenthesized lists, nil as `()`. The parser admits the
//! Lisp-style sugared form `(a b c)` as nested cons cells
//! `Cons(a, Cons(b, Cons(c, Nil)))`.
//!
//! ## Canonicalization
//!
//! Walks the parser-emitted byte sequence and emits Rivest's
//! canonical S-expression form: atoms as `<n>:<bytes>` (raw length
//! prefix, no quoting), cons as `(car cdr)`. Idempotent on canonical
//! input.

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
    SExprAddrBounds, MAX_SEXPR_ATOM_BYTES, MAX_SEXPR_DEPTH, MAX_SEXPR_ELEMENTS,
    SEXPR_VALUE_MAX_BYTES,
};
pub use value::{canonicalize, SExprValue, SExprValueRegistry};
pub use verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};
