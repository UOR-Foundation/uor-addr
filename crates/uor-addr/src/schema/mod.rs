//! **`uor_addr::schema` — UOR-ADDR's schema-pinned descendants**
//! (ARCHITECTURE.md "Schema-pinned descendants").
//!
//! Every descendant in this module specializes one of UOR-ADDR's
//! format-specific realizations by adding **schema-specific
//! admission predicates** (required fields, value-range constraints,
//! cross-field structural constraints) at the host-boundary parser.
//! The ψ-pipeline and the κ-derivation surface are unchanged from
//! the underlying format's realization — schema admission applies
//! at parse time per SD2 Grounding, before the typed-iso surface.
//!
//! A schema is a substitution-axis selection per
//! ADR-007 / ADR-030 / ADR-052 declaring the typed feature
//! hierarchy's domain-specific refinement.
//!
//! ## Shipped descendants
//!
//! - [`photo`] — Photo content-addressing, schema-pinned over the
//!   JSON realization. Required fields: `subject`, `captured_at`,
//!   `location`, `camera_make`, `camera_model`, `content_hash`,
//!   `provenance`.
//! - [`document`] — Document content-addressing, schema-pinned over
//!   the JSON realization. Required fields: `title`, `authors`,
//!   `version`, `sections`, `citations`.
//! - [`codemodule_signed`] — Signed code-module content-addressing,
//!   schema-pinned over the code-module AST realization. Adds a
//!   signature requirement: the input AST's top-level Module must
//!   contain a `signature` item carrying signature bytes over the
//!   canonical AST bytes minus the signature item itself.

pub mod codemodule_signed;
pub mod document;
pub mod photo;
