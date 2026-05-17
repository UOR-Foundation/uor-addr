//! Host-boundary operation bodies — the σ-projection evaluators the
//! host runs **before** constructing the typed `JsonInput`.
//!
//! - [`canonicalize`] — host-boundary JCS-RFC8785 + Unicode-NFC
//!   canonicalisation of an unstructured JSON byte sequence.
//!
//! ARCHITECTURAL NOTE — `ops::` contains only host-boundary
//! evaluators. The canonical hash axis is consumed inside the ψ_9
//! resolver body via `H::initial().fold_bytes(…)` per wiki ADR-046's
//! resolver-body iterative-resolution discipline; the axis impl is
//! `prism::crypto::Sha256Hasher` (re-exported from [`crate::shapes`]),
//! so this crate carries no bespoke SHA-256 evaluator of its own. The
//! verb body has no σ-enumeration per wiki ADR-035's ψ-residuals
//! discipline.

pub mod canonicalize;
