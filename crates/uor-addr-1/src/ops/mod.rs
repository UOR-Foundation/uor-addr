//! Runtime operation bodies — the σ-projection evaluators the host
//! boundary and the ψ-pipeline resolvers call.
//!
//! - [`sha256`] — pure-Rust FIPS-180-4 SHA-256 streaming + one-shot
//!   compression. Reused by [`crate::shapes::hasher::Sha256Hasher`].
//! - [`canonicalize`] — host-boundary JCS-RFC8785 + Unicode-NFC
//!   canonicalisation of an unstructured JSON byte sequence.
//!
//! ARCHITECTURAL NOTE — both modules contain only operational
//! evaluators. Neither emits `Term::AxisInvocation`; the canonical
//! hash axis is consumed inside the ψ_9 resolver body via
//! `H::initial().fold_bytes(…)` per wiki ADR-046's resolver-body
//! iterative-resolution discipline. The verb body itself has no
//! σ-enumeration per wiki ADR-035's ψ-residuals discipline.

pub mod canonicalize;
pub mod sha256;
