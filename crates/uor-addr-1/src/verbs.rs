//! `uor-addr-1`'s ψ-chain content-address derivation verb
//! (wiki ADR-024, ADR-035, ADR-036).
//!
//! The address-derivation inference is the **k-invariant branch** of
//! the ψ-pipeline applied to a `JsonInput`:
//!
//! ```text
//! JsonInput  (canonical-form JCS+NFC bytes)
//!    ↓ ψ_1 Nerve            (Constraints → SimplicialComplex)
//!    ↓ ψ_7 PostnikovTower   (SimplicialComplex → PostnikovTower)
//!    ↓ ψ_8 HomotopyGroups   (PostnikovTower → HomotopyGroups)
//!    ↓ ψ_9 KInvariants      (HomotopyGroups → KInvariants)
//! AddressLabel — the κ-label (71-byte `sha256:<64hex>`)
//! ```
//!
//! k-invariants `κ_k` are the universal classifying invariants of the
//! Postnikov tower, and the typed-iso surface of a wire-format-valid
//! content address is naturally characterized by its k-invariant
//! signature. Foundation's catamorphism evaluates the chain end-to-end
//! via the application's `ResolverTuple`
//! ([`crate::resolvers::AddressResolverTuple`]).
//!
//! ## Pure-prism commitment — wiki ADR-035 ψ-residuals discipline
//!
//! The verb body composes only ψ-Term variants (`Term::Nerve /
//! PostnikovTower / HomotopyGroups / KInvariants`); the canonical
//! hash axis is consumed by ψ_9's resolver
//! ([`crate::resolvers::AddressKInvariantResolver`]), **never** by
//! the verb body's term composition. No `Term::AxisInvocation`, no
//! `Term::FirstAdmit`, no σ-residual byte-comparison ops. ADR-035
//! commits this discipline at the verb-body level; ADR-046 admits
//! σ-residuals at the resolver-body level. The test
//! `verb_arena_contains_no_sigma_residuals` pins the wiki-level
//! discipline by walking the emitted `Term` arena.
//!
//! ## What this verb deliberately is not
//!
//! - **Not** a `dispatch_kernel` invocation of a custom
//!   `ContentAddressingAxis`. The earlier framing of UOR-ADDR-1 as
//!   such an axis violates ADR-035's ψ-residuals discipline: axis
//!   invocations belong inside resolver bodies per ADR-046, not in
//!   the typed-iso surface.
//! - **Not** an enumerator. There is no σ-enumeration anywhere — the
//!   ψ-pipeline maps the typed canonical-form bytes to the κ-label
//!   by structural transformation in exactly one σ-projection (the
//!   `H::initial().fold_bytes(bytes).finalize()` invocation inside
//!   the ψ_9 resolver body, sanctioned by ADR-046).

use uor_foundation_sdk::verb;

use crate::model::{AddressLabel, JsonInput};

verb! {
    pub fn address_inference(input: JsonInput) -> AddressLabel {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uor_foundation::enforcement::Term;

    #[test]
    fn verb_term_arena_is_emitted_and_nonempty() {
        let arena = address_inference_term_arena();
        assert!(!arena.is_empty());
    }

    #[test]
    fn verb_arena_contains_psi_1_nerve() {
        let arena = address_inference_term_arena();
        assert!(arena.iter().any(|t| matches!(t, Term::Nerve { .. })));
    }

    #[test]
    fn verb_arena_contains_psi_7_postnikov_tower() {
        let arena = address_inference_term_arena();
        assert!(arena
            .iter()
            .any(|t| matches!(t, Term::PostnikovTower { .. })));
    }

    #[test]
    fn verb_arena_contains_psi_8_homotopy_groups() {
        let arena = address_inference_term_arena();
        assert!(arena
            .iter()
            .any(|t| matches!(t, Term::HomotopyGroups { .. })));
    }

    #[test]
    fn verb_arena_contains_psi_9_k_invariants() {
        let arena = address_inference_term_arena();
        assert!(arena.iter().any(|t| matches!(t, Term::KInvariants { .. })));
    }

    #[test]
    fn verb_arena_contains_no_sigma_residuals() {
        // Wiki ADR-035 ψ-residuals discipline: no σ-enumeration in the
        // verb body. The arena must contain none of FirstAdmit, Le,
        // Concat, or AxisInvocation. The canonical hash axis is
        // consumed by resolvers per ADR-046's discipline boundary —
        // never by the verb body's term composition.
        let arena = address_inference_term_arena();
        let has_first_admit = arena.iter().any(|t| matches!(t, Term::FirstAdmit { .. }));
        let has_axis_invocation = arena
            .iter()
            .any(|t| matches!(t, Term::AxisInvocation { .. }));
        let has_le_or_concat = arena.iter().any(|t| {
            matches!(
                t,
                Term::Application {
                    operator: uor_foundation::PrimitiveOp::Le
                        | uor_foundation::PrimitiveOp::Concat
                        | uor_foundation::PrimitiveOp::Lt
                        | uor_foundation::PrimitiveOp::Ge
                        | uor_foundation::PrimitiveOp::Gt,
                    ..
                }
            )
        });
        assert!(
            !has_first_admit,
            "FirstAdmit is a σ-enumeration residual — must not appear in the pure-prism verb body"
        );
        assert!(
            !has_axis_invocation,
            "AxisInvocation belongs in resolvers, not in the verb body's composition"
        );
        assert!(
            !has_le_or_concat,
            "byte-comparison/concat ops are σ-residuals — admission is structural"
        );
    }
}
