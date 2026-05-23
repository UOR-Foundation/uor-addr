//! GGUF realization's ψ-chain content-address derivation verb. Identical
//! at the term-arena level to [`crate::ring::verbs`] — the canonical
//! k-invariants branch ψ_1 → ψ_7 → ψ_8 → ψ_9 — over `Input = GgufValue`.

use prism::pipeline::verb;

use crate::gguf::value::GgufCarrier;
use crate::label::AddressLabel;

verb! {
    pub fn address_inference(input: GgufCarrier<'_>) -> AddressLabel {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism::operation::Term;

    #[test]
    fn verb_arena_is_canonical_k_invariants_branch() {
        let arena = address_inference_term_arena::<{ crate::ADDR_INLINE_BYTES }>();
        assert!(!arena.is_empty());
        assert!(arena.iter().any(|t| matches!(t, Term::Nerve { .. })));
        assert!(arena
            .iter()
            .any(|t| matches!(t, Term::PostnikovTower { .. })));
        assert!(arena
            .iter()
            .any(|t| matches!(t, Term::HomotopyGroups { .. })));
        assert!(arena.iter().any(|t| matches!(t, Term::KInvariants { .. })));
    }

    #[test]
    fn verb_arena_contains_no_sigma_residuals() {
        let arena = address_inference_term_arena::<{ crate::ADDR_INLINE_BYTES }>();
        assert!(!arena.iter().any(|t| matches!(t, Term::FirstAdmit { .. })));
        assert!(!arena
            .iter()
            .any(|t| matches!(t, Term::AxisInvocation { .. })));
    }
}
