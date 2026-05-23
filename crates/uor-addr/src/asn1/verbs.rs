//! ASN.1 realization's ψ-chain content-address derivation
//! verb (wiki ADR-024 + ADR-035 + ADR-036 + ARCHITECTURE.md
//! "Common verb arena").
//!
//! The verb body is **identical at the term-arena level** to the
//! JSON realization's [`crate::json::address_inference`] — the
//! canonical k-invariants branch (ψ_1 → ψ_7 → ψ_8 → ψ_9). Only the
//! input type and (under instantiation) the resolver bodies vary;
//! the structural shape of the term arena is the same across every
//! UOR-ADDR realization.

use prism::pipeline::verb;

use crate::asn1::value::Asn1Carrier;
use crate::label::AddressLabel;

verb! {
    pub fn address_inference(input: Asn1Carrier<'_>) -> AddressLabel {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism::operation::Term;

    #[test]
    fn verb_term_arena_is_emitted_and_nonempty() {
        let arena = address_inference_term_arena::<{ crate::ADDR_INLINE_BYTES }>();
        assert!(!arena.is_empty());
    }

    #[test]
    fn verb_arena_contains_psi_1_nerve() {
        let arena = address_inference_term_arena::<{ crate::ADDR_INLINE_BYTES }>();
        assert!(arena.iter().any(|t| matches!(t, Term::Nerve { .. })));
    }

    #[test]
    fn verb_arena_contains_psi_7_postnikov_tower() {
        let arena = address_inference_term_arena::<{ crate::ADDR_INLINE_BYTES }>();
        assert!(arena
            .iter()
            .any(|t| matches!(t, Term::PostnikovTower { .. })));
    }

    #[test]
    fn verb_arena_contains_psi_8_homotopy_groups() {
        let arena = address_inference_term_arena::<{ crate::ADDR_INLINE_BYTES }>();
        assert!(arena
            .iter()
            .any(|t| matches!(t, Term::HomotopyGroups { .. })));
    }

    #[test]
    fn verb_arena_contains_psi_9_k_invariants() {
        let arena = address_inference_term_arena::<{ crate::ADDR_INLINE_BYTES }>();
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
