//! `AddressModel` — `uor-addr-1`'s `PrismModel<H, B, A, R, C>` declaration
//! (wiki ADR-020 + ADR-036 + ADR-048).
//!
//! The address-derivation inference is end-to-end prism: foundation's
//! catamorphism evaluates the ψ-chain verb arena
//! ([`crate::verbs::address_inference`]) dispatching each
//! resolver-bound ψ-Term through
//! [`crate::resolvers::AddressResolverTuple`]. There is no
//! σ-enumeration, no AxisInvocation in the verb body, no algorithmic
//! body in the typed-iso surface; the model declares the typed feature
//! hierarchy and the parametric tensor-algebra composition that
//! observes it.
//!
//! ## Typed feature hierarchy
//!
//! - [`crate::JsonValue`] — the typed JSON-value input shape
//!   (structurally-tagged byte form; depth + width bounds enforced at
//!   construction). The PrismModel's `Input` type.
//! - [`AddressLabel`] — the ψ-pipeline label (71 W8 sites — the
//!   wire-format `sha256:<64hex>` width). The PrismModel's `Output`
//!   type.
//!
//! ## Wiki commitments validated
//!
//! - **ADR-020 PrismModel** — the five-position parametric model
//!   declaration `<H: HostTypes, B: HostBounds, A: AxisTuple + Hasher,
//!   R: ResolverTuple, C: TypedCommitment>` is realised by
//!   [`AddressModel`] via the `prism_model!` SDK macro.
//! - **ADR-027 sealed Output shapes** — [`AddressLabel`] is emitted via
//!   `output_shape!`, which the wiki commits to as the canonical
//!   sanctioned-construction path for `GroundedShape` types
//!   (`12-Glossary.md`).
//! - **Algebraic-closure encoding (ADR-024 / ADR-026)** — `AddressLabel`
//!   declares 71 disjoint `ConstraintRef::Site` constraints satisfying
//!   `χ(N(C)) = 71 = SITE_COUNT` and `β_k = 0` for k ≥ 1; the criterion
//!   is asserted at compile time in [`crate::resolvers`].
//! - **ADR-023 IntoBindingValue** — [`crate::JsonValue`] carries its
//!   structurally-tagged byte form up to
//!   [`crate::shapes::JSON_VALUE_MAX_BYTES`] through the catamorphism's
//!   binding-table form per ADR-023's typed-iso input requirement.
//! - **ADR-048 TypedCommitment** — UOR-ADDR-1 selects
//!   `prism::pipeline::EmptyCommitment` for its `C` slot; the
//!   κ-derivation surface carries no auxiliary cost dimension.

extern crate alloc;

use prism::pipeline::{output_shape, prism_model, ConstraintRef, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::resolvers::AddressResolverTuple;
use crate::shapes::bounds::AddrBounds;
use crate::shapes::Sha256Hasher;
use crate::value::JsonValue;

// Bring the verb's term-arena const + marker fn into scope.
#[allow(unused_imports)]
use crate::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

/// The wire-format address byte width: `sha256:` (7) + 64-hex (64) = 71.
pub const ADDRESS_LABEL_BYTES: usize = 71;

// ─── Output shape: AddressLabel ─────────────────────────────────────────
//
// The ψ-pipeline label. Site count = 71 — exactly the wire-format
// `sha256:<64hex>` ASCII width. The terminal ψ_9 resolver
// ([`crate::resolvers::AddressKInvariantResolver`]) emits a 71-byte
// κ-label whose bytes ARE the wire-format content address by
// construction.
//
// **Algebraic-closure encoded** (wiki ADR-024 / ADR-026, plus the
// glossary entries "Closure (substrate)" / "Closure (prism)" in
// `12-Glossary.md`): the framework's canonical completeness
// criterion is χ(N(C)) = SITE_COUNT and β_k = 0 for k ≥ 1.
// `AddressLabel` declares 71 disjoint `Site` constraints — one per
// wire-format-label byte position. Each constraint pins exactly one
// site; site supports are pairwise disjoint; the constraint nerve
// N(C) is 71 isolated vertices with no higher simplices. Therefore:
//
//   β_0 = 71,    β_k = 0 for k ≥ 1
//   χ(N(C)) = β_0 - β_1 + … = 71 = SITE_COUNT
//
// The wiki's iterative-resolution discipline converges in n - χ(N(C))
// = 0 residual rank: at ψ_9 all 71 sites are pinned simultaneously by
// the κ-derivation projecting the typed `JsonValue` through the
// canonical hash axis. Sites 0..7 are template-pinned (the ASCII
// "sha256:" prefix); sites 7..71 are κ-pinned (the 64 lowercase-hex
// digits of the SHA-256 digest).
output_shape! {
    pub struct AddressLabel;
    impl ConstrainedTypeShape for AddressLabel {
        const IRI: &'static str = "https://uor.foundation/addr/AddressLabel";
        const SITE_COUNT: usize = 71;
        const CONSTRAINTS: &'static [ConstraintRef] = &[
            // 71 disjoint Site constraints — one per wire-format
            // address byte position.
            ConstraintRef::Site { position: 0 }, ConstraintRef::Site { position: 1 },
            ConstraintRef::Site { position: 2 }, ConstraintRef::Site { position: 3 },
            ConstraintRef::Site { position: 4 }, ConstraintRef::Site { position: 5 },
            ConstraintRef::Site { position: 6 }, ConstraintRef::Site { position: 7 },
            ConstraintRef::Site { position: 8 }, ConstraintRef::Site { position: 9 },
            ConstraintRef::Site { position: 10 }, ConstraintRef::Site { position: 11 },
            ConstraintRef::Site { position: 12 }, ConstraintRef::Site { position: 13 },
            ConstraintRef::Site { position: 14 }, ConstraintRef::Site { position: 15 },
            ConstraintRef::Site { position: 16 }, ConstraintRef::Site { position: 17 },
            ConstraintRef::Site { position: 18 }, ConstraintRef::Site { position: 19 },
            ConstraintRef::Site { position: 20 }, ConstraintRef::Site { position: 21 },
            ConstraintRef::Site { position: 22 }, ConstraintRef::Site { position: 23 },
            ConstraintRef::Site { position: 24 }, ConstraintRef::Site { position: 25 },
            ConstraintRef::Site { position: 26 }, ConstraintRef::Site { position: 27 },
            ConstraintRef::Site { position: 28 }, ConstraintRef::Site { position: 29 },
            ConstraintRef::Site { position: 30 }, ConstraintRef::Site { position: 31 },
            ConstraintRef::Site { position: 32 }, ConstraintRef::Site { position: 33 },
            ConstraintRef::Site { position: 34 }, ConstraintRef::Site { position: 35 },
            ConstraintRef::Site { position: 36 }, ConstraintRef::Site { position: 37 },
            ConstraintRef::Site { position: 38 }, ConstraintRef::Site { position: 39 },
            ConstraintRef::Site { position: 40 }, ConstraintRef::Site { position: 41 },
            ConstraintRef::Site { position: 42 }, ConstraintRef::Site { position: 43 },
            ConstraintRef::Site { position: 44 }, ConstraintRef::Site { position: 45 },
            ConstraintRef::Site { position: 46 }, ConstraintRef::Site { position: 47 },
            ConstraintRef::Site { position: 48 }, ConstraintRef::Site { position: 49 },
            ConstraintRef::Site { position: 50 }, ConstraintRef::Site { position: 51 },
            ConstraintRef::Site { position: 52 }, ConstraintRef::Site { position: 53 },
            ConstraintRef::Site { position: 54 }, ConstraintRef::Site { position: 55 },
            ConstraintRef::Site { position: 56 }, ConstraintRef::Site { position: 57 },
            ConstraintRef::Site { position: 58 }, ConstraintRef::Site { position: 59 },
            ConstraintRef::Site { position: 60 }, ConstraintRef::Site { position: 61 },
            ConstraintRef::Site { position: 62 }, ConstraintRef::Site { position: 63 },
            ConstraintRef::Site { position: 64 }, ConstraintRef::Site { position: 65 },
            ConstraintRef::Site { position: 66 }, ConstraintRef::Site { position: 67 },
            ConstraintRef::Site { position: 68 }, ConstraintRef::Site { position: 69 },
            ConstraintRef::Site { position: 70 },
        ];
    }
}

// ─── The PrismModel ─────────────────────────────────────────────────────
//
// Wiki ADR-048 adds `C: TypedCommitment` as the 5th model-declaration
// parameter (default `EmptyCommitment`). UOR-ADDR-1 explicitly selects
// `EmptyCommitment` — the κ-derivation surface has no auxiliary
// cost-model dimension beyond the SHA-256 σ-projection itself, and
// the JSON content-addressing problem carries no search-cost analogue
// to the `LexicographicLessEqThreshold` `TargetCommitment` alias.

prism_model! {
    pub struct AddressModel;
    pub struct AddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        AddrBounds,
        Sha256Hasher,
        AddressResolverTuple<Sha256Hasher>,
        EmptyCommitment
    > for AddressModel {
        type Input = JsonValue;
        type Output = AddressLabel;
        type Route = AddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            address_inference(input)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use prism::pipeline::{ConstrainedTypeShape, IntoBindingValue};

    #[test]
    fn json_value_parses_simple_object() {
        let v = JsonValue::parse(br#"{"foo":"bar"}"#).expect("valid");
        let mut out = [0u8; 4096];
        let n = v.into_binding_bytes(&mut out).expect("buffer fits");
        assert!(n > 0);
        assert!(n <= crate::shapes::JSON_VALUE_MAX_BYTES);
    }

    #[test]
    fn json_value_rejects_overdeep_nesting() {
        let mut s = alloc::string::String::new();
        for _ in 0..(crate::shapes::MAX_JSON_DEPTH + 4) {
            s.push('[');
        }
        for _ in 0..(crate::shapes::MAX_JSON_DEPTH + 4) {
            s.push(']');
        }
        let err = JsonValue::parse(s.as_bytes()).expect_err("must reject");
        assert!(err.constraint_iri.contains("depthBound"));
    }

    #[test]
    fn address_label_site_count_matches_wire_format_width() {
        assert_eq!(
            <AddressLabel as ConstrainedTypeShape>::SITE_COUNT,
            ADDRESS_LABEL_BYTES
        );
    }

    #[test]
    fn address_label_carries_seventy_one_disjoint_site_constraints() {
        let cs = <AddressLabel as ConstrainedTypeShape>::CONSTRAINTS;
        assert_eq!(cs.len(), 71, "71 Site constraints (algebraic-closure)");
        for c in cs {
            assert!(matches!(c, ConstraintRef::Site { .. }));
        }
    }

    #[test]
    fn address_label_constraints_pin_every_wire_format_site() {
        let cs = <AddressLabel as ConstrainedTypeShape>::CONSTRAINTS;
        let positions: Vec<u32> = cs
            .iter()
            .filter_map(|c| match c {
                ConstraintRef::Site { position } => Some(*position),
                _ => None,
            })
            .collect();
        assert_eq!(positions.len(), 71);
        for (i, &p) in positions.iter().enumerate() {
            assert_eq!(p, i as u32, "Site_{i} pins position {i}");
        }
    }
}
