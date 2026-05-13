//! `AddressModel` — `uor-addr-1`'s `PrismModel<H, B, A, R>` declaration
//! (wiki ADR-020 + ADR-036).
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
//! - [`JsonInput`] — the canonical-form JCS+NFC JSON byte sequence
//!   (variable length, capped at 4096 bytes per
//!   [`crate::shapes::AddrBounds::TERM_VALUE_MAX_BYTES`]). The
//!   PrismModel's `Input` type.
//! - [`AddressLabel`] — the ψ-pipeline label (71 W8 sites — the
//!   wire-format `sha256:<64hex>` width). The PrismModel's `Output`
//!   type.
//!
//! ## Wiki commitments validated
//!
//! - **ADR-020 PrismModel** — the four-position parametric model
//!   declaration `<H: HostTypes, B: HostBounds, A: AxisTuple + Hasher,
//!   R: ResolverTuple>` is realised by [`AddressModel`] via the
//!   `prism_model!` SDK macro.
//! - **ADR-027 sealed Output shapes** — [`AddressLabel`] is emitted via
//!   `output_shape!`, which the wiki commits to as the canonical
//!   sanctioned-construction path for `GroundedShape` types
//!   (`12-Glossary.md`).
//! - **Algebraic-closure encoding (ADR-024 / ADR-026)** — `AddressLabel`
//!   declares 71 disjoint `ConstraintRef::Site` constraints satisfying
//!   `χ(N(C)) = 71 = SITE_COUNT` and `β_k = 0` for k ≥ 1; the criterion
//!   is asserted at compile time in [`crate::resolvers`].
//! - **ADR-023 IntoBindingValue** — [`JsonInput`] carries variable
//!   length up to `MAX_BYTES` through the catamorphism's
//!   binding-table form per ADR-023's canonical
//!   content-addressable byte-sequence requirement.

extern crate alloc;

use alloc::vec::Vec;

use uor_foundation::enforcement::ShapeViolation;
use uor_foundation::pipeline::{ConstrainedTypeShape, ConstraintRef, IntoBindingValue};
use uor_foundation::{DefaultHostTypes, ViolationKind};
use uor_foundation_sdk::{output_shape, prism_model};

use crate::resolvers::AddressResolverTuple;
use crate::shapes::bounds::AddrBounds;
use crate::shapes::hasher::Sha256Hasher;

// Bring the verb's term-arena const + marker fn into scope.
#[allow(unused_imports)]
use crate::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

/// The wire-format address byte width: `sha256:` (7) + 64-hex (64) = 71.
pub const ADDRESS_LABEL_BYTES: usize = 71;

/// The maximum byte width of a canonical-form JCS+NFC JSON payload.
/// Sized to fit within [`crate::shapes::AddrBounds::TERM_VALUE_MAX_BYTES`]
/// after the ψ-stage carrier's 4-byte length prefix and 91-byte
/// geometry-tail header are accounted for. 3968 bytes = 4 KiB - 128
/// (4 prefix + 91 tail + 33 headroom).
pub const JSON_INPUT_MAX_BYTES: usize = 3968;

// ─── Input shape: JsonInput ─────────────────────────────────────────────

/// The canonical-form JSON byte sequence produced by the host-boundary
/// [`crate::ops::canonicalize::jcs_nfc`] transform. Variable length,
/// capped at [`JSON_INPUT_MAX_BYTES`].
///
/// The byte buffer is heap-allocated for ergonomic construction in the
/// host pipeline; on the foundation side, only `into_binding_bytes`'s
/// `out: &mut [u8]` is observed, so the runtime allocation does not
/// enter the typed-iso surface or any resolver carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonInput {
    /// Canonical-form bytes (JCS-RFC8785 + Unicode-NFC). Length ≤
    /// [`JSON_INPUT_MAX_BYTES`]; enforced at construction.
    pub bytes: Vec<u8>,
}

impl JsonInput {
    const LENGTH_VIOLATION: ShapeViolation = ShapeViolation {
        shape_iri: "https://uor.foundation/addr/JsonInput",
        constraint_iri: "https://uor.foundation/addr/JsonInput/maxBytes",
        property_iri: "https://uor.foundation/addr/JsonInput/byteCount",
        expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
        min_count: 0,
        max_count: JSON_INPUT_MAX_BYTES as u32,
        kind: ViolationKind::ValueCheck,
    };

    /// Construct from canonical-form bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Self::LENGTH_VIOLATION`] when `bytes.len() >
    /// JSON_INPUT_MAX_BYTES`.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ShapeViolation> {
        if bytes.len() > JSON_INPUT_MAX_BYTES {
            return Err(Self::LENGTH_VIOLATION);
        }
        Ok(Self { bytes })
    }
}

impl ConstrainedTypeShape for JsonInput {
    const IRI: &'static str = "https://uor.foundation/addr/JsonInput";
    // `SITE_COUNT` is the *maximum* byte width: each site is one W8 byte
    // of the canonical-form payload. Actual length is variable up to
    // this ceiling; `into_binding_bytes` returns the written length.
    const SITE_COUNT: usize = JSON_INPUT_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for JsonInput {}

impl IntoBindingValue for JsonInput {
    const MAX_BYTES: usize = JSON_INPUT_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if self.bytes.len() > out.len() {
            return Err(Self::LENGTH_VIOLATION);
        }
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

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
// the κ-derivation projecting the typed `JsonInput` through the
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

prism_model! {
    pub struct AddressModel;
    pub struct AddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        AddrBounds,
        Sha256Hasher,
        AddressResolverTuple<Sha256Hasher>
    > for AddressModel {
        type Input = JsonInput;
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

    #[test]
    fn json_input_round_trips_canonical_bytes() {
        let canonical = br#"{"foo":"bar"}"#.to_vec();
        let input = JsonInput::new(canonical.clone()).expect("within bounds");
        let mut out = [0u8; 4096];
        let n = input.into_binding_bytes(&mut out).expect("buffer fits");
        assert_eq!(n, canonical.len());
        assert_eq!(&out[..n], canonical.as_slice());
    }

    #[test]
    fn json_input_rejects_oversize() {
        let oversize = vec![0u8; JSON_INPUT_MAX_BYTES + 1];
        let err = JsonInput::new(oversize).expect_err("must reject oversize");
        assert_eq!(err.shape_iri, JsonInput::LENGTH_VIOLATION.shape_iri);
    }

    #[test]
    fn address_label_site_count_matches_wire_format_width() {
        assert_eq!(<AddressLabel as ConstrainedTypeShape>::SITE_COUNT, ADDRESS_LABEL_BYTES);
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
