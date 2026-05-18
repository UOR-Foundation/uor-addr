//! `json::AddressModel` — the JSON realization's `PrismModel<H, B, A,
//! R, C>` declaration (wiki ADR-020 + ADR-036 + ADR-048).
//!
//! The address-derivation inference is end-to-end prism: foundation's
//! catamorphism evaluates the ψ-chain verb arena
//! ([`crate::json::address_inference`]) dispatching each
//! resolver-bound ψ-Term through
//! [`crate::json::AddressResolverTuple`]. There is no σ-enumeration,
//! no AxisInvocation in the verb body, no algorithmic body in the
//! typed-iso surface; the model declares the typed feature hierarchy
//! and the parametric tensor-algebra composition that observes it.
//!
//! ## Typed feature hierarchy
//!
//! - [`crate::json::JsonValue`] — the typed JSON-value input shape
//!   (structurally-tagged byte form; depth + width bounds enforced
//!   at construction). The PrismModel's `Input` type.
//! - [`crate::AddressLabel`] — the ψ-pipeline label (71 W8 sites —
//!   the wire-format `sha256:<64hex>` width). The PrismModel's
//!   `Output` type, shared across all UOR-ADDR realizations binding
//!   `H = Sha256Hasher`.
//!
//! ## Wiki commitments validated
//!
//! - **ADR-020 PrismModel** — the five-position parametric model
//!   declaration `<H: HostTypes, B: HostBounds, A: AxisTuple + Hasher,
//!   R: ResolverTuple, C: TypedCommitment>` is realised by
//!   [`AddressModel`] via the `prism_model!` SDK macro.
//! - **ADR-023 IntoBindingValue** — [`crate::json::JsonValue`]
//!   carries its structurally-tagged byte form up to
//!   [`crate::json::JSON_VALUE_MAX_BYTES`] through the catamorphism's
//!   binding-table form per ADR-023's typed-iso input requirement.
//! - **ADR-048 TypedCommitment** — this realization binds
//!   `prism::pipeline::EmptyCommitment` for its `C` slot; the
//!   κ-derivation surface carries no auxiliary cost dimension. The
//!   [`crate::variant::storage`] module ships the
//!   cost-model-bearing variant binding
//!   `AndCommitment<EmptyCommitment, PayloadCommitment<K>>` per
//!   QS-06.

use prism::pipeline::{prism_model, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::json::resolvers::AddressResolverTuple;
use crate::json::shapes::bounds::AddrBounds;
use crate::json::shapes::Sha256Hasher;
use crate::json::value::JsonValue;
use crate::label::AddressLabel;

// Bring the verb's term-arena const + marker fn into scope.
#[allow(unused_imports)]
use crate::json::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

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
    use crate::json::shapes;
    use prism::pipeline::IntoBindingValue;

    #[test]
    fn json_value_parses_simple_object() {
        let v = JsonValue::parse(br#"{"foo":"bar"}"#).expect("valid");
        let mut out = [0u8; 4096];
        let n = v.into_binding_bytes(&mut out).expect("buffer fits");
        assert!(n > 0);
        assert!(n <= shapes::JSON_VALUE_MAX_BYTES);
    }

    #[test]
    fn json_value_rejects_overdeep_nesting() {
        let mut s = alloc::string::String::new();
        for _ in 0..(shapes::MAX_JSON_DEPTH + 4) {
            s.push('[');
        }
        for _ in 0..(shapes::MAX_JSON_DEPTH + 4) {
            s.push(']');
        }
        let err = JsonValue::parse(s.as_bytes()).expect_err("must reject");
        assert!(err.constraint_iri.contains("depthBound"));
    }
}
