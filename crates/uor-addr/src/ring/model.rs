//! `ring::AddressModel` — the ring-element realization's
//! `PrismModel<H, B, A, R, C>` declaration (wiki ADR-020 + ADR-036 +
//! ADR-048 + ARCHITECTURE.md "Common PrismModel form").

use prism::pipeline::{prism_model, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::label::AddressLabel;
use crate::ring::resolvers::AddressResolverTuple;
use crate::ring::shapes::bounds::RingAddrBounds;
use crate::ring::value::RingElement;

#[allow(unused_imports)]
use crate::ring::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

prism_model! {
    pub struct AddressModel;
    pub struct AddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        RingAddrBounds,
        prism::crypto::Sha256Hasher,
        AddressResolverTuple<prism::crypto::Sha256Hasher>,
        EmptyCommitment
    > for AddressModel {
        type Input = RingElement;
        type Output = AddressLabel;
        type Route = AddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            address_inference(input)
        }
    }
}
