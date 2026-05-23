//! `ring::AddressModel` — the ring-element realization's `PrismModel`
//! declaration, binding the shared [`AddrBounds`]
//! profile and the shared [`AddressResolverTuple`](crate::resolvers)
//! ψ-tower. `prism_model!` derives the ADR-060 `INLINE_BYTES` carrier
//! width from the bounds and threads the `'a` input-carrier lifetime.

use prism::pipeline::{prism_model, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::bounds::AddrBounds;
use crate::label::AddressLabel;
use crate::resolvers::AddressResolverTuple;
use crate::ring::value::RingElement;

#[allow(unused_imports)]
use crate::ring::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

prism_model! {
    pub struct AddressModel;
    pub struct AddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        AddrBounds,
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
