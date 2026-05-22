//! `gguf::AddressModel` — the GGUF realization's `PrismModel` declaration.
//! Mirrors [`crate::ring::model`] with `Input = GgufValue` and the
//! [`GgufAddrBounds`] capacity profile.

use prism::pipeline::{prism_model, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::gguf::resolvers::AddressResolverTuple;
use crate::gguf::shapes::bounds::GgufAddrBounds;
use crate::gguf::value::GgufValue;
use crate::label::AddressLabel;

#[allow(unused_imports)]
use crate::gguf::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

prism_model! {
    pub struct AddressModel;
    pub struct AddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        GgufAddrBounds,
        prism::crypto::Sha256Hasher,
        AddressResolverTuple<prism::crypto::Sha256Hasher>,
        EmptyCommitment
    > for AddressModel {
        type Input = GgufValue;
        type Output = AddressLabel;
        type Route = AddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            address_inference(input)
        }
    }
}
