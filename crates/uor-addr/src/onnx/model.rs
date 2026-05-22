//! `gguf::AddressModel` — the ONNX realization's `PrismModel` declaration.
//! Mirrors [`crate::ring::model`] with `Input = OnnxValue` and the
//! [`OnnxAddrBounds`] capacity profile.

use prism::pipeline::{prism_model, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::onnx::resolvers::AddressResolverTuple;
use crate::onnx::shapes::bounds::OnnxAddrBounds;
use crate::onnx::value::OnnxValue;
use crate::label::AddressLabel;

#[allow(unused_imports)]
use crate::onnx::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

prism_model! {
    pub struct AddressModel;
    pub struct AddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        OnnxAddrBounds,
        prism::crypto::Sha256Hasher,
        AddressResolverTuple<prism::crypto::Sha256Hasher>,
        EmptyCommitment
    > for AddressModel {
        type Input = OnnxValue;
        type Output = AddressLabel;
        type Route = AddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            address_inference(input)
        }
    }
}
