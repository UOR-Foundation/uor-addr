//! `asn1::AddressModel` — the ASN.1 realization's `PrismModel`
//! declaration, binding the shared [`AddrBounds`]
//! profile and the shared [`AddressResolverTuple`](crate::resolvers)
//! ψ-tower. The input is the ADR-060 borrowed-carrier handle
//! [`Asn1Carrier`].

use prism::pipeline::{prism_model, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::asn1::value::Asn1Carrier;
use crate::bounds::AddrBounds;
use crate::label::AddressLabel;
use crate::resolvers::AddressResolverTuple;

#[allow(unused_imports)]
use crate::asn1::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

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
        type Input = Asn1Carrier<'a>;
        type Output = AddressLabel;
        type Route = AddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            address_inference(input)
        }
    }
}
