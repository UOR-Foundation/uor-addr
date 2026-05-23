//! `sexp::AddressModel` — the S-expression realization's `PrismModel`
//! declaration, binding the shared [`AddrBounds`]
//! profile and the shared [`AddressResolverTuple`](crate::resolvers)
//! ψ-tower. The input is the ADR-060 stream-carrier handle
//! [`SExprValue`]; `prism_model!` threads the `'a` input-carrier lifetime
//! and derives the inline carrier width from the bounds.

use prism::pipeline::{prism_model, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::bounds::AddrBounds;
use crate::label::AddressLabel;
use crate::resolvers::AddressResolverTuple;
use crate::sexp::value::SExprValue;

#[allow(unused_imports)]
use crate::sexp::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

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
        type Input = SExprValue<'a>;
        type Output = AddressLabel;
        type Route = AddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            address_inference(input)
        }
    }
}
