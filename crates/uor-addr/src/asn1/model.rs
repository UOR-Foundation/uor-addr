//! `asn1::AddressModel` — the ASN.1 realization's
//! `PrismModel<H, B, A, R, C>` declaration (wiki ADR-020 + ADR-036 +
//! ADR-048 + ARCHITECTURE.md "Common PrismModel form").

use prism::pipeline::{prism_model, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::asn1::resolvers::AddressResolverTuple;
use crate::asn1::shapes::bounds::Asn1AddrBounds;
use crate::asn1::value::Asn1Value;
use crate::label::AddressLabel;

#[allow(unused_imports)]
use crate::asn1::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

prism_model! {
    pub struct AddressModel;
    pub struct AddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        Asn1AddrBounds,
        prism::crypto::Sha256Hasher,
        AddressResolverTuple<prism::crypto::Sha256Hasher>,
        EmptyCommitment
    > for AddressModel {
        type Input = Asn1Value;
        type Output = AddressLabel;
        type Route = AddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            address_inference(input)
        }
    }
}
