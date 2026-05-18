//! `codemodule::AddressModel` — the code-module AST realization's
//! `PrismModel<H, B, A, R, C>` declaration (wiki ADR-020 + ADR-036 +
//! ADR-048 + ARCHITECTURE.md "Common PrismModel form").

use prism::pipeline::{prism_model, EmptyCommitment};
use prism::vocabulary::DefaultHostTypes;

use crate::codemodule::resolvers::AddressResolverTuple;
use crate::codemodule::shapes::bounds::CodeModuleAddrBounds;
use crate::codemodule::value::CodeModuleValue;
use crate::label::AddressLabel;

#[allow(unused_imports)]
use crate::codemodule::verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};

prism_model! {
    pub struct AddressModel;
    pub struct AddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        CodeModuleAddrBounds,
        prism::crypto::Sha256Hasher,
        AddressResolverTuple<prism::crypto::Sha256Hasher>,
        EmptyCommitment
    > for AddressModel {
        type Input = CodeModuleValue;
        type Output = AddressLabel;
        type Route = AddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            address_inference(input)
        }
    }
}
