//! `json::AddressModel*` — the JSON realization's `PrismModel`
//! declarations, one per admissible σ-axis ([`crate::hash`]). Each binds
//! the shared [`AddrBounds`](crate::bounds::AddrBounds) profile and the
//! shared [`AddressResolverTuple`](crate::resolvers) ψ-tower; the input is
//! the ADR-060 borrowed-carrier handle [`JsonCarrier`]. `AddressModel`
//! (sha256) is the default; `AddressModelBlake3` / `AddressModelSha3_256` /
//! `AddressModelKeccak256` bind the other 32-byte axes.

use crate::json::value::JsonCarrier;
#[allow(unused_imports)]
use crate::json::verbs::{
    address_inference, address_inference_blake3, address_inference_keccak256,
    address_inference_sha3_256, VERB_TERMS_ADDRESS_INFERENCE, VERB_TERMS_ADDRESS_INFERENCE_BLAKE3,
    VERB_TERMS_ADDRESS_INFERENCE_KECCAK256, VERB_TERMS_ADDRESS_INFERENCE_SHA3_256,
};
use crate::label::{
    AddressLabelBlake3, AddressLabelKeccak256, AddressLabelSha256, AddressLabelSha3_256,
};

addr_models! {
    input: JsonCarrier<'a>,
    {
        hasher: prism::crypto::Sha256Hasher,
        shape: AddressLabelSha256,
        model: AddressModel,
        route: AddressRoute,
        verb: address_inference
    },
    {
        hasher: prism::crypto::Blake3Hasher,
        shape: AddressLabelBlake3,
        model: AddressModelBlake3,
        route: AddressRouteBlake3,
        verb: address_inference_blake3
    },
    {
        hasher: prism::crypto::Sha3_256Hasher,
        shape: AddressLabelSha3_256,
        model: AddressModelSha3_256,
        route: AddressRouteSha3_256,
        verb: address_inference_sha3_256
    },
    {
        hasher: prism::crypto::Keccak256Hasher,
        shape: AddressLabelKeccak256,
        model: AddressModelKeccak256,
        route: AddressRouteKeccak256,
        verb: address_inference_keccak256
    },
}
