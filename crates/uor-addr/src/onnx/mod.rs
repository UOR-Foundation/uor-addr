//! **`uor_addr::onnx` — the ONNX IR v13 realization of UOR-ADDR.**
//!
//! Typed content-addressing for ONNX `ModelProto` files under a
//! protobuf-canonical structural form, with the σ-projection bound to
//! [`prism::crypto::Sha256Hasher`].
//!
//! ## Authoritative sources
//!
//! - ONNX protobuf schema — <https://github.com/onnx/onnx/blob/main/onnx/onnx.proto>
//! - ONNX IR specification — <https://github.com/onnx/onnx/blob/main/docs/IR.md>
//! - ONNX versioning — <https://github.com/onnx/onnx/blob/main/docs/Versioning.md>
//! - Protobuf v3 wire format — <https://protobuf.dev/programming-guides/encoding/>
//! - SHA-256 σ-projection — NIST FIPS 180-4.
//!
//! ## Canonical form
//!
//! A protobuf-canonical two-level commitment (canonical form v1 —
//! [`CANONICAL_FORM_VERSION`]): `LE_i64(ir_version) || opset_root ||
//! graph_root || model_meta_root`, where each root is a streamed SHA-256
//! over the corresponding canonicalized skeleton (field-number ordering,
//! Kahn-topological node ordering with lexicographic tie-break,
//! name-sorted initializers / IO, typed-data-to-`raw_data` reduction,
//! and depth-bounded subgraph recursion). See [`value`] for the full
//! byte layout. Mirrors [`crate::gguf`]'s streamed-commitment design.

pub mod dtype;
pub mod model;
pub mod pipeline;
pub mod protobuf;
pub mod resolvers;
pub mod shapes;
pub mod value;
pub mod verbs;

/// Canonical-form version (see [`crate::gguf::CANONICAL_FORM_VERSION`]
/// for the versioning discipline).
pub const CANONICAL_FORM_VERSION: u32 = 1;

pub use dtype::OnnxDataType;
pub use model::{AddressModel, AddressRoute};
pub use pipeline::{address, AddressFailure, AddressOutcome, AddressWitness};
pub use resolvers::{
    AddressChainComplexResolver, AddressCochainComplexResolver, AddressCohomologyGroupResolver,
    AddressHomologyGroupResolver, AddressHomotopyGroupResolver, AddressKInvariantResolver,
    AddressNerveResolver, AddressPostnikovResolver, AddressResolverTuple,
};
pub use shapes::bounds::{
    OnnxAddrBounds, OnnxHostBounds, ONNX_CANON_BYTES, ONNX_CANON_MAX_BYTES,
    ONNX_IR_VERSION_REQUIRED, ONNX_TENSOR_DATA_TYPE_MAX, ONNX_TENSOR_DATA_TYPE_MIN,
};
#[cfg(feature = "alloc")]
pub use value::canonicalize;
pub use value::{OnnxValue, OnnxValueRegistry};
pub use verbs::{address_inference, VERB_TERMS_ADDRESS_INFERENCE};
