//! `OnnxHostBounds` — the ONNX realization's typed-input bound surface
//! plus the concrete carrier capacity profile (`OnnxAddrBounds`).
//!
//! Mirrors [`crate::gguf::shapes::bounds`]: spec-pinned ONNX constants,
//! the application-policy [`OnnxHostBounds`] trait (the ONNX IR sets no
//! hard ceiling on node / initializer / attribute counts — protobuf's
//! 2 GiB message cap applies to total wire size, not field shape), and a
//! concrete [`OnnxAddrBounds`] encoding profile calibrated + cited inline.

use prism::vocabulary::HostBounds;

/// The only ONNX IR version this realization admits. Source: `onnx.proto`
/// `Version::IR_VERSION`.
pub const ONNX_IR_VERSION_REQUIRED: i64 = 13;

/// `TensorProto.DataType` enum range admitted at the typed-input
/// boundary (`FLOAT`=1 … `FLOAT4E2M1`=23). Source: `onnx.proto`.
pub const ONNX_TENSOR_DATA_TYPE_MIN: i32 = 1;
/// Upper bound of [`ONNX_TENSOR_DATA_TYPE_MIN`]'s range.
pub const ONNX_TENSOR_DATA_TYPE_MAX: i32 = 23;

/// Byte width of the ONNX **canonical form** — a fixed two-level
/// commitment the ψ-pipeline carries and ψ₉ hashes:
///
/// ```text
/// LE_i64(ir_version) opset_root[32] graph_root[32] model_meta_root[32]
/// ```
///
/// The roots are streamed SHA-256 over the (unbounded) canonical opset /
/// graph / model-metadata skeletons at the host boundary, keeping the
/// canonical form a flat 104 bytes within the foundation pipeline's fixed
/// 4096-byte route buffer.
pub const ONNX_CANON_BYTES: usize = 8 + 32 + 32 + 32;

/// Carrier width for the ONNX canonical commitment (with headroom over
/// [`ONNX_CANON_BYTES`]).
pub const ONNX_CANON_MAX_BYTES: usize = 256;

/// Application-policy bounds for ONNX typed input. Extends [`HostBounds`]
/// (ADR-037) with ONNX-specific ceilings the ONNX IR leaves open.
pub trait OnnxHostBounds: HostBounds {
    /// Maximum node count in a single graph (or subgraph).
    const ONNX_GRAPH_NODE_COUNT_MAX: usize;
    /// Maximum initializer count in a single graph.
    const ONNX_INITIALIZER_COUNT_MAX: usize;
    /// Maximum input count of a single node.
    const ONNX_NODE_INPUT_COUNT_MAX: usize;
    /// Maximum output count of a single node.
    const ONNX_NODE_OUTPUT_COUNT_MAX: usize;
    /// Maximum attribute count of a single node.
    const ONNX_NODE_ATTRIBUTE_COUNT_MAX: usize;
    /// Maximum subgraph nesting depth (`If`/`Loop`/`Scan` bodies).
    const ONNX_SUBGRAPH_DEPTH_MAX: usize;
    /// Maximum tensor rank.
    const ONNX_TENSOR_RANK_MAX: usize;
    /// Maximum string byte width (names, string attributes).
    const ONNX_STRING_BYTES_MAX: usize;
    /// Maximum `raw_data` byte width of a single tensor.
    const ONNX_TENSOR_RAW_DATA_BYTES_MAX: u64;
    /// Maximum total `ModelProto` wire byte width.
    const ONNX_MODEL_BYTES_MAX: u64;
    /// Maximum function count.
    const ONNX_FUNCTION_COUNT_MAX: usize;
    /// Maximum opset-import count.
    const ONNX_OPSET_IMPORT_COUNT_MAX: usize;
    /// Maximum entry count of a single `StringStringEntryProto` map
    /// (`metadata_props`).
    const ONNX_METADATA_PROPS_COUNT_MAX: usize;
    /// Maximum entry count of a graph input / output / value_info list.
    const ONNX_GRAPH_IO_COUNT_MAX: usize;
    /// Application policy: the minimum opset version accepted for the
    /// default domain `""`.
    const ONNX_OPSET_VERSION_MIN: i64;
}

/// The ONNX realization's concrete capacity profile.
///
/// # Calibration
///
/// The [`OnnxHostBounds`] constants admit a Llama-3-8B-Instruct-class
/// ONNX export (the largest model in the conformance corpus) with
/// headroom:
///
/// - `ONNX_GRAPH_NODE_COUNT_MAX = 2_048` per graph level — covers
///   MNIST / ResNet-50 / GPT-2 exports. Node bookkeeping is one
///   `(offset, len)` span per node, materialized per graph level on the
///   stack, so this bound also keeps subgraph recursion within a
///   conventional stack; large LLM exports declare a higher bound (and
///   run with a larger stack).
/// - `ONNX_INITIALIZER_COUNT_MAX = 4_096` — one per weight tensor.
/// - `ONNX_OPSET_VERSION_MIN = 1` — accept any opset (ONNX mandates no
///   minimum; raise per application policy).
///
/// Applications admitting different shapes declare their own
/// `impl OnnxHostBounds` (see `tools/calibrate-onnx-bounds.py`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OnnxAddrBounds;

impl HostBounds for OnnxAddrBounds {
    const FINGERPRINT_MIN_BYTES: usize = 32;
    const FINGERPRINT_MAX_BYTES: usize = 32;
    const TRACE_MAX_EVENTS: usize = 64;
    const WITT_LEVEL_MAX_BITS: u32 = 32;

    const TERM_VALUE_MAX_BYTES: usize = 4096;
    const AXIS_OUTPUT_BYTES_MAX: usize = 4096;
    const FOLD_UNROLL_THRESHOLD: usize = 8;
    const BETTI_DIMENSION_MAX: usize = 71;
    const NERVE_CONSTRAINTS_MAX: usize = 128;
    const NERVE_SITES_MAX: usize = 71;
    const JACOBIAN_SITES_MAX: usize = 71;
    const RECURSION_TRACE_DEPTH_MAX: usize = 16;
    const OP_CHAIN_DEPTH_MAX: usize = 8;
    const AFFINE_COEFFS_MAX: usize = 80;
    const CONJUNCTION_TERMS_MAX: usize = 128;
    const ROUTE_INPUT_BUFFER_BYTES: usize = 4096;
    const ROUTE_OUTPUT_BUFFER_BYTES: usize = 4096;
    const UNFOLD_ITERATIONS_MAX: usize = 256;

    const NERVE_OUTPUT_BYTES_MAX: usize = 4096;
    const CHAIN_COMPLEX_OUTPUT_BYTES_MAX: usize = 4096;
    const HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX: usize = 4096;
    const COCHAIN_COMPLEX_OUTPUT_BYTES_MAX: usize = 4096;
    const COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX: usize = 4096;
    const POSTNIKOV_TOWER_OUTPUT_BYTES_MAX: usize = 4096;
    const HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX: usize = 4096;
    const K_INVARIANTS_OUTPUT_BYTES_MAX: usize = 4096;
}

impl OnnxHostBounds for OnnxAddrBounds {
    const ONNX_GRAPH_NODE_COUNT_MAX: usize = 2_048;
    const ONNX_INITIALIZER_COUNT_MAX: usize = 4_096;
    const ONNX_NODE_INPUT_COUNT_MAX: usize = 512;
    const ONNX_NODE_OUTPUT_COUNT_MAX: usize = 512;
    const ONNX_NODE_ATTRIBUTE_COUNT_MAX: usize = 128;
    const ONNX_SUBGRAPH_DEPTH_MAX: usize = 16;
    const ONNX_TENSOR_RANK_MAX: usize = 8;
    const ONNX_STRING_BYTES_MAX: usize = 1 << 20; // 1 MiB
    const ONNX_TENSOR_RAW_DATA_BYTES_MAX: u64 = 1 << 40; // 1 TiB
    const ONNX_MODEL_BYTES_MAX: u64 = 1 << 40; // 1 TiB
    const ONNX_FUNCTION_COUNT_MAX: usize = 1_024;
    const ONNX_OPSET_IMPORT_COUNT_MAX: usize = 64;
    const ONNX_METADATA_PROPS_COUNT_MAX: usize = 1_024;
    const ONNX_GRAPH_IO_COUNT_MAX: usize = 4_096;
    const ONNX_OPSET_VERSION_MIN: i64 = 1;
}
