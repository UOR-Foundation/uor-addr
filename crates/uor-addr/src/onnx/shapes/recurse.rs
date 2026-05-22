//! Bounded recursive structural typing for ONNX subgraphs (ADR-057).
//!
//! A `NodeProto` attribute of type `GRAPH` / `GRAPHS` embeds a subgraph
//! that may itself contain nodes with `GRAPH` / `GRAPHS` attributes
//! (`If`-then-`If`, `Loop`-body-`If`, …). The recursion target is the
//! `GraphProto` grammar; the descent bound is the application-declared
//! [`OnnxHostBounds::ONNX_SUBGRAPH_DEPTH_MAX`].
//!
//! As with the JSON / S-expression / GGUF realizations, the recursion is
//! enforced **in the canonicalizer**: [`crate::onnx::value`]'s
//! `canonical_graph` recurses into `GRAPH` / `GRAPHS` attribute values
//! carrying an explicit `depth`, rejecting any model exceeding
//! `ONNX_SUBGRAPH_DEPTH_MAX` with the `…/OnnxValue/subgraphDepthBound`
//! shape violation. Each subgraph contributes its own `graph_root`
//! digest, so the top-level commitment stays carrier-bounded at every
//! depth.
//!
//! [`OnnxHostBounds::ONNX_SUBGRAPH_DEPTH_MAX`]: crate::onnx::shapes::bounds::OnnxHostBounds::ONNX_SUBGRAPH_DEPTH_MAX

use crate::onnx::shapes::bounds::{OnnxAddrBounds, OnnxHostBounds};

/// The subgraph descent bound under the bundled encoding profile.
pub const SUBGRAPH_DESCENT_BOUND: usize =
    <OnnxAddrBounds as OnnxHostBounds>::ONNX_SUBGRAPH_DEPTH_MAX;
