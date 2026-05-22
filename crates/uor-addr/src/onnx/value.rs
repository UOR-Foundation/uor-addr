//! `OnnxValue` — the ONNX IR v13 typed input carrier.
//!
//! Like [`crate::gguf::GgufValue`], the parser produces a fixed-width
//! two-level **canonical commitment** directly into a stack buffer;
//! `canonicalize_into` is the identity.
//!
//! # Canonical form (the protobuf-canonical commitment)
//!
//! Protobuf v3 admits many byte-representations of the same logical
//! message. This realization defines a canonical form that collapses
//! that freedom and binds every leaf via streamed SHA-256:
//!
//! ```text
//! LE_i64(ir_version) || opset_root || graph_root || model_meta_root
//! ```
//!
//! - **opset_root** — SHA-256 over the opset imports sorted by
//!   `(domain, version)`: `sha256(domain) || LE_i64(version)` each.
//! - **graph_root** — SHA-256 over the graph name, then **nodes in
//!   Kahn-topological order with lexicographic `(name, op_type, domain)`
//!   tie-breaking**, then initializers sorted by name (each carrying a
//!   streamed digest of its tensor data, with typed-data fields
//!   re-encoded to the canonical `raw_data` layout), then graph
//!   input / output / value_info sorted by name. `GRAPH`-typed node
//!   attributes recurse, bounded by
//!   [`OnnxHostBounds::ONNX_SUBGRAPH_DEPTH_MAX`].
//! - **model_meta_root** — producer / domain / model_version plus
//!   `metadata_props` sorted by key.
//!
//! Two ONNX models that decode to the same logical content — regardless
//! of protobuf field order, node ordering (among valid topological
//! orderings), or whether tensor data is stored in `raw_data` or the
//! typed-data fields — canonicalize identically.

use prism::crypto::Sha256Hasher;
use prism::pipeline::{
    register_shape, ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation,
    ViolationKind,
};
use prism::vocabulary::Hasher;

use crate::onnx::dtype::OnnxDataType;
use crate::onnx::protobuf::{read_varint, FieldValue, MessageReader};
use crate::onnx::shapes::bounds::{
    OnnxAddrBounds, OnnxHostBounds, ONNX_CANON_BYTES, ONNX_CANON_MAX_BYTES,
    ONNX_IR_VERSION_REQUIRED,
};

// ─── ShapeViolation IRIs ─────────────────────────────────────────────────

macro_rules! violation {
    ($name:ident, $constraint:literal, $kind:expr) => {
        const $name: ShapeViolation = ShapeViolation {
            shape_iri: "https://uor.foundation/addr/OnnxValue",
            constraint_iri: concat!("https://uor.foundation/addr/OnnxValue/", $constraint),
            property_iri: concat!("https://uor.foundation/addr/OnnxValue/", $constraint),
            expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
            min_count: 0,
            max_count: 1,
            kind: $kind,
        };
    };
}

violation!(PROTOBUF_FAILURE, "validProtobuf", ViolationKind::ValueCheck);
violation!(UNSUPPORTED_IR, "supportedIrVersion", ViolationKind::ValueCheck);
violation!(OPSET_TOO_OLD, "opsetVersionMin", ViolationKind::ValueCheck);
violation!(MISSING_GRAPH, "graphPresent", ViolationKind::ValueCheck);
violation!(BOUND_EXCEEDED, "withinBounds", ViolationKind::CardinalityViolation);
violation!(SUBGRAPH_DEPTH, "subgraphDepthBound", ViolationKind::CardinalityViolation);
violation!(GRAPH_CYCLE, "acyclicGraph", ViolationKind::ValueCheck);
violation!(UNKNOWN_DTYPE, "knownTensorDataType", ViolationKind::ValueCheck);
violation!(CANON_OVERFLOW, "canonicalFormWidth", ViolationKind::CardinalityViolation);

fn from_wire(_e: crate::onnx::protobuf::WireError) -> ShapeViolation {
    PROTOBUF_FAILURE
}

#[inline]
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256Hasher::initial().fold_bytes(bytes).finalize()
}

/// Fold `bytes` into the running hasher behind a mutable reference (the
/// `Hasher::fold_bytes` consume-and-return API is awkward inside `FnMut`
/// closures; this wraps the take-replace dance once).
#[inline]
fn fold(h: &mut Sha256Hasher, bytes: &[u8]) {
    let cur = core::mem::replace(h, Sha256Hasher::initial());
    *h = cur.fold_bytes(bytes);
}

// Working-array capacities for the bundled `OnnxAddrBounds` encoding
// profile. Every parser scratch array is sized to a *cited* bound rather
// than a bare literal; `parse_with::<OH>` additionally rejects inputs
// exceeding the generic `OH` bound. (Per the spec's bounds discipline an
// application admitting larger graphs declares its own `OnnxHostBounds`
// and builds with a correspondingly larger profile.)
const OPSET_CAP: usize = <OnnxAddrBounds as OnnxHostBounds>::ONNX_OPSET_IMPORT_COUNT_MAX;
const META_PROPS_CAP: usize = <OnnxAddrBounds as OnnxHostBounds>::ONNX_METADATA_PROPS_COUNT_MAX;
const NODE_CAP: usize = <OnnxAddrBounds as OnnxHostBounds>::ONNX_GRAPH_NODE_COUNT_MAX;
const ATTR_CAP: usize = <OnnxAddrBounds as OnnxHostBounds>::ONNX_NODE_ATTRIBUTE_COUNT_MAX;
const INIT_CAP: usize = <OnnxAddrBounds as OnnxHostBounds>::ONNX_INITIALIZER_COUNT_MAX;
const IO_CAP: usize = <OnnxAddrBounds as OnnxHostBounds>::ONNX_GRAPH_IO_COUNT_MAX;

/// Recursion ceiling for the opaque-message field-order canonicalizer.
const CANON_PROTO_DEPTH_MAX: usize = 32;

/// Field-order-canonical digest of an opaque protobuf message — folds its
/// fields in ascending field-number order (stable within a number, so
/// repeated-field order is preserved), recursing into length-delimited
/// fields. This applies canonicalization rule 1 (field-number ordering)
/// to sub-messages the realization otherwise treats opaquely
/// (`TypeProto`, `SparseTensorProto`), so two serializations of the same
/// logical value canonicalize identically.
///
/// A length-delimited field that is genuinely a string / bytes leaf
/// (e.g. `dim_param`) generally fails to re-parse as a well-formed
/// message; that case falls back to a digest of the raw payload. The
/// transform is deterministic either way: identical bytes always take the
/// same path.
fn canonical_proto_digest(body: &[u8], depth: usize) -> Result<[u8; 32], ShapeViolation> {
    #[derive(Clone, Copy, Default)]
    struct F {
        number: u64,
        wt: u8,
        off: usize,
        len: usize,
        val: u64,
    }
    const FIELD_CAP: usize = 256;
    let mut fs = [F::default(); FIELD_CAP];
    let mut n = 0;
    let mut r = MessageReader::new(body);
    while let Some(f) = r.next_field().map_err(from_wire)? {
        if n >= FIELD_CAP {
            return Err(BOUND_EXCEEDED);
        }
        fs[n] = match f.value {
            FieldValue::Varint(v) => F { number: f.number, wt: 0, off: 0, len: 0, val: v },
            FieldValue::Fixed64(v) => F { number: f.number, wt: 1, off: 0, len: 0, val: v },
            FieldValue::Fixed32(v) => F { number: f.number, wt: 5, off: 0, len: 0, val: u64::from(v) },
            FieldValue::Bytes(b) => F {
                number: f.number,
                wt: 2,
                off: b.as_ptr() as usize - body.as_ptr() as usize,
                len: b.len(),
                val: 0,
            },
        };
        n += 1;
    }
    let fs = &mut fs[..n];
    // Stable sort by field number (insertion sort keeps equal-key order).
    insertion_sort(fs, |a: &F, b: &F| a.number <= b.number);

    let mut h = Sha256Hasher::initial();
    for f in fs.iter() {
        fold(&mut h, &f.number.to_le_bytes());
        fold(&mut h, &[f.wt]);
        match f.wt {
            0 | 1 => fold(&mut h, &f.val.to_le_bytes()),
            5 => fold(&mut h, &(f.val as u32).to_le_bytes()),
            _ => {
                let payload = &body[f.off..f.off + f.len];
                let sub = if depth < CANON_PROTO_DEPTH_MAX && !payload.is_empty() {
                    canonical_proto_digest(payload, depth + 1).unwrap_or_else(|_| sha256(payload))
                } else {
                    sha256(payload)
                };
                fold(&mut h, &sub);
            }
        }
    }
    Ok(h.finalize())
}

// ─── Protobuf field accessors over a message body ────────────────────────

/// First occurrence of `field_no` in `body`, or `None`.
fn first_field(body: &[u8], field_no: u64) -> Result<Option<FieldValue<'_>>, ShapeViolation> {
    let mut r = MessageReader::new(body);
    while let Some(f) = r.next_field().map_err(from_wire)? {
        if f.number == field_no {
            return Ok(Some(f.value));
        }
    }
    Ok(None)
}

fn first_varint(body: &[u8], field_no: u64) -> Result<Option<u64>, ShapeViolation> {
    Ok(match first_field(body, field_no)? {
        Some(FieldValue::Varint(v)) => Some(v),
        _ => None,
    })
}

fn first_bytes(body: &[u8], field_no: u64) -> Result<&[u8], ShapeViolation> {
    Ok(match first_field(body, field_no)? {
        Some(FieldValue::Bytes(b)) => b,
        _ => &[],
    })
}

/// Invoke `f` for every occurrence of `field_no` (the repeated-field
/// iterator). Stops and propagates the first error `f` returns.
fn for_each_field(
    body: &[u8],
    field_no: u64,
    mut f: impl FnMut(FieldValue<'_>) -> Result<(), ShapeViolation>,
) -> Result<(), ShapeViolation> {
    let mut r = MessageReader::new(body);
    while let Some(field) = r.next_field().map_err(from_wire)? {
        if field.number == field_no {
            f(field.value)?;
        }
    }
    Ok(())
}

fn count_field(body: &[u8], field_no: u64) -> Result<usize, ShapeViolation> {
    let mut n = 0;
    for_each_field(body, field_no, |_| {
        n += 1;
        Ok(())
    })?;
    Ok(n)
}

// ─── Canonical-commitment writer (fixed width) ───────────────────────────

struct CanonWriter {
    bytes: [u8; ONNX_CANON_MAX_BYTES],
    len: usize,
}
impl CanonWriter {
    fn new() -> Self {
        Self {
            bytes: [0u8; ONNX_CANON_MAX_BYTES],
            len: 0,
        }
    }
    fn put(&mut self, src: &[u8]) -> Result<(), ShapeViolation> {
        let end = self.len.checked_add(src.len()).ok_or(CANON_OVERFLOW)?;
        if end > ONNX_CANON_MAX_BYTES {
            return Err(CANON_OVERFLOW);
        }
        self.bytes[self.len..end].copy_from_slice(src);
        self.len = end;
        Ok(())
    }
}

fn insertion_sort<T: Copy>(xs: &mut [T], le: impl Fn(&T, &T) -> bool) {
    let mut i = 1;
    while i < xs.len() {
        let mut j = i;
        while j > 0 && !le(&xs[j - 1], &xs[j]) {
            xs.swap(j - 1, j);
            j -= 1;
        }
        i += 1;
    }
}

// ─── OnnxValue carrier ────────────────────────────────────────────────────

/// A parsed, canonicalized ONNX `ModelProto`. Stored bytes are the
/// fixed-width canonical commitment (see module docs).
#[derive(Clone)]
pub struct OnnxValue {
    bytes: [u8; ONNX_CANON_MAX_BYTES],
    len: u32,
}

impl core::fmt::Debug for OnnxValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OnnxValue")
            .field("canonical_len", &self.len)
            .finish_non_exhaustive()
    }
}
impl PartialEq for OnnxValue {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_bytes() == other.canonical_bytes()
    }
}
impl Eq for OnnxValue {}

impl OnnxValue {
    /// Borrow the canonical commitment bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Parse an ONNX `ModelProto` wire buffer under [`OnnxAddrBounds`].
    ///
    /// # Errors
    ///
    /// A [`ShapeViolation`] whose `constraint_iri` names the violated
    /// invariant (protobuf decode failure, unsupported IR version, opset
    /// below the minimum, missing graph, a bound overflow, a subgraph
    /// cycle, or an unknown tensor data type).
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        Self::parse_with::<OnnxAddrBounds>(raw)
    }

    /// Parse under an explicit [`OnnxHostBounds`] profile.
    pub fn parse_with<OH: OnnxHostBounds>(raw: &[u8]) -> Result<Self, ShapeViolation> {
        // ── ir_version (ModelProto #1) ──
        let ir_version = first_varint(raw, 1)?.ok_or(UNSUPPORTED_IR)? as i64;
        if ir_version != ONNX_IR_VERSION_REQUIRED {
            return Err(UNSUPPORTED_IR);
        }

        // ── opset_root (ModelProto #8, repeated OperatorSetIdProto) ──
        let opset_root = opset_root::<OH>(raw)?;

        // ── graph (ModelProto #7) ──
        let graph = first_bytes(raw, 7)?;
        if graph.is_empty() {
            return Err(MISSING_GRAPH);
        }
        let graph_root = canonical_graph::<OH>(graph, 0)?;

        // ── model_meta_root ──
        let model_meta_root = model_meta_root::<OH>(raw)?;

        // ── emit commitment ──
        let mut w = CanonWriter::new();
        w.put(&ir_version.to_le_bytes())?;
        w.put(&opset_root)?;
        w.put(&graph_root)?;
        w.put(&model_meta_root)?;
        debug_assert_eq!(w.len, ONNX_CANON_BYTES);

        Ok(Self {
            bytes: w.bytes,
            len: w.len as u32,
        })
    }
}

/// `opset_root` — opset imports sorted by `(domain, version)`. Enforces
/// at least one default-domain (`""`) import at or above
/// `OH::ONNX_OPSET_VERSION_MIN`.
fn opset_root<OH: OnnxHostBounds>(model: &[u8]) -> Result<[u8; 32], ShapeViolation> {
    #[derive(Clone, Copy, Default)]
    struct Opset {
        off: usize,
        len: usize,
    } // span of the OperatorSetIdProto body
    let n = count_field(model, 8)?;
    if n > OH::ONNX_OPSET_IMPORT_COUNT_MAX {
        return Err(BOUND_EXCEEDED);
    }
    let mut entries = [Opset::default(); OPSET_CAP];
    let cap = entries.len().min(OH::ONNX_OPSET_IMPORT_COUNT_MAX);
    let mut i = 0;
    {
        let mut r = MessageReader::new(model);
        while let Some(f) = r.next_field().map_err(from_wire)? {
            if f.number == 8 {
                if let FieldValue::Bytes(b) = f.value {
                    if i >= cap {
                        return Err(BOUND_EXCEEDED);
                    }
                    let base = b.as_ptr() as usize - model.as_ptr() as usize;
                    entries[i] = Opset {
                        off: base,
                        len: b.len(),
                    };
                    i += 1;
                }
            }
        }
    }
    let entries = &mut entries[..i];

    // Default-domain minimum-version check.
    let mut ok_min = false;
    for e in entries.iter() {
        let body = &model[e.off..e.off + e.len];
        let domain = first_bytes(body, 1)?;
        let version = first_varint(body, 2)?.unwrap_or(0) as i64;
        if domain.is_empty() && version >= OH::ONNX_OPSET_VERSION_MIN {
            ok_min = true;
        }
    }
    if !ok_min && !entries.is_empty() {
        return Err(OPSET_TOO_OLD);
    }

    let mut order = [0u16; OPSET_CAP];
    for (k, slot) in order.iter_mut().take(entries.len()).enumerate() {
        *slot = k as u16;
    }
    let order = &mut order[..entries.len()];
    insertion_sort(order, |&a, &b| {
        let ea = &model[entries[a as usize].off..entries[a as usize].off + entries[a as usize].len];
        let eb = &model[entries[b as usize].off..entries[b as usize].off + entries[b as usize].len];
        let (da, va) = (
            first_bytes(ea, 1).unwrap_or(&[]),
            first_varint(ea, 2).ok().flatten().unwrap_or(0),
        );
        let (db, vb) = (
            first_bytes(eb, 1).unwrap_or(&[]),
            first_varint(eb, 2).ok().flatten().unwrap_or(0),
        );
        (da, va) <= (db, vb)
    });

    let mut h = Sha256Hasher::initial();
    for &idx in order.iter() {
        let body = &model[entries[idx as usize].off..entries[idx as usize].off + entries[idx as usize].len];
        let domain = first_bytes(body, 1)?;
        let version = first_varint(body, 2)?.unwrap_or(0) as i64;
        fold(&mut h, &sha256(domain));
        fold(&mut h, &version.to_le_bytes());
    }
    Ok(h.finalize())
}

/// `model_meta_root` — producer / domain / model_version + sorted
/// `metadata_props`.
fn model_meta_root<OH: OnnxHostBounds>(model: &[u8]) -> Result<[u8; 32], ShapeViolation> {
    let mut h = Sha256Hasher::initial();
    fold(&mut h, &sha256(first_bytes(model, 2)?)); // producer_name
    fold(&mut h, &sha256(first_bytes(model, 3)?)); // producer_version
    fold(&mut h, &sha256(first_bytes(model, 4)?)); // domain
    fold(&mut h, &(first_varint(model, 5)?.unwrap_or(0) as i64).to_le_bytes()); // model_version
    fold(&mut h, &string_string_root::<OH>(model, 14)?); // metadata_props
    Ok(h.finalize())
}

/// SHA-256 over a repeated `StringStringEntryProto` map (`field_no`),
/// sorted by key. Rejects maps exceeding
/// `OH::ONNX_METADATA_PROPS_COUNT_MAX`.
fn string_string_root<OH: OnnxHostBounds>(
    body: &[u8],
    field_no: u64,
) -> Result<[u8; 32], ShapeViolation> {
    #[derive(Clone, Copy, Default)]
    struct Entry {
        off: usize,
        len: usize,
    }
    let mut entries = [Entry::default(); META_PROPS_CAP];
    let mut i = 0;
    {
        let mut r = MessageReader::new(body);
        while let Some(f) = r.next_field().map_err(from_wire)? {
            if f.number == field_no {
                if let FieldValue::Bytes(b) = f.value {
                    if i >= entries.len() || i >= OH::ONNX_METADATA_PROPS_COUNT_MAX {
                        return Err(BOUND_EXCEEDED);
                    }
                    entries[i] = Entry {
                        off: b.as_ptr() as usize - body.as_ptr() as usize,
                        len: b.len(),
                    };
                    i += 1;
                }
            }
        }
    }
    let entries = &mut entries[..i];
    let mut order = [0u16; META_PROPS_CAP];
    for (k, slot) in order.iter_mut().take(entries.len()).enumerate() {
        *slot = k as u16;
    }
    let order = &mut order[..entries.len()];
    insertion_sort(order, |&a, &b| {
        let ka = first_bytes(&body[entries[a as usize].off..entries[a as usize].off + entries[a as usize].len], 1).unwrap_or(&[]);
        let kb = first_bytes(&body[entries[b as usize].off..entries[b as usize].off + entries[b as usize].len], 1).unwrap_or(&[]);
        ka <= kb
    });
    let mut h = Sha256Hasher::initial();
    for &idx in order.iter() {
        let e = &body[entries[idx as usize].off..entries[idx as usize].off + entries[idx as usize].len];
        fold(&mut h, &sha256(first_bytes(e, 1)?));
        fold(&mut h, &sha256(first_bytes(e, 2)?));
    }
    Ok(h.finalize())
}

/// Canonicalize a `GraphProto` body into a 32-byte `graph_root`,
/// recursing into subgraphs bounded by `OH::ONNX_SUBGRAPH_DEPTH_MAX`.
fn canonical_graph<OH: OnnxHostBounds>(graph: &[u8], depth: usize) -> Result<[u8; 32], ShapeViolation> {
    if depth > OH::ONNX_SUBGRAPH_DEPTH_MAX {
        return Err(SUBGRAPH_DEPTH);
    }

    let mut h = Sha256Hasher::initial();
    fold(&mut h, &sha256(first_bytes(graph, 2)?)); // graph name

    // ── Nodes in Kahn-topological order (lex tie-break) ──
    let node_count = count_field(graph, 1)?;
    if node_count > OH::ONNX_GRAPH_NODE_COUNT_MAX {
        return Err(BOUND_EXCEEDED);
    }
    let mut nodes = [NodeSpan::default(); NODE_CAP];
    if node_count > nodes.len() {
        return Err(BOUND_EXCEEDED);
    }
    let mut i = 0;
    {
        let mut r = MessageReader::new(graph);
        while let Some(f) = r.next_field().map_err(from_wire)? {
            if f.number == 1 {
                if let FieldValue::Bytes(b) = f.value {
                    nodes[i] = NodeSpan {
                        off: b.as_ptr() as usize - graph.as_ptr() as usize,
                        len: b.len(),
                    };
                    i += 1;
                }
            }
        }
    }
    let nodes = &nodes[..node_count];

    let mut emitted = [false; NODE_CAP];
    let emitted = &mut emitted[..node_count];
    for _ in 0..node_count {
        // Find the lex-min ready (all producers emitted), unemitted node.
        let mut best: Option<usize> = None;
        for (cand, node) in nodes.iter().enumerate() {
            if emitted[cand] {
                continue;
            }
            if !node_ready(graph, nodes, emitted, node)? {
                continue;
            }
            best = Some(match best {
                None => cand,
                Some(b) => {
                    if node_lex_le(graph, &nodes[cand], &nodes[b])? {
                        cand
                    } else {
                        b
                    }
                }
            });
        }
        let pick = best.ok_or(GRAPH_CYCLE)?; // no ready node ⇒ cycle
        let body = &graph[nodes[pick].off..nodes[pick].off + nodes[pick].len];
        fold(&mut h, &node_commitment::<OH>(body, depth)?);
        emitted[pick] = true;
    }

    // ── Initializers (#5), sorted by name, with tensor-data digests ──
    fold(&mut h, &tensor_section_root::<OH>(graph, 5)?);

    // ── Graph IO: inputs (#11), outputs (#12), value_info (#13) ──
    fold(&mut h, &value_info_root::<OH>(graph, 11)?);
    fold(&mut h, &value_info_root::<OH>(graph, 12)?);
    fold(&mut h, &value_info_root::<OH>(graph, 13)?);

    Ok(h.finalize())
}

/// A `(offset, len)` span of a node's `NodeProto` body within the parent
/// graph buffer.
#[derive(Clone, Copy, Default)]
struct NodeSpan {
    off: usize,
    len: usize,
}

/// A node is ready when every input name that is *produced by another
/// node in this graph* has had its producer emitted.
fn node_ready(graph: &[u8], nodes: &[NodeSpan], emitted: &[bool], node: &NodeSpan) -> Result<bool, ShapeViolation> {
    let body = &graph[node.off..node.off + node.len];
    let mut ready = true;
    for_each_field(body, 1, |v| {
        if let FieldValue::Bytes(name) = v {
            if !name.is_empty() {
                // find producer
                for (k, prod) in nodes.iter().enumerate() {
                    let pbody = &graph[prod.off..prod.off + prod.len];
                    let mut produces = false;
                    for_each_field(pbody, 2, |ov| {
                        if let FieldValue::Bytes(on) = ov {
                            if on == name {
                                produces = true;
                            }
                        }
                        Ok(())
                    })?;
                    if produces && !emitted[k] {
                        ready = false;
                    }
                }
            }
        }
        Ok(())
    })?;
    Ok(ready)
}

/// Lexicographic order on `(name, op_type, domain)`.
fn node_lex_le(graph: &[u8], a: &NodeSpan, b: &NodeSpan) -> Result<bool, ShapeViolation> {
    let ba = &graph[a.off..a.off + a.len];
    let bb = &graph[b.off..b.off + b.len];
    let ka = (first_bytes(ba, 3)?, first_bytes(ba, 4)?, first_bytes(ba, 7)?);
    let kb = (first_bytes(bb, 3)?, first_bytes(bb, 4)?, first_bytes(bb, 7)?);
    Ok(ka <= kb)
}

/// Per-node commitment: identity fields, positional inputs / outputs,
/// then the name-sorted attribute root (which recurses into subgraphs).
fn node_commitment<OH: OnnxHostBounds>(node: &[u8], depth: usize) -> Result<[u8; 32], ShapeViolation> {
    let mut h = Sha256Hasher::initial();
    fold(&mut h, &sha256(first_bytes(node, 3)?)); // name
    fold(&mut h, &sha256(first_bytes(node, 4)?)); // op_type
    fold(&mut h, &sha256(first_bytes(node, 7)?)); // domain
    fold(&mut h, &sha256(first_bytes(node, 8)?)); // overload (IR v10+)

    let n_in = count_field(node, 1)?;
    if n_in > OH::ONNX_NODE_INPUT_COUNT_MAX {
        return Err(BOUND_EXCEEDED);
    }
    fold(&mut h, &(n_in as u32).to_le_bytes());
    for_each_field(node, 1, |v| {
        if let FieldValue::Bytes(name) = v {
            fold(&mut h, &sha256(name));
        }
        Ok(())
    })?;

    let n_out = count_field(node, 2)?;
    if n_out > OH::ONNX_NODE_OUTPUT_COUNT_MAX {
        return Err(BOUND_EXCEEDED);
    }
    fold(&mut h, &(n_out as u32).to_le_bytes());
    for_each_field(node, 2, |v| {
        if let FieldValue::Bytes(name) = v {
            fold(&mut h, &sha256(name));
        }
        Ok(())
    })?;

    fold(&mut h, &attribute_root::<OH>(node, depth)?);
    Ok(h.finalize())
}

/// Name-sorted attribute root (`NodeProto.attribute` #5).
fn attribute_root<OH: OnnxHostBounds>(node: &[u8], depth: usize) -> Result<[u8; 32], ShapeViolation> {
    #[derive(Clone, Copy, Default)]
    struct Span {
        off: usize,
        len: usize,
    }
    let count = count_field(node, 5)?;
    if count > OH::ONNX_NODE_ATTRIBUTE_COUNT_MAX {
        return Err(BOUND_EXCEEDED);
    }
    let mut attrs = [Span::default(); ATTR_CAP];
    if count > attrs.len() {
        return Err(BOUND_EXCEEDED);
    }
    let mut i = 0;
    {
        let mut r = MessageReader::new(node);
        while let Some(f) = r.next_field().map_err(from_wire)? {
            if f.number == 5 {
                if let FieldValue::Bytes(b) = f.value {
                    attrs[i] = Span {
                        off: b.as_ptr() as usize - node.as_ptr() as usize,
                        len: b.len(),
                    };
                    i += 1;
                }
            }
        }
    }
    let attrs = &mut attrs[..count];
    let mut order = [0u16; ATTR_CAP];
    for (k, slot) in order.iter_mut().take(attrs.len()).enumerate() {
        *slot = k as u16;
    }
    let order = &mut order[..attrs.len()];
    insertion_sort(order, |&a, &b| {
        let na = first_bytes(&node[attrs[a as usize].off..attrs[a as usize].off + attrs[a as usize].len], 1).unwrap_or(&[]);
        let nb = first_bytes(&node[attrs[b as usize].off..attrs[b as usize].off + attrs[b as usize].len], 1).unwrap_or(&[]);
        na <= nb
    });

    let mut h = Sha256Hasher::initial();
    for &idx in order.iter() {
        let a = &node[attrs[idx as usize].off..attrs[idx as usize].off + attrs[idx as usize].len];
        fold(&mut h, &sha256(first_bytes(a, 1)?)); // name
        let atype = first_varint(a, 20)?.unwrap_or(0) as i32;
        fold(&mut h, &atype.to_le_bytes());
        fold(&mut h, &attribute_value_digest::<OH>(a, atype, depth)?);
    }
    Ok(h.finalize())
}

/// Digest of an attribute's value, dispatched on its `AttributeType`.
fn attribute_value_digest<OH: OnnxHostBounds>(a: &[u8], atype: i32, depth: usize) -> Result<[u8; 32], ShapeViolation> {
    let mut h = Sha256Hasher::initial();
    match atype {
        1 => {
            // FLOAT (#2, fixed32)
            if let Some(FieldValue::Fixed32(bits)) = first_field(a, 2)? {
                fold(&mut h, &bits.to_le_bytes());
            }
        }
        2 => {
            // INT (#3, varint)
            fold(&mut h, &(first_varint(a, 3)?.unwrap_or(0) as i64).to_le_bytes());
        }
        3 => {
            // STRING (#4, bytes)
            fold(&mut h, &sha256(first_bytes(a, 4)?));
        }
        4 => {
            // TENSOR (#5)
            fold(&mut h, &tensor_digest::<OH>(first_bytes(a, 5)?)?);
        }
        5 => {
            // GRAPH (#6) — recurse
            fold(&mut h, &canonical_graph::<OH>(first_bytes(a, 6)?, depth + 1)?);
        }
        6 => {
            // FLOATS (#7, packed fixed32)
            for_each_field(a, 7, |v| {
                if let FieldValue::Bytes(p) = v {
                    fold(&mut h, &sha256(p));
                } else if let FieldValue::Fixed32(b) = v {
                    fold(&mut h, &b.to_le_bytes());
                }
                Ok(())
            })?;
        }
        7 => {
            // INTS (#8, packed varint)
            fold_packed_varints(a, 8, &mut h)?;
        }
        8 => {
            // STRINGS (#9, repeated bytes)
            for_each_field(a, 9, |v| {
                if let FieldValue::Bytes(s) = v {
                    fold(&mut h, &sha256(s));
                }
                Ok(())
            })?;
        }
        9 => {
            // TENSORS (#10)
            for_each_field(a, 10, |v| {
                if let FieldValue::Bytes(t) = v {
                    fold(&mut h, &tensor_digest::<OH>(t)?);
                }
                Ok(())
            })?;
        }
        10 => {
            // GRAPHS (#11) — recurse
            let mut err = None;
            for_each_field(a, 11, |v| {
                if let FieldValue::Bytes(g) = v {
                    match canonical_graph::<OH>(g, depth + 1) {
                        Ok(d) => fold(&mut h, &d),
                        Err(e) => err = Some(e),
                    }
                }
                Ok(())
            })?;
            if let Some(e) = err {
                return Err(e);
            }
        }
        11 => fold(&mut h, &canonical_proto_digest(first_bytes(a, 22)?, 0)?), // SPARSE_TENSOR
        12 => {
            let mut err = None;
            for_each_field(a, 23, |v| {
                if let FieldValue::Bytes(s) = v {
                    match canonical_proto_digest(s, 0) {
                        Ok(d) => fold(&mut h, &d),
                        Err(e) => err = Some(e),
                    }
                }
                Ok(())
            })?;
            if let Some(e) = err {
                return Err(e);
            }
        }
        13 => fold(&mut h, &canonical_proto_digest(first_bytes(a, 14)?, 0)?), // TYPE_PROTO
        14 => {
            // TYPE_PROTOS — each element is a known TypeProto message;
            // propagate a malformed-message error rather than masking it.
            let mut err = None;
            for_each_field(a, 15, |v| {
                if let FieldValue::Bytes(s) = v {
                    match canonical_proto_digest(s, 0) {
                        Ok(d) => fold(&mut h, &d),
                        Err(e) => err = Some(e),
                    }
                }
                Ok(())
            })?;
            if let Some(e) = err {
                return Err(e);
            }
        }
        _ => {}
    }
    Ok(h.finalize())
}

fn fold_packed_varints(body: &[u8], field_no: u64, h: &mut Sha256Hasher) -> Result<(), ShapeViolation> {
    for_each_field(body, field_no, |v| {
        match v {
            FieldValue::Bytes(p) => {
                let mut pos = 0;
                while pos < p.len() {
                    let (val, np) = read_varint(p, pos).map_err(from_wire)?;
                    fold(h, &(val as i64).to_le_bytes());
                    pos = np;
                }
            }
            FieldValue::Varint(val) => fold(h, &(val as i64).to_le_bytes()),
            _ => {}
        }
        Ok(())
    })
}

/// Name-sorted root over a repeated `TensorProto` field (initializers).
fn tensor_section_root<OH: OnnxHostBounds>(graph: &[u8], field_no: u64) -> Result<[u8; 32], ShapeViolation> {
    #[derive(Clone, Copy, Default)]
    struct Span {
        off: usize,
        len: usize,
    }
    let count = count_field(graph, field_no)?;
    if count > OH::ONNX_INITIALIZER_COUNT_MAX {
        return Err(BOUND_EXCEEDED);
    }
    let mut spans = [Span::default(); INIT_CAP];
    if count > spans.len() {
        return Err(BOUND_EXCEEDED);
    }
    let mut i = 0;
    {
        let mut r = MessageReader::new(graph);
        while let Some(f) = r.next_field().map_err(from_wire)? {
            if f.number == field_no {
                if let FieldValue::Bytes(b) = f.value {
                    spans[i] = Span {
                        off: b.as_ptr() as usize - graph.as_ptr() as usize,
                        len: b.len(),
                    };
                    i += 1;
                }
            }
        }
    }
    let spans = &mut spans[..count];
    let mut order = [0u16; INIT_CAP];
    for (k, slot) in order.iter_mut().take(spans.len()).enumerate() {
        *slot = k as u16;
    }
    let order = &mut order[..spans.len()];
    insertion_sort(order, |&a, &b| {
        let na = first_bytes(&graph[spans[a as usize].off..spans[a as usize].off + spans[a as usize].len], 8).unwrap_or(&[]);
        let nb = first_bytes(&graph[spans[b as usize].off..spans[b as usize].off + spans[b as usize].len], 8).unwrap_or(&[]);
        na <= nb
    });
    let mut h = Sha256Hasher::initial();
    for &idx in order.iter() {
        let body = &graph[spans[idx as usize].off..spans[idx as usize].off + spans[idx as usize].len];
        fold(&mut h, &tensor_digest::<OH>(body)?);
    }
    Ok(h.finalize())
}

/// Canonical digest of a `TensorProto`: `sha256(name) || LE_i32(dtype)
/// || LE_u32(rank) || (LE_i64 dim …) || data_digest`, where `data_digest`
/// streams `raw_data` if present, else the typed-data field re-encoded to
/// the canonical little-endian `raw_data` layout (so the two storage
/// forms canonicalize identically).
fn tensor_digest<OH: OnnxHostBounds>(t: &[u8]) -> Result<[u8; 32], ShapeViolation> {
    let dtype_id = first_varint(t, 2)?.unwrap_or(0) as i32;
    let dtype = OnnxDataType::from_i32(dtype_id).ok_or(UNKNOWN_DTYPE)?;

    let mut h = Sha256Hasher::initial();
    fold(&mut h, &sha256(first_bytes(t, 8)?)); // name
    fold(&mut h, &dtype_id.to_le_bytes());

    // dims (#1, repeated int64; packed or unpacked).
    let rank = count_dims(t)?;
    if rank > OH::ONNX_TENSOR_RANK_MAX {
        return Err(BOUND_EXCEEDED);
    }
    fold(&mut h, &(rank as u32).to_le_bytes());
    fold_packed_varints(t, 1, &mut h)?;

    // data_digest
    fold(&mut h, &tensor_data_digest::<OH>(t, dtype)?);
    Ok(h.finalize())
}

fn count_dims(t: &[u8]) -> Result<usize, ShapeViolation> {
    let mut n = 0;
    for_each_field(t, 1, |v| {
        match v {
            FieldValue::Bytes(p) => {
                let mut pos = 0;
                while pos < p.len() {
                    let (_, np) = read_varint(p, pos).map_err(from_wire)?;
                    n += 1;
                    pos = np;
                }
            }
            FieldValue::Varint(_) => n += 1,
            _ => {}
        }
        Ok(())
    })?;
    Ok(n)
}

/// Stream the tensor's data through SHA-256 in canonical `raw_data`
/// layout.
fn tensor_data_digest<OH: OnnxHostBounds>(
    t: &[u8],
    dtype: OnnxDataType,
) -> Result<[u8; 32], ShapeViolation> {
    // External data (`data_location` #14 == EXTERNAL = 1): the no_std
    // core cannot open the referenced sibling file, so the κ-label binds
    // the external *reference* (`external_data` #13 — location / offset /
    // length / checksum, sorted by key) rather than the dereferenced
    // bytes. A domain tag keeps external digests disjoint from inline
    // ones. Hosts requiring inline≡external equivalence dereference
    // before calling.
    if first_varint(t, 14)?.unwrap_or(0) == 1 {
        let mut h = Sha256Hasher::initial();
        fold(&mut h, b"onnx:external-data:v1");
        fold(&mut h, &string_string_root::<OH>(t, 13)?);
        return Ok(h.finalize());
    }
    // raw_data (#9) takes precedence and is already canonical.
    if let Some(FieldValue::Bytes(raw)) = first_field(t, 9)? {
        if !raw.is_empty() {
            return Ok(sha256(raw));
        }
    }
    let mut h = Sha256Hasher::initial();
    match dtype {
        // float_data (#4) / double_data (#10): packed fixed-width — the
        // packed payload IS the canonical raw layout.
        OnnxDataType::Float => fold_fixed_payload(t, 4, &mut h)?,
        OnnxDataType::Double | OnnxDataType::Complex128 => fold_fixed_payload(t, 10, &mut h)?,
        OnnxDataType::Complex64 => fold_fixed_payload(t, 4, &mut h)?,
        // int64_data (#7): re-encode each varint to 8-byte LE.
        OnnxDataType::Int64 => fold_typed_varints(t, 7, 8, &mut h)?,
        // uint64_data (#11): UINT64 → 8-byte LE; UINT32 → 4-byte LE.
        OnnxDataType::Uint64 => fold_typed_varints(t, 11, 8, &mut h)?,
        OnnxDataType::Uint32 => fold_typed_varints(t, 11, 4, &mut h)?,
        // int32_data (#5) carries INT32/INT16/INT8/UINT16/UINT8/BOOL and
        // the bit-packed small floats — re-encode to the dtype's width.
        OnnxDataType::Int32 => fold_typed_varints(t, 5, 4, &mut h)?,
        OnnxDataType::Int16 | OnnxDataType::Uint16 | OnnxDataType::Float16 | OnnxDataType::Bfloat16 => {
            fold_typed_varints(t, 5, 2, &mut h)?
        }
        OnnxDataType::Int8
        | OnnxDataType::Uint8
        | OnnxDataType::Bool
        | OnnxDataType::Float8E4M3Fn
        | OnnxDataType::Float8E4M3Fnuz
        | OnnxDataType::Float8E5M2
        | OnnxDataType::Float8E5M2Fnuz
        | OnnxDataType::Int4
        | OnnxDataType::Uint4
        | OnnxDataType::Float4E2M1 => fold_typed_varints(t, 5, 1, &mut h)?,
        // string_data (#6): fold each element's digest.
        OnnxDataType::String => {
            for_each_field(t, 6, |v| {
                if let FieldValue::Bytes(s) = v {
                    fold(&mut h, &sha256(s));
                }
                Ok(())
            })?;
        }
    }
    Ok(h.finalize())
}

/// Fold the (already-canonical) packed payload of a fixed-width repeated
/// field directly.
fn fold_fixed_payload(body: &[u8], field_no: u64, h: &mut Sha256Hasher) -> Result<(), ShapeViolation> {
    for_each_field(body, field_no, |v| {
        match v {
            FieldValue::Bytes(p) => fold(h, p),
            FieldValue::Fixed32(b) => fold(h, &b.to_le_bytes()),
            FieldValue::Fixed64(b) => fold(h, &b.to_le_bytes()),
            _ => {}
        }
        Ok(())
    })
}

/// Re-encode each varint of a packed/unpacked repeated field to `width`
/// little-endian bytes (the canonical `raw_data` element layout).
fn fold_typed_varints(body: &[u8], field_no: u64, width: usize, h: &mut Sha256Hasher) -> Result<(), ShapeViolation> {
    for_each_field(body, field_no, |v| {
        match v {
            FieldValue::Bytes(p) => {
                let mut pos = 0;
                while pos < p.len() {
                    let (val, np) = read_varint(p, pos).map_err(from_wire)?;
                    fold(h, &val.to_le_bytes()[..width]);
                    pos = np;
                }
            }
            FieldValue::Varint(val) => fold(h, &val.to_le_bytes()[..width]),
            _ => {}
        }
        Ok(())
    })
}

/// Name-sorted root over a repeated `ValueInfoProto` field (graph
/// input / output / value_info). Binds the name plus a field-order-
/// canonical digest of the `TypeProto`. Rejects lists exceeding
/// `OH::ONNX_GRAPH_IO_COUNT_MAX`.
fn value_info_root<OH: OnnxHostBounds>(
    graph: &[u8],
    field_no: u64,
) -> Result<[u8; 32], ShapeViolation> {
    #[derive(Clone, Copy, Default)]
    struct Span {
        off: usize,
        len: usize,
    }
    let mut spans = [Span::default(); IO_CAP];
    let mut i = 0;
    {
        let mut r = MessageReader::new(graph);
        while let Some(f) = r.next_field().map_err(from_wire)? {
            if f.number == field_no {
                if let FieldValue::Bytes(b) = f.value {
                    if i >= spans.len() || i >= OH::ONNX_GRAPH_IO_COUNT_MAX {
                        return Err(BOUND_EXCEEDED);
                    }
                    spans[i] = Span {
                        off: b.as_ptr() as usize - graph.as_ptr() as usize,
                        len: b.len(),
                    };
                    i += 1;
                }
            }
        }
    }
    let spans = &mut spans[..i];
    let mut order = [0u16; IO_CAP];
    for (k, slot) in order.iter_mut().take(spans.len()).enumerate() {
        *slot = k as u16;
    }
    let order = &mut order[..spans.len()];
    insertion_sort(order, |&a, &b| {
        let na = first_bytes(&graph[spans[a as usize].off..spans[a as usize].off + spans[a as usize].len], 1).unwrap_or(&[]);
        let nb = first_bytes(&graph[spans[b as usize].off..spans[b as usize].off + spans[b as usize].len], 1).unwrap_or(&[]);
        na <= nb
    });
    let mut h = Sha256Hasher::initial();
    for &idx in order.iter() {
        let body = &graph[spans[idx as usize].off..spans[idx as usize].off + spans[idx as usize].len];
        fold(&mut h, &sha256(first_bytes(body, 1)?)); // name
        fold(&mut h, &canonical_proto_digest(first_bytes(body, 2)?, 0)?); // type (TypeProto)
    }
    Ok(h.finalize())
}

// ─── ConstrainedTypeShape + IntoBindingValue + AddressInput ──────────────

impl ConstrainedTypeShape for OnnxValue {
    const IRI: &'static str = "https://uor.foundation/addr/OnnxValue";
    const SITE_COUNT: usize = ONNX_CANON_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for OnnxValue {}

impl IntoBindingValue for OnnxValue {
    const MAX_BYTES: usize = ONNX_CANON_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        let n = self.len as usize;
        if n > out.len() {
            return Err(CANON_OVERFLOW);
        }
        out[..n].copy_from_slice(&self.bytes[..n]);
        Ok(n)
    }
}

register_shape!(OnnxValueRegistry, OnnxValue);

/// Slice-output canonicalizer — identity on the already-canonical bytes.
pub fn canonicalize_into_slice(canonical: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
    if canonical.len() > out.len() {
        return Err(CANON_OVERFLOW);
    }
    out[..canonical.len()].copy_from_slice(canonical);
    Ok(canonical.len())
}

impl crate::common::AddressInput for OnnxValue {
    type Registry = OnnxValueRegistry;

    #[inline]
    fn canonicalize_into(parser_emitted: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        canonicalize_into_slice(parser_emitted, out)
    }

    #[inline]
    fn parse(input: &[u8]) -> Result<Self, ShapeViolation> {
        Self::parse(input)
    }
}

/// **Available only under the `alloc` feature.** Canonical commitment as
/// an owned `Vec<u8>`.
#[cfg(feature = "alloc")]
pub fn canonicalize(raw: &[u8]) -> Result<alloc::vec::Vec<u8>, ShapeViolation> {
    extern crate alloc;
    Ok(OnnxValue::parse(raw)?.canonical_bytes().to_vec())
}
