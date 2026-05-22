//! `GgufValue` — the GGUF v3 typed input carrier.
//!
//! Following the [`crate::ring::RingElement`] discipline, the parser
//! produces the **canonical structural form** directly into a fixed
//! stack buffer; [`GgufValue`]'s stored bytes *are* the canonical form,
//! so [`crate::common::AddressInput::canonicalize_into`] is the identity.
//!
//! # Canonical structural form (the Merkle skeleton)
//!
//! The GGUF spec defines no canonical form; this realization defines one.
//! Two GGUF files that decode to the same logical content canonicalize
//! to byte-identical skeletons. The skeleton is bounded
//! ([`GGUF_CANON_MAX_BYTES`]) regardless of model size because every
//! variable-length leaf is represented by its 32-byte streamed SHA-256
//! digest:
//!
//! ```text
//! LE_u32(GGUF_MAGIC)
//! LE_u32(GGUF_VERSION_REQUIRED)
//! LE_u64(tensor_count)
//! LE_u64(kv_count)
//! LE_u64(canonical_alignment)
//! ── metadata KVs, sorted by key bytes ──
//!   for kv: sha256(key) || LE_u32(type_tag) || canonical_value(kv)
//!     scalar  → the value's natural little-endian bytes
//!     string  → LE_u64(len) || sha256(utf8 bytes)
//!     array   → LE_u32(elem_type) || LE_u64(len) || sha256(wire payload)
//! ── tensor info, sorted by name bytes ──
//!   for t: sha256(name) || LE_u32(n_dims) || (LE_u64(dim) × n_dims)
//!       || LE_u32(ggml_type_id) || LE_u64(recomputed_offset)
//!       || sha256(tensor data bytes)        ← streamed; binds the weights
//! ```
//!
//! `recomputed_offset` is the cumulative aligned byte position in
//! sorted-tensor order (NOT the input's stored offset), so two inputs
//! whose tensor-data sections are laid out in different orders
//! canonicalize identically. Tensor data is streamed through
//! [`prism::crypto::Sha256Hasher`] (true incremental SHA-256) so
//! arbitrarily large weights bind into the κ-label without flowing
//! through the bounded ψ-pipeline carrier.

use prism::crypto::Sha256Hasher;
use prism::pipeline::{
    register_shape, ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation,
    ViolationKind,
};
use prism::vocabulary::Hasher;

use crate::gguf::dtype::GgmlType;
use crate::gguf::shapes::bounds::{
    GgufAddrBounds, GgufHostBounds, GGUF_CANON_BYTES, GGUF_CANON_MAX_BYTES, GGUF_DEFAULT_ALIGNMENT,
    GGUF_HEADER_BYTES, GGUF_MAGIC, GGUF_MAX_DIMS, GGUF_VERSION_REQUIRED,
};

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

macro_rules! violation {
    ($name:ident, $constraint:literal, $property:literal, $kind:expr) => {
        const $name: ShapeViolation = ShapeViolation {
            shape_iri: "https://uor.foundation/addr/GgufValue",
            constraint_iri: concat!("https://uor.foundation/addr/GgufValue/", $constraint),
            property_iri: concat!("https://uor.foundation/addr/GgufValue/", $property),
            expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
            min_count: 0,
            max_count: 1,
            kind: $kind,
        };
    };
}

violation!(INVALID_MAGIC, "validMagic", "magic", ViolationKind::ValueCheck);
violation!(
    UNSUPPORTED_VERSION,
    "supportedVersion",
    "version",
    ViolationKind::ValueCheck
);
violation!(TRUNCATED, "notTruncated", "byteSpan", ViolationKind::ValueCheck);
violation!(
    BOUND_EXCEEDED,
    "withinBounds",
    "count",
    ViolationKind::CardinalityViolation
);
violation!(
    ARRAY_DEPTH,
    "arrayDepthBound",
    "arrayDepth",
    ViolationKind::CardinalityViolation
);
violation!(
    INVALID_ALIGNMENT,
    "validAlignment",
    "alignment",
    ViolationKind::ValueCheck
);
violation!(
    UNKNOWN_TENSOR_TYPE,
    "knownTensorType",
    "tensorType",
    ViolationKind::ValueCheck
);
violation!(
    CANON_OVERFLOW,
    "canonicalFormWidth",
    "canonicalByteCount",
    ViolationKind::CardinalityViolation
);

// ─── GGUF metadata value type tags (gguf.md) ─────────────────────────────

const T_UINT8: u32 = 0;
const T_INT8: u32 = 1;
const T_UINT16: u32 = 2;
const T_INT16: u32 = 3;
const T_UINT32: u32 = 4;
const T_INT32: u32 = 5;
const T_FLOAT32: u32 = 6;
const T_BOOL: u32 = 7;
const T_STRING: u32 = 8;
const T_ARRAY: u32 = 9;
const T_UINT64: u32 = 10;
const T_INT64: u32 = 11;
const T_FLOAT64: u32 = 12;

/// Fixed wire width of a scalar metadata value type, or `None` for the
/// variable-length `STRING`/`ARRAY` types.
const fn scalar_width(type_tag: u32) -> Option<usize> {
    Some(match type_tag {
        T_UINT8 | T_INT8 | T_BOOL => 1,
        T_UINT16 | T_INT16 => 2,
        T_UINT32 | T_INT32 | T_FLOAT32 => 4,
        T_UINT64 | T_INT64 | T_FLOAT64 => 8,
        _ => return None,
    })
}

// ─── Little-endian readers over a borrowed cursor ────────────────────────

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ShapeViolation> {
        let end = self.pos.checked_add(n).ok_or(TRUNCATED)?;
        if end > self.buf.len() {
            return Err(TRUNCATED);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, ShapeViolation> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, ShapeViolation> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

#[inline]
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256Hasher::initial().fold_bytes(bytes).finalize()
}

#[inline]
const fn align_up(offset: u64, alignment: u64) -> u64 {
    let rem = offset % alignment;
    if rem == 0 {
        offset
    } else {
        offset + (alignment - rem)
    }
}

// ─── A bounded canonical-form writer ─────────────────────────────────────

struct CanonWriter {
    bytes: [u8; GGUF_CANON_MAX_BYTES],
    len: usize,
}

impl CanonWriter {
    fn new() -> Self {
        Self {
            bytes: [0u8; GGUF_CANON_MAX_BYTES],
            len: 0,
        }
    }

    fn put(&mut self, src: &[u8]) -> Result<(), ShapeViolation> {
        let end = self.len.checked_add(src.len()).ok_or(CANON_OVERFLOW)?;
        if end > GGUF_CANON_MAX_BYTES {
            return Err(CANON_OVERFLOW);
        }
        self.bytes[self.len..end].copy_from_slice(src);
        self.len = end;
        Ok(())
    }

    fn put_u32(&mut self, v: u32) -> Result<(), ShapeViolation> {
        self.put(&v.to_le_bytes())
    }

    fn put_u64(&mut self, v: u64) -> Result<(), ShapeViolation> {
        self.put(&v.to_le_bytes())
    }
}

// ─── Parsed-section descriptors (offsets into the input slice) ───────────

#[derive(Clone, Copy)]
struct KvEntry {
    key_off: usize,
    key_len: usize,
    type_tag: u32,
    /// Offset of the value payload (just past the type tag + key).
    val_off: usize,
    /// Total wire span of the value payload.
    val_span: usize,
}

#[derive(Clone, Copy)]
struct TensorEntry {
    name_off: usize,
    name_len: usize,
    n_dims: u32,
    dims: [u64; GGUF_MAX_DIMS],
    ggml_type: GgmlType,
    stored_offset: u64,
    data_bytes: u64,
}

/// The maximum entry counts the parser materializes on the stack. These
/// are the [`GgufAddrBounds`] ceilings; a model exceeding them is
/// rejected with [`BOUND_EXCEEDED`]. (An application with its own
/// `impl GgufHostBounds` would size these from its own constants.)
const KV_CAP: usize = <GgufAddrBounds as GgufHostBounds>::GGUF_METADATA_KV_COUNT_MAX;
const TENSOR_CAP: usize = <GgufAddrBounds as GgufHostBounds>::GGUF_TENSOR_COUNT_MAX;

// ─── GgufValue — the typed input carrier ─────────────────────────────────

/// A parsed, canonicalized GGUF v3 file. Stored bytes are the canonical
/// structural form (see module docs).
#[derive(Clone)]
pub struct GgufValue {
    bytes: [u8; GGUF_CANON_MAX_BYTES],
    len: u32,
}

impl core::fmt::Debug for GgufValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GgufValue")
            .field("canonical_len", &self.len)
            .finish_non_exhaustive()
    }
}

impl PartialEq for GgufValue {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_bytes() == other.canonical_bytes()
    }
}
impl Eq for GgufValue {}

impl GgufValue {
    /// Borrow the canonical structural-form bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Parse a GGUF v3 input slice into a canonicalized [`GgufValue`]
    /// under the [`GgufAddrBounds`] encoding profile.
    ///
    /// # Errors
    ///
    /// A [`ShapeViolation`] whose `constraint_iri` names the violated
    /// invariant (bad magic, unsupported version, truncation, a bound
    /// overflow, invalid alignment, an unknown tensor type, or a
    /// canonical-form width overflow).
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        Self::parse_with::<GgufAddrBounds>(raw)
    }

    /// Parse under an explicit [`GgufHostBounds`] profile `GH`.
    pub fn parse_with<GH: GgufHostBounds>(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let mut cur = Cursor::new(raw);

        // ── Header ──
        if cur.u32()? != GGUF_MAGIC {
            return Err(INVALID_MAGIC);
        }
        if cur.u32()? != GGUF_VERSION_REQUIRED {
            return Err(UNSUPPORTED_VERSION);
        }
        let tensor_count = cur.u64()?;
        let kv_count = cur.u64()?;
        debug_assert_eq!(cur.pos, GGUF_HEADER_BYTES);

        if tensor_count as usize > GH::GGUF_TENSOR_COUNT_MAX
            || tensor_count as usize > TENSOR_CAP
            || kv_count as usize > GH::GGUF_METADATA_KV_COUNT_MAX
            || kv_count as usize > KV_CAP
        {
            return Err(BOUND_EXCEEDED);
        }

        // ── Metadata KV section ──
        let mut kvs = [KvEntry {
            key_off: 0,
            key_len: 0,
            type_tag: 0,
            val_off: 0,
            val_span: 0,
        }; KV_CAP];
        let mut alignment = GGUF_DEFAULT_ALIGNMENT;
        for slot in kvs.iter_mut().take(kv_count as usize) {
            let key_len = cur.u64()? as usize;
            if key_len > GH::GGUF_METADATA_KEY_BYTES_MAX {
                return Err(BOUND_EXCEEDED);
            }
            let key_off = cur.pos;
            let key = cur.take(key_len)?;
            let type_tag = cur.u32()?;
            let val_off = cur.pos;
            let val_span = measure_value::<GH>(&mut cur, type_tag, 0)?;

            // `general.alignment` overrides the canonical alignment.
            if key == b"general.alignment" && type_tag == T_UINT32 {
                let a = u32::from_le_bytes([
                    raw[val_off],
                    raw[val_off + 1],
                    raw[val_off + 2],
                    raw[val_off + 3],
                ]) as u64;
                if a < 8 || !a.is_power_of_two() {
                    return Err(INVALID_ALIGNMENT);
                }
                alignment = a;
            }

            *slot = KvEntry {
                key_off,
                key_len,
                type_tag,
                val_off,
                val_span,
            };
        }
        let kvs = &kvs[..kv_count as usize];

        // ── Tensor info section ──
        let mut tensors = [TensorEntry {
            name_off: 0,
            name_len: 0,
            n_dims: 0,
            dims: [0; GGUF_MAX_DIMS],
            ggml_type: GgmlType::F32,
            stored_offset: 0,
            data_bytes: 0,
        }; TENSOR_CAP];
        let mut total_data_bytes: u64 = 0;
        for slot in tensors.iter_mut().take(tensor_count as usize) {
            let name_len = cur.u64()? as usize;
            if name_len > GH::GGUF_STRING_BYTES_MAX {
                return Err(BOUND_EXCEEDED);
            }
            let name_off = cur.pos;
            cur.take(name_len)?;
            let n_dims = cur.u32()?;
            if n_dims as usize > GGUF_MAX_DIMS {
                return Err(BOUND_EXCEEDED);
            }
            let mut dims = [0u64; GGUF_MAX_DIMS];
            let mut n_elements: u64 = 1;
            for d in dims.iter_mut().take(n_dims as usize) {
                *d = cur.u64()?;
                n_elements = n_elements.checked_mul(*d).ok_or(BOUND_EXCEEDED)?;
            }
            let type_id = cur.u32()?;
            let ggml_type = GgmlType::from_u32(type_id).ok_or(UNKNOWN_TENSOR_TYPE)?;
            let stored_offset = cur.u64()?;
            let data_bytes = ggml_type
                .tensor_data_bytes(n_elements)
                .ok_or(UNKNOWN_TENSOR_TYPE)?;
            total_data_bytes = total_data_bytes
                .checked_add(data_bytes)
                .ok_or(BOUND_EXCEEDED)?;
            if total_data_bytes > GH::GGUF_TENSOR_DATA_BYTES_MAX {
                return Err(BOUND_EXCEEDED);
            }
            *slot = TensorEntry {
                name_off,
                name_len,
                n_dims,
                dims,
                ggml_type,
                stored_offset,
                data_bytes,
            };
        }
        let tensors = &mut tensors[..tensor_count as usize];

        // Tensor-data section begins at the next alignment boundary past
        // the end of the tensor-info section.
        let data_section_start = align_up(cur.pos as u64, alignment);

        // ── Sort orders (lexicographic on raw UTF-8 bytes) ──
        let mut kv_order = [0u16; KV_CAP];
        for (i, slot) in kv_order.iter_mut().take(kvs.len()).enumerate() {
            *slot = i as u16;
        }
        let kv_order = &mut kv_order[..kvs.len()];
        insertion_sort(kv_order, |&a, &b| {
            let ka = &raw[kvs[a as usize].key_off..kvs[a as usize].key_off + kvs[a as usize].key_len];
            let kb = &raw[kvs[b as usize].key_off..kvs[b as usize].key_off + kvs[b as usize].key_len];
            ka <= kb
        });

        let mut t_order = [0u16; TENSOR_CAP];
        for (i, slot) in t_order.iter_mut().take(tensors.len()).enumerate() {
            *slot = i as u16;
        }
        let t_order = &mut t_order[..tensors.len()];
        insertion_sort(t_order, |&a, &b| {
            let na = &raw[tensors[a as usize].name_off
                ..tensors[a as usize].name_off + tensors[a as usize].name_len];
            let nb = &raw[tensors[b as usize].name_off
                ..tensors[b as usize].name_off + tensors[b as usize].name_len];
            na <= nb
        });

        // ── Fold the metadata section root ──
        // metadata_root = SHA-256 over the concatenation, in sorted-key
        // order, of: sha256(key) || LE_u32(type) || canonical_value.
        let mut mh = Sha256Hasher::initial();
        for &idx in kv_order.iter() {
            let kv = &kvs[idx as usize];
            let key = &raw[kv.key_off..kv.key_off + kv.key_len];
            mh = mh.fold_bytes(&sha256(key));
            mh = mh.fold_bytes(&kv.type_tag.to_le_bytes());
            mh = fold_canonical_value(mh, raw, kv);
        }
        let metadata_root = mh.finalize();

        // ── Fold the tensor section root ──
        // tensor_root = SHA-256 over the concatenation, in sorted-name
        // order, of: sha256(name) || LE_u32(n_dims) || (LE_u64 dim …) ||
        // LE_u32(ggml_type_id) || LE_u64(recomputed_offset) ||
        // sha256(streamed tensor data).
        let mut th = Sha256Hasher::initial();
        let mut canonical_offset: u64 = 0;
        for &idx in t_order.iter() {
            let t = &tensors[idx as usize];
            let name = &raw[t.name_off..t.name_off + t.name_len];
            th = th.fold_bytes(&sha256(name));
            th = th.fold_bytes(&t.n_dims.to_le_bytes());
            for d in t.dims.iter().take(t.n_dims as usize) {
                th = th.fold_bytes(&d.to_le_bytes());
            }
            th = th.fold_bytes(&t.ggml_type.id().to_le_bytes());
            th = th.fold_bytes(&canonical_offset.to_le_bytes());

            // Stream the tensor's data region through SHA-256. A region
            // extending past the input is a truncation error.
            let start = data_section_start
                .checked_add(t.stored_offset)
                .ok_or(TRUNCATED)? as usize;
            let end = start.checked_add(t.data_bytes as usize).ok_or(TRUNCATED)?;
            if end > raw.len() {
                return Err(TRUNCATED);
            }
            th = th.fold_bytes(&sha256(&raw[start..end]));

            canonical_offset = align_up(canonical_offset + t.data_bytes, alignment);
        }
        let tensor_root = th.finalize();

        // ── Emit the fixed-width canonical commitment ──
        let mut w = CanonWriter::new();
        w.put_u32(GGUF_MAGIC)?;
        w.put_u32(GGUF_VERSION_REQUIRED)?;
        w.put_u64(tensor_count)?;
        w.put_u64(kv_count)?;
        w.put_u64(alignment)?;
        w.put(&metadata_root)?;
        w.put(&tensor_root)?;
        debug_assert_eq!(w.len, GGUF_CANON_BYTES);

        Ok(Self {
            bytes: w.bytes,
            len: w.len as u32,
        })
    }
}

/// Measure (and bounds-check) the wire span of a metadata value of the
/// given `type_tag`, advancing the cursor past it. Recurses into ARRAY
/// payloads, enforcing [`GgufHostBounds::GGUF_METADATA_ARRAY_DEPTH_MAX`].
/// Returns the value's total wire byte span.
fn measure_value<GH: GgufHostBounds>(
    cur: &mut Cursor<'_>,
    type_tag: u32,
    depth: usize,
) -> Result<usize, ShapeViolation> {
    let start = cur.pos;
    if let Some(w) = scalar_width(type_tag) {
        cur.take(w)?;
    } else if type_tag == T_STRING {
        let n = cur.u64()? as usize;
        if n > GH::GGUF_STRING_BYTES_MAX {
            return Err(BOUND_EXCEEDED);
        }
        cur.take(n)?;
    } else if type_tag == T_ARRAY {
        if depth >= GH::GGUF_METADATA_ARRAY_DEPTH_MAX {
            return Err(ARRAY_DEPTH);
        }
        let elem_type = cur.u32()?;
        let len = cur.u64()? as usize;
        if len > GH::GGUF_METADATA_ARRAY_LEN_MAX {
            return Err(BOUND_EXCEEDED);
        }
        for _ in 0..len {
            measure_value::<GH>(cur, elem_type, depth + 1)?;
        }
    } else {
        return Err(TRUNCATED); // unknown type tag
    }
    Ok(cur.pos - start)
}

/// Fold the canonical representation of a metadata value into the
/// running hasher: scalars inline (their natural little-endian bytes);
/// STRING / ARRAY as a length-tagged header plus a streamed digest of the
/// wire payload (so arbitrarily large arrays / strings stay bounded).
fn fold_canonical_value(mut h: Sha256Hasher, raw: &[u8], kv: &KvEntry) -> Sha256Hasher {
    let payload = &raw[kv.val_off..kv.val_off + kv.val_span];
    if scalar_width(kv.type_tag).is_some() {
        h = h.fold_bytes(payload);
    } else if kv.type_tag == T_STRING {
        // payload = LE_u64(len) || utf8 bytes
        let len = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0; 8]));
        h = h.fold_bytes(&len.to_le_bytes());
        h = h.fold_bytes(&sha256(&payload[8..]));
    } else if kv.type_tag == T_ARRAY {
        // payload = LE_u32(elem_type) || LE_u64(len) || wire elements
        let elem_type = u32::from_le_bytes(payload[..4].try_into().unwrap_or([0; 4]));
        let len = u64::from_le_bytes(payload[4..12].try_into().unwrap_or([0; 8]));
        h = h.fold_bytes(&elem_type.to_le_bytes());
        h = h.fold_bytes(&len.to_le_bytes());
        h = h.fold_bytes(&sha256(&payload[12..]));
    }
    h
}

/// Stable insertion sort over a small index slice, `le(a, b)` defining a
/// `<=` total order. no_alloc; O(n²) but `n` is bounded by the
/// KV/tensor-count ceilings.
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

// ─── ConstrainedTypeShape + IntoBindingValue + AddressInput ──────────────

impl ConstrainedTypeShape for GgufValue {
    const IRI: &'static str = "https://uor.foundation/addr/GgufValue";
    const SITE_COUNT: usize = GGUF_CANON_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for GgufValue {}

impl IntoBindingValue for GgufValue {
    const MAX_BYTES: usize = GGUF_CANON_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        let n = self.len as usize;
        if n > out.len() {
            return Err(CANON_OVERFLOW);
        }
        out[..n].copy_from_slice(&self.bytes[..n]);
        Ok(n)
    }
}

register_shape!(GgufValueRegistry, GgufValue);

/// Slice-output canonicalizer — identity on the already-canonical bytes.
pub fn canonicalize_into_slice(canonical: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
    if canonical.len() > out.len() {
        return Err(CANON_OVERFLOW);
    }
    out[..canonical.len()].copy_from_slice(canonical);
    Ok(canonical.len())
}

impl crate::common::AddressInput for GgufValue {
    type Registry = GgufValueRegistry;

    #[inline]
    fn canonicalize_into(parser_emitted: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        canonicalize_into_slice(parser_emitted, out)
    }

    #[inline]
    fn parse(input: &[u8]) -> Result<Self, ShapeViolation> {
        Self::parse(input)
    }
}

/// **Available only under the `alloc` feature.** Canonical structural
/// form as an owned `Vec<u8>`.
#[cfg(feature = "alloc")]
pub fn canonicalize(raw: &[u8]) -> Result<alloc::vec::Vec<u8>, ShapeViolation> {
    extern crate alloc;
    Ok(GgufValue::parse(raw)?.canonical_bytes().to_vec())
}
