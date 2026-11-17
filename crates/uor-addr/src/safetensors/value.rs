//! safetensors typed input: admission rules and the canonical skeleton.
//!
//! ```text
//! b"SAFE" || LE_u32(CANONICAL_FORM_VERSION)
//! LE_u64(tensor_count) || LE_u64(metadata_count)
//! ── __metadata__ entries, sorted by key bytes ──
//!   blake3(key) || LE_u64(len(value)) || blake3(value)
//! ── tensors, sorted by name bytes ──
//!   blake3(name) || LE_u32(dtype_id) || LE_u32(rank) || (LE_u64(dim) × rank)
//!       || LE_u64(canonical_offset)
//!       || blake3(tensor data bytes)        ← binds the weights
//! ```
//!
//! Keys, names and values are the UTF-8 bytes of the decoded JSON string:
//! escapes resolved, no Unicode normalization (normalizing would merge two
//! tensors whose names the format keeps apart). `canonical_offset` is the
//! cumulative byte position in sorted-name order, so stored offsets and the
//! buffer's tensor order do not move the label.
//!
//! Admission follows the reference implementation's validation, and is
//! stricter where it leaves a choice open, because anything admitted but
//! not bound would let two different files share a label:
//!
//! - the header is at most [`SAFETENSORS_MAX_HEADER_BYTES`], valid UTF-8,
//!   and exactly one JSON object followed only by whitespace;
//! - duplicate keys are refused, at every level;
//! - a tensor entry has exactly `dtype`, `shape` and `data_offsets`;
//!   dimensions and offsets are non-negative integers below 2^64;
//! - `__metadata__`, if present, maps strings to strings;
//! - a tensor's byte length is its dtype's bits × the product of its shape,
//!   divided by 8, with no remainder;
//! - tensors cover the buffer exactly: contiguous from offset 0, no holes,
//!   no overlap, and no bytes after the last one.

use prism::crypto::Blake3Hasher;
use prism::operation::TermValue;
use prism::pipeline::{
    ConstrainedTypeShape, ConstraintRef, IntoBindingValue, PartitionProductFields, ShapeViolation,
    ViolationKind,
};
use prism::vocabulary::Hasher;

use alloc::vec::Vec;

use crate::safetensors::dtype::SafetensorsDtype;
use crate::safetensors::{
    CANONICAL_FORM_VERSION, SAFETENSORS_MAX_HEADER_BYTES, SAFETENSORS_SKELETON_TAG,
};

macro_rules! violation {
    ($name:ident, $constraint:literal, $property:literal, $kind:expr) => {
        const $name: ShapeViolation = ShapeViolation {
            shape_iri: "https://uor.foundation/addr/SafetensorsValue",
            constraint_iri: concat!("https://uor.foundation/addr/SafetensorsValue/", $constraint),
            property_iri: concat!("https://uor.foundation/addr/SafetensorsValue/", $property),
            expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
            min_count: 0,
            max_count: 1,
            kind: $kind,
        };
    };
}

violation!(
    TRUNCATED,
    "notTruncated",
    "byteSpan",
    ViolationKind::ValueCheck
);
violation!(
    HEADER_TOO_LARGE,
    "headerBound",
    "headerLength",
    ViolationKind::CardinalityViolation
);
violation!(
    INVALID_HEADER,
    "wellFormedHeader",
    "header",
    ViolationKind::ValueCheck
);
violation!(
    DUPLICATE_KEY,
    "uniqueKeys",
    "key",
    ViolationKind::ValueCheck
);
violation!(
    UNKNOWN_DTYPE,
    "knownDtype",
    "dtype",
    ViolationKind::ValueCheck
);
violation!(
    TENSOR_SIZE,
    "sizeMatchesShape",
    "dataOffsets",
    ViolationKind::ValueCheck
);
violation!(
    UNCOVERED_BUFFER,
    "bufferCovered",
    "dataOffsets",
    ViolationKind::ValueCheck
);

#[inline]
fn blake3(bytes: &[u8]) -> [u8; 32] {
    Blake3Hasher::initial().fold_bytes(bytes).finalize()
}

// ─── SafetensorsCarrier — the borrowed model-input handle ────────────────

/// Borrowed canonical-skeleton input handle (ADR-060 borrowed carrier).
#[derive(Clone, Copy, Debug)]
pub struct SafetensorsCarrier<'a>(&'a [u8]);

impl<'a> SafetensorsCarrier<'a> {
    /// Wrap a canonical-skeleton byte slice as a model input handle.
    #[must_use]
    pub fn new(skeleton: &'a [u8]) -> Self {
        Self(skeleton)
    }

    /// Borrow the canonical-skeleton bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl ConstrainedTypeShape for SafetensorsCarrier<'_> {
    const IRI: &'static str = "https://uor.foundation/addr/SafetensorsValue";
    const SITE_COUNT: usize = 1;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for SafetensorsCarrier<'_> {}

impl<'a> IntoBindingValue<'a> for SafetensorsCarrier<'a> {
    fn as_binding_value<const INLINE_BYTES: usize>(&self) -> TermValue<'a, INLINE_BYTES> {
        TermValue::borrowed(self.0)
    }
}

impl PartitionProductFields for SafetensorsCarrier<'_> {
    const FIELDS: &'static [(u32, u32)] = &[];
    const FIELD_NAMES: &'static [&'static str] = &[];
}

// ─── The header, read strictly ───────────────────────────────────────────

struct TensorEntry {
    name: Vec<u8>,
    dtype: SafetensorsDtype,
    shape: Vec<u64>,
    begin: u64,
    end: u64,
}

struct Header {
    tensors: Vec<TensorEntry>,
    metadata: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A reader for exactly the JSON the format admits. It is not a general
/// JSON parser on purpose: every construct it does not expect is refused,
/// so nothing reaches the skeleton that the skeleton does not bind.
struct Json<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Json<'a> {
    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.b.get(self.p) {
            self.p += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.b.get(self.p).copied()
    }

    fn eat(&mut self, c: u8) -> Result<(), ShapeViolation> {
        if self.peek() == Some(c) {
            self.p += 1;
            Ok(())
        } else {
            Err(INVALID_HEADER)
        }
    }

    fn hex4(&mut self) -> Result<u32, ShapeViolation> {
        let digits = self.b.get(self.p..self.p + 4).ok_or(INVALID_HEADER)?;
        self.p += 4;
        digits.iter().try_fold(0u32, |acc, &d| {
            let v = (d as char).to_digit(16).ok_or(INVALID_HEADER)?;
            Ok(acc * 16 + v)
        })
    }

    /// A JSON string, decoded to UTF-8 bytes. The header was checked to be
    /// UTF-8 before reading, so raw bytes pass through; escapes are
    /// resolved, and an escape naming a lone surrogate is refused.
    fn string(&mut self) -> Result<Vec<u8>, ShapeViolation> {
        self.eat(b'"')?;
        let mut out = Vec::new();
        loop {
            let c = *self.b.get(self.p).ok_or(INVALID_HEADER)?;
            self.p += 1;
            match c {
                b'"' => return Ok(out),
                0x00..=0x1f => return Err(INVALID_HEADER),
                b'\\' => {
                    let e = *self.b.get(self.p).ok_or(INVALID_HEADER)?;
                    self.p += 1;
                    let simple = match e {
                        b'"' => Some(b'"'),
                        b'\\' => Some(b'\\'),
                        b'/' => Some(b'/'),
                        b'b' => Some(0x08),
                        b'f' => Some(0x0c),
                        b'n' => Some(b'\n'),
                        b'r' => Some(b'\r'),
                        b't' => Some(b'\t'),
                        b'u' => None,
                        _ => return Err(INVALID_HEADER),
                    };
                    if let Some(s) = simple {
                        out.push(s);
                        continue;
                    }
                    let hi = self.hex4()?;
                    let code = if (0xd800..0xdc00).contains(&hi) {
                        if self.b.get(self.p..self.p + 2) != Some(b"\\u") {
                            return Err(INVALID_HEADER);
                        }
                        self.p += 2;
                        let lo = self.hex4()?;
                        if !(0xdc00..0xe000).contains(&lo) {
                            return Err(INVALID_HEADER);
                        }
                        0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                    } else if (0xdc00..0xe000).contains(&hi) {
                        return Err(INVALID_HEADER);
                    } else {
                        hi
                    };
                    let ch = char::from_u32(code).ok_or(INVALID_HEADER)?;
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => out.push(c),
            }
        }
    }

    /// A non-negative JSON integer below 2^64. Fractions, exponents and
    /// signs are refused rather than rounded.
    fn uint(&mut self) -> Result<u64, ShapeViolation> {
        self.ws();
        let start = self.p;
        while let Some(b'0'..=b'9') = self.b.get(self.p) {
            self.p += 1;
        }
        let digits = &self.b[start..self.p];
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return Err(INVALID_HEADER);
        }
        if let Some(b'.' | b'e' | b'E') = self.b.get(self.p) {
            return Err(INVALID_HEADER);
        }
        digits.iter().try_fold(0u64, |acc, &d| {
            acc.checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(d - b'0')))
                .ok_or(INVALID_HEADER)
        })
    }

    fn uint_array(&mut self) -> Result<Vec<u64>, ShapeViolation> {
        self.eat(b'[')?;
        let mut out = Vec::new();
        if self.peek() == Some(b']') {
            self.p += 1;
            return Ok(out);
        }
        loop {
            out.push(self.uint()?);
            match self.peek() {
                Some(b',') => self.p += 1,
                Some(b']') => {
                    self.p += 1;
                    return Ok(out);
                }
                _ => return Err(INVALID_HEADER),
            }
        }
    }

    /// The members of one object, each handed to `member` with its key.
    /// Duplicate keys are refused here, once, for every object.
    fn object(
        &mut self,
        mut member: impl FnMut(&mut Self, Vec<u8>) -> Result<(), ShapeViolation>,
    ) -> Result<(), ShapeViolation> {
        self.eat(b'{')?;
        let mut seen: Vec<Vec<u8>> = Vec::new();
        if self.peek() == Some(b'}') {
            self.p += 1;
            return Ok(());
        }
        loop {
            let key = self.string()?;
            if seen.contains(&key) {
                return Err(DUPLICATE_KEY);
            }
            seen.push(key.clone());
            self.eat(b':')?;
            member(self, key)?;
            match self.peek() {
                Some(b',') => self.p += 1,
                Some(b'}') => {
                    self.p += 1;
                    return Ok(());
                }
                _ => return Err(INVALID_HEADER),
            }
        }
    }

    fn tensor(&mut self, name: Vec<u8>) -> Result<TensorEntry, ShapeViolation> {
        let (mut dtype, mut shape, mut offsets) = (None, None, None);
        self.object(|j, key| {
            match key.as_slice() {
                b"dtype" => {
                    let n = j.string()?;
                    dtype = Some(SafetensorsDtype::from_name(&n).ok_or(UNKNOWN_DTYPE)?);
                }
                b"shape" => shape = Some(j.uint_array()?),
                b"data_offsets" => offsets = Some(j.uint_array()?),
                _ => return Err(INVALID_HEADER),
            }
            Ok(())
        })?;
        let (dtype, shape, offsets) = (
            dtype.ok_or(INVALID_HEADER)?,
            shape.ok_or(INVALID_HEADER)?,
            offsets.ok_or(INVALID_HEADER)?,
        );
        let [begin, end] = offsets[..] else {
            return Err(INVALID_HEADER);
        };
        Ok(TensorEntry {
            name,
            dtype,
            shape,
            begin,
            end,
        })
    }

    fn header(&mut self) -> Result<Header, ShapeViolation> {
        let mut tensors = Vec::new();
        let mut metadata = Vec::new();
        self.object(|j, key| {
            if key == b"__metadata__" {
                j.object(|j, k| {
                    let v = j.string()?;
                    metadata.push((k, v));
                    Ok(())
                })
            } else {
                tensors.push(j.tensor(key)?);
                Ok(())
            }
        })?;
        self.ws();
        if self.p != self.b.len() {
            return Err(INVALID_HEADER);
        }
        Ok(Header { tensors, metadata })
    }
}

/// A tensor's byte length from its dtype and shape. Overflow is refused
/// over the non-zero dimensions even when a zero dimension makes the
/// tensor empty, as the reference implementation does.
fn byte_length(dtype: SafetensorsDtype, shape: &[u64]) -> Result<u64, ShapeViolation> {
    let bits = shape
        .iter()
        .filter(|&&d| d != 0)
        .try_fold(dtype.bits(), |acc, &d| acc.checked_mul(d))
        .ok_or(TENSOR_SIZE)?;
    let bits = if shape.contains(&0) { 0 } else { bits };
    if bits % 8 != 0 {
        return Err(TENSOR_SIZE);
    }
    Ok(bits / 8)
}

// ─── SafetensorsValue — the owned, canonicalized file ────────────────────

/// A parsed, canonicalized safetensors file. The stored bytes are the flat
/// canonical skeleton (see the [module docs](self)).
#[derive(Clone, PartialEq, Eq)]
pub struct SafetensorsValue {
    bytes: Vec<u8>,
}

impl core::fmt::Debug for SafetensorsValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SafetensorsValue")
            .field("canonical_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl SafetensorsValue {
    /// Borrow the canonical-skeleton bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parse a safetensors file into its canonical skeleton.
    ///
    /// # Errors
    ///
    /// A [`ShapeViolation`] whose `constraint_iri` names the violated rule:
    /// `notTruncated`, `headerBound`, `wellFormedHeader`, `uniqueKeys`,
    /// `knownDtype`, `sizeMatchesShape`, or `bufferCovered`.
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let len_bytes: [u8; 8] = raw
            .get(..8)
            .ok_or(TRUNCATED)?
            .try_into()
            .map_err(|_| TRUNCATED)?;
        let n = u64::from_le_bytes(len_bytes);
        if n > SAFETENSORS_MAX_HEADER_BYTES {
            return Err(HEADER_TOO_LARGE);
        }
        // n is at most 100 MB, so it fits a usize on every target that can
        // hold the file at all.
        let data_start = 8 + n as usize;
        let header = raw.get(8..data_start).ok_or(TRUNCATED)?;
        core::str::from_utf8(header).map_err(|_| INVALID_HEADER)?;
        let Header {
            mut tensors,
            mut metadata,
        } = Json { b: header, p: 0 }.header()?;
        let data = &raw[data_start..];

        for t in &tensors {
            if t.end < t.begin || t.end - t.begin != byte_length(t.dtype, &t.shape)? {
                return Err(TENSOR_SIZE);
            }
        }

        // Exact cover: in offset order, each tensor starts where the last
        // ended, from 0 to the end of the buffer.
        let mut by_offset: Vec<&TensorEntry> = tensors.iter().collect();
        by_offset.sort_by_key(|t| (t.begin, t.end));
        let mut at = 0u64;
        for t in by_offset {
            if t.begin != at {
                return Err(UNCOVERED_BUFFER);
            }
            at = t.end;
        }
        if at != data.len() as u64 {
            return Err(UNCOVERED_BUFFER);
        }

        metadata.sort_by(|a, b| a.0.cmp(&b.0));
        tensors.sort_by(|a, b| a.name.cmp(&b.name));

        let mut out = Vec::new();
        out.extend_from_slice(&SAFETENSORS_SKELETON_TAG);
        out.extend_from_slice(&CANONICAL_FORM_VERSION.to_le_bytes());
        out.extend_from_slice(&(tensors.len() as u64).to_le_bytes());
        out.extend_from_slice(&(metadata.len() as u64).to_le_bytes());
        for (k, v) in &metadata {
            out.extend_from_slice(&blake3(k));
            out.extend_from_slice(&(v.len() as u64).to_le_bytes());
            out.extend_from_slice(&blake3(v));
        }
        let mut offset = 0u64;
        for t in &tensors {
            out.extend_from_slice(&blake3(&t.name));
            out.extend_from_slice(&t.dtype.id().to_le_bytes());
            out.extend_from_slice(&(t.shape.len() as u32).to_le_bytes());
            for d in &t.shape {
                out.extend_from_slice(&d.to_le_bytes());
            }
            out.extend_from_slice(&offset.to_le_bytes());
            // Offsets were checked against the buffer length above.
            out.extend_from_slice(&blake3(&data[t.begin as usize..t.end as usize]));
            offset += t.end - t.begin;
        }
        Ok(Self { bytes: out })
    }
}

/// Canonical skeleton as an owned `Vec<u8>`.
///
/// # Errors
///
/// Surfaces the [`ShapeViolation`] [`SafetensorsValue::parse`] would raise.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, ShapeViolation> {
    Ok(SafetensorsValue::parse(raw)?.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(header: &[u8], data: &[u8]) -> Vec<u8> {
        let mut v = (header.len() as u64).to_le_bytes().to_vec();
        v.extend_from_slice(header);
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn empty_header_is_the_bare_skeleton() {
        let s = canonicalize(&file(b"{}", &[])).expect("valid");
        // tag(4) + version(4) + tensor count(8) + metadata count(8).
        assert_eq!(s.len(), 24);
        assert_eq!(&s[..4], b"SAFE");
    }

    #[test]
    fn each_rule_names_itself() {
        let cases: [(&[u8], &[u8], ShapeViolation); 5] = [
            (br#"{"a":1}"#, &[], INVALID_HEADER),
            (br#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"a":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}"#, &[0; 8], DUPLICATE_KEY),
            (br#"{"a":{"dtype":"Q4","shape":[1],"data_offsets":[0,4]}}"#, &[0; 4], UNKNOWN_DTYPE),
            (br#"{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,4]}}"#, &[0; 4], TENSOR_SIZE),
            (br#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#, &[0; 5], UNCOVERED_BUFFER),
        ];
        for (header, data, expected) in cases {
            let err = SafetensorsValue::parse(&file(header, data)).expect_err("refused");
            assert_eq!(err.constraint_iri, expected.constraint_iri);
        }
        let mut big = file(b"{}", &[]);
        big[..8].copy_from_slice(&(SAFETENSORS_MAX_HEADER_BYTES + 1).to_le_bytes());
        assert_eq!(
            SafetensorsValue::parse(&big)
                .expect_err("refused")
                .constraint_iri,
            HEADER_TOO_LARGE.constraint_iri
        );
        assert_eq!(
            SafetensorsValue::parse(&[0; 7])
                .expect_err("refused")
                .constraint_iri,
            TRUNCATED.constraint_iri
        );
    }
}
