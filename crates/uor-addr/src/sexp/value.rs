//! `SExprValue` — the typed S-expression carrier (wiki ADR-023 +
//! ADR-027 + ARCHITECTURE.md "Format-specific realizations" §
//! `uor-addr-sexp`).
//!
//! Runtime form is a structurally-tagged byte serialization of a
//! canonical S-expression, stored in a fixed-size stack buffer of
//! [`SEXPR_VALUE_MAX_BYTES`] bytes. The three structural cases —
//! Atom, Cons, Nil — each map to a known tag in the byte layout;
//! recursive children live inside the same flat buffer.
//!
//! # `no_std` + `no_alloc`
//!
//! [`SExprValue::parse`] is a single-pass tokenizer over `&[u8]` that
//! writes tagged bytes directly into the fixed buffer; there is no
//! intermediate AST. [`canonicalize_into_slice`] walks the tagged
//! bytes and emits Rivest canonical bytes (`<n>:<bytes>` for atoms,
//! `(s_1 s_2 ... s_n)` for proper lists, `()` for nil) directly into
//! the caller's `out` slice. No allocator.
//!
//! # Tagged byte layout
//!
//! ```text
//! SExprValue ::= Tag(1 byte) Payload
//!   Tag = 0x00 Nil       — no payload
//!   Tag = 0x01 Atom      — u16 BE length || N bytes (raw)
//!   Tag = 0x02 Cons      — SExprValue (car) || SExprValue (cdr)
//! ```
//!
//! All multi-byte length fields are big-endian.
//!
//! # Input syntax
//!
//! [`SExprValue::parse`] admits two equivalent surface syntaxes:
//!
//! - **Canonical (Rivest 1997 §4.3)** — `<n>:<bytes>` for atoms,
//!   `(<canonical> <canonical>)` for cons, `()` for nil.
//! - **Token list** — whitespace-separated tokens between
//!   parentheses, each token interpreted as an atom whose bytes are
//!   the token's UTF-8 representation.

use prism::pipeline::{
    register_shape, ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation,
    ViolationKind,
};

use crate::sexp::shapes::bounds::{
    MAX_SEXPR_ATOM_BYTES, MAX_SEXPR_DEPTH, MAX_SEXPR_ELEMENTS, SEXPR_VALUE_MAX_BYTES,
};

// ─── Tag byte constants ─────────────────────────────────────────────────

pub(crate) const TAG_NIL: u8 = 0x00;
pub(crate) const TAG_ATOM: u8 = 0x01;
pub(crate) const TAG_CONS: u8 = 0x02;

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

const INVALID_SEXPR_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/SExprValue",
    constraint_iri: "https://uor.foundation/addr/SExprValue/validUtf8SExpr",
    property_iri: "https://uor.foundation/addr/inputBytes",
    expected_range: "https://uor.foundation/addr/ValidUtf8SExpr",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

const DEPTH_BOUND_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/SExprValue",
    constraint_iri: "https://uor.foundation/addr/SExprValue/depthBound",
    property_iri: "https://uor.foundation/addr/SExprValue/depth",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_SEXPR_DEPTH as u32,
    kind: ViolationKind::CardinalityViolation,
};

const ATOM_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/SExprValue",
    constraint_iri: "https://uor.foundation/addr/SExprValue/atomWidth",
    property_iri: "https://uor.foundation/addr/SExprValue/atomByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_SEXPR_ATOM_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const ELEMENTS_BOUND_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/SExprValue",
    constraint_iri: "https://uor.foundation/addr/SExprValue/elementsBound",
    property_iri: "https://uor.foundation/addr/SExprValue/elementCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_SEXPR_ELEMENTS as u32,
    kind: ViolationKind::CardinalityViolation,
};

const TOTAL_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/SExprValue",
    constraint_iri: "https://uor.foundation/addr/SExprValue/serializedWidth",
    property_iri: "https://uor.foundation/addr/SExprValue/totalByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: SEXPR_VALUE_MAX_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const CORRUPT_TAGGED_BYTES: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/SExprValue",
    constraint_iri: "https://uor.foundation/addr/SExprValue/wellFormedTaggedBytes",
    property_iri: "https://uor.foundation/addr/SExprValue/taggedBytes",
    expected_range: "https://uor.foundation/addr/WellFormedTaggedSExprValue",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

// ─── SExprValue — the typed input carrier ────────────────────────────────

/// Typed S-expression input shape. Runtime bytes are the
/// structurally-tagged serialization documented in the module
/// header, stored in a fixed-size stack buffer.
#[derive(Clone)]
pub struct SExprValue {
    pub(crate) bytes: [u8; SEXPR_VALUE_MAX_BYTES],
    pub(crate) len: u16,
}

impl core::fmt::Debug for SExprValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SExprValue")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl PartialEq for SExprValue {
    fn eq(&self, other: &Self) -> bool {
        self.tagged_bytes() == other.tagged_bytes()
    }
}

impl Eq for SExprValue {}

impl SExprValue {
    /// Parse raw S-expression bytes into a typed `SExprValue`.
    ///
    /// Accepts both Rivest canonical form (`<n>:<bytes>`) and the
    /// token-list sugar (whitespace-separated tokens between parens).
    ///
    /// # Errors
    ///
    /// - `validUtf8SExpr` — input is not valid UTF-8 S-expression.
    /// - `depthBound` — nesting depth exceeds [`MAX_SEXPR_DEPTH`].
    /// - `atomWidth` — an atom exceeds [`MAX_SEXPR_ATOM_BYTES`] UTF-8 bytes.
    /// - `elementsBound` — a cons-list exceeds [`MAX_SEXPR_ELEMENTS`] elements.
    /// - `serializedWidth` — the tagged byte serialization exceeds
    ///   [`SEXPR_VALUE_MAX_BYTES`].
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        // UTF-8 validation up front (we then iterate by byte; the
        // ASCII whitespace + paren handling does not need code-point
        // iteration).
        core::str::from_utf8(raw).map_err(|_| INVALID_SEXPR_VIOLATION)?;
        let mut value = Self {
            bytes: [0u8; SEXPR_VALUE_MAX_BYTES],
            len: 0,
        };
        let mut p = Parser::new(raw);
        p.skip_ws();
        parse_expr(&mut p, &mut value, 0)?;
        p.skip_ws();
        if !p.is_eof() {
            return Err(INVALID_SEXPR_VIOLATION);
        }
        Ok(value)
    }

    /// Borrow the structurally-tagged byte serialization.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    fn push_byte(&mut self, b: u8) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos >= SEXPR_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos] = b;
        self.len += 1;
        Ok(())
    }

    fn push_u16_be(&mut self, v: u16) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos + 2 > SEXPR_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        let bytes = v.to_be_bytes();
        self.bytes[pos] = bytes[0];
        self.bytes[pos + 1] = bytes[1];
        self.len += 2;
        Ok(())
    }

    fn extend(&mut self, data: &[u8]) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos + data.len() > SEXPR_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos..pos + data.len()].copy_from_slice(data);
        self.len += data.len() as u16;
        Ok(())
    }
}

// ─── Convenience alloc surface (feature = "alloc") ──────────────────────

/// Parse raw S-expression bytes and emit Rivest canonical
/// S-expression bytes — the same bytes ψ_9 hashes inside the
/// typed-iso surface.
///
/// **Available only under the `alloc` feature.** The no_alloc
/// equivalent is [`canonicalize_into_slice`] which writes into a
/// caller-supplied `&mut [u8]`.
///
/// # Errors
///
/// Surfaces any [`ShapeViolation`] [`SExprValue::parse`] would emit.
#[cfg(feature = "alloc")]
pub fn canonicalize(raw: &[u8]) -> Result<alloc::vec::Vec<u8>, ShapeViolation> {
    extern crate alloc;
    let value = SExprValue::parse(raw)?;
    let mut out = alloc::vec![0u8; SEXPR_VALUE_MAX_BYTES * 2];
    let n = canonicalize_into_slice(value.tagged_bytes(), &mut out)?;
    out.truncate(n);
    Ok(out)
}

// ─── Streaming surface-syntax tokenizer ─────────────────────────────────

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn peek(&self) -> Result<u8, ShapeViolation> {
        if self.is_eof() {
            return Err(INVALID_SEXPR_VIOLATION);
        }
        Ok(self.src[self.pos])
    }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }
}

fn parse_expr(
    p: &mut Parser<'_>,
    out: &mut SExprValue,
    depth: usize,
) -> Result<(), ShapeViolation> {
    if depth > MAX_SEXPR_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    p.skip_ws();
    let b = p.peek()?;
    if b == b'(' {
        p.pos += 1;
        parse_list(p, out, depth + 1)
    } else if b.is_ascii_digit() && peek_canonical_atom(p) {
        parse_canonical_atom(p, out)
    } else {
        parse_token_atom(p, out)
    }
}

fn peek_canonical_atom(p: &Parser<'_>) -> bool {
    let mut i = p.pos;
    while i < p.src.len() && p.src[i].is_ascii_digit() {
        i += 1;
    }
    i < p.src.len() && p.src[i] == b':' && i > p.pos
}

fn parse_canonical_atom(p: &mut Parser<'_>, out: &mut SExprValue) -> Result<(), ShapeViolation> {
    let start = p.pos;
    while p.pos < p.src.len() && p.src[p.pos].is_ascii_digit() {
        p.pos += 1;
    }
    let len_str =
        core::str::from_utf8(&p.src[start..p.pos]).map_err(|_| INVALID_SEXPR_VIOLATION)?;
    let len: usize = len_str.parse().map_err(|_| INVALID_SEXPR_VIOLATION)?;
    if p.pos >= p.src.len() || p.src[p.pos] != b':' {
        return Err(INVALID_SEXPR_VIOLATION);
    }
    p.pos += 1; // consume ':'
    if len > MAX_SEXPR_ATOM_BYTES {
        return Err(ATOM_WIDTH_VIOLATION);
    }
    if p.pos + len > p.src.len() {
        return Err(INVALID_SEXPR_VIOLATION);
    }
    let bytes = &p.src[p.pos..p.pos + len];
    p.pos += len;
    out.push_byte(TAG_ATOM)?;
    out.push_u16_be(len as u16)?;
    out.extend(bytes)
}

fn parse_token_atom(p: &mut Parser<'_>, out: &mut SExprValue) -> Result<(), ShapeViolation> {
    let start = p.pos;
    while p.pos < p.src.len() {
        let b = p.src[p.pos];
        if b.is_ascii_whitespace() || b == b'(' || b == b')' {
            break;
        }
        p.pos += 1;
    }
    let bytes = &p.src[start..p.pos];
    if bytes.is_empty() {
        return Err(INVALID_SEXPR_VIOLATION);
    }
    if bytes.len() > MAX_SEXPR_ATOM_BYTES {
        return Err(ATOM_WIDTH_VIOLATION);
    }
    out.push_byte(TAG_ATOM)?;
    out.push_u16_be(bytes.len() as u16)?;
    out.extend(bytes)
}

/// Parse a list body — emit a chain of `TAG_CONS car cdr` then
/// `TAG_NIL` for the proper-list tail. Walks children one at a time
/// without buffering, by reserving each Cons's car position before
/// recursing and stitching the cdr chain post-recursion.
///
/// The streaming approach: emit a TAG_CONS for each element seen,
/// recurse on the element (which writes the car), then continue with
/// the next element or terminate with TAG_NIL. Since the tagged form
/// for a list `(a b c)` is `CONS a CONS b CONS c NIL`, the emit order
/// matches the parse order — pure forward streaming.
fn parse_list(
    p: &mut Parser<'_>,
    out: &mut SExprValue,
    depth: usize,
) -> Result<(), ShapeViolation> {
    let mut element_count: u32 = 0;
    loop {
        p.skip_ws();
        if p.is_eof() {
            return Err(INVALID_SEXPR_VIOLATION);
        }
        if p.src[p.pos] == b')' {
            p.pos += 1;
            // Close the cons chain.
            out.push_byte(TAG_NIL)?;
            return Ok(());
        }
        if element_count as usize >= MAX_SEXPR_ELEMENTS {
            return Err(ELEMENTS_BOUND_VIOLATION);
        }
        out.push_byte(TAG_CONS)?;
        parse_expr(p, out, depth)?;
        element_count += 1;
    }
}

// ─── Streaming Rivest canonicalizer (tagged bytes → canonical bytes) ────

/// Decode tagged bytes and emit Rivest canonical S-expression bytes
/// into `out`. Returns the number of bytes written. The ψ_9 resolver
/// invokes this inside its resolver body per ADR-046's
/// iterative-resolution discipline.
///
/// # Errors
///
/// - [`CORRUPT_TAGGED_BYTES`] — the tagged buffer is truncated or
///   carries an unknown structural tag.
/// - [`TOTAL_WIDTH_VIOLATION`] — the canonical-form bytes exceed
///   `out.len()`.
pub fn canonicalize_into_slice(tagged: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
    let mut writer = SliceWriter::new(out);
    let mut pos = 0;
    emit_value(tagged, &mut pos, &mut writer, 0)?;
    if pos != tagged.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    Ok(writer.pos)
}

struct SliceWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0 }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), ShapeViolation> {
        if self.pos + bytes.len() > self.out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.out[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    fn write_byte(&mut self, b: u8) -> Result<(), ShapeViolation> {
        self.write(&[b])
    }
}

fn read_byte(tagged: &[u8], pos: &mut usize) -> Result<u8, ShapeViolation> {
    if *pos >= tagged.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let b = tagged[*pos];
    *pos += 1;
    Ok(b)
}

fn read_u16_be(tagged: &[u8], pos: &mut usize) -> Result<u16, ShapeViolation> {
    if *pos + 2 > tagged.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let v = u16::from_be_bytes([tagged[*pos], tagged[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_slice<'a>(
    tagged: &'a [u8],
    pos: &mut usize,
    len: usize,
) -> Result<&'a [u8], ShapeViolation> {
    if *pos + len > tagged.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let s = &tagged[*pos..*pos + len];
    *pos += len;
    Ok(s)
}

fn emit_value(
    tagged: &[u8],
    pos: &mut usize,
    w: &mut SliceWriter<'_>,
    depth: usize,
) -> Result<(), ShapeViolation> {
    if depth > MAX_SEXPR_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    let tag = read_byte(tagged, pos)?;
    match tag {
        TAG_NIL => w.write(b"()"),
        TAG_ATOM => {
            let len = read_u16_be(tagged, pos)? as usize;
            let bytes = read_slice(tagged, pos, len)?;
            emit_atom(len, bytes, w)
        }
        TAG_CONS => emit_list(tagged, pos, w, depth + 1),
        _ => Err(CORRUPT_TAGGED_BYTES),
    }
}

fn emit_atom(len: usize, bytes: &[u8], w: &mut SliceWriter<'_>) -> Result<(), ShapeViolation> {
    let mut buf = [0u8; 20];
    let len_str = format_usize_into(&mut buf, len);
    w.write(len_str)?;
    w.write_byte(b':')?;
    w.write(bytes)
}

/// Emit a Rivest flat-list form `(s_1 s_2 ... s_n)`. We've already
/// consumed the leading TAG_CONS; iterate by alternating "read child
/// + read next tag (CONS or NIL)".
fn emit_list(
    tagged: &[u8],
    pos: &mut usize,
    w: &mut SliceWriter<'_>,
    depth: usize,
) -> Result<(), ShapeViolation> {
    w.write_byte(b'(')?;
    // First child of this cons.
    emit_value(tagged, pos, w, depth)?;
    loop {
        let next_tag = read_byte(tagged, pos)?;
        match next_tag {
            TAG_NIL => {
                w.write_byte(b')')?;
                return Ok(());
            }
            TAG_CONS => {
                w.write_byte(b' ')?;
                emit_value(tagged, pos, w, depth)?;
            }
            TAG_ATOM => {
                // Improper-list tail — emit Rivest's dotted-pair form.
                // Unreachable for inputs constructed through
                // `SExprValue::parse` (the parser only emits proper
                // lists), defensive for substrate-corrupted bytes.
                let len = read_u16_be(tagged, pos)? as usize;
                let bytes = read_slice(tagged, pos, len)?;
                w.write(b" . ")?;
                emit_atom(len, bytes, w)?;
                w.write_byte(b')')?;
                return Ok(());
            }
            _ => return Err(CORRUPT_TAGGED_BYTES),
        }
    }
}

/// `usize → ASCII decimal` without alloc beyond a 20-byte scratch.
fn format_usize_into(buf: &mut [u8; 20], mut n: usize) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut idx = buf.len();
    while n > 0 {
        idx -= 1;
        buf[idx] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[idx..]
}

// ─── ConstrainedTypeShape + IntoBindingValue + AddressInput ──────────────

impl ConstrainedTypeShape for SExprValue {
    const IRI: &'static str = "https://uor.foundation/addr/SExprValue";
    const SITE_COUNT: usize = SEXPR_VALUE_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for SExprValue {}

impl IntoBindingValue for SExprValue {
    const MAX_BYTES: usize = SEXPR_VALUE_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        let n = self.len as usize;
        if n > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..n].copy_from_slice(&self.bytes[..n]);
        Ok(n)
    }
}

register_shape!(SExprValueRegistry, SExprValue);

impl crate::common::AddressInput for SExprValue {
    type Registry = SExprValueRegistry;

    #[inline]
    fn canonicalize_into(parser_emitted: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        canonicalize_into_slice(parser_emitted, out)
    }

    #[inline]
    fn parse(input: &[u8]) -> Result<Self, ShapeViolation> {
        Self::parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nil() {
        let v = SExprValue::parse(b"()").expect("valid nil");
        assert_eq!(v.bytes[0], TAG_NIL);
        assert_eq!(v.len, 1);
    }

    #[test]
    fn parses_atom_canonical_form() {
        let v = SExprValue::parse(b"5:hello").expect("valid canonical atom");
        assert_eq!(v.bytes[0], TAG_ATOM);
    }

    #[test]
    fn parses_token_list() {
        let v = SExprValue::parse(b"(a b c)").expect("valid token list");
        assert_eq!(v.bytes[0], TAG_CONS);
    }

    #[test]
    fn rejects_invalid_input() {
        let err = SExprValue::parse(b"((").expect_err("unbalanced parens");
        assert_eq!(err.constraint_iri, INVALID_SEXPR_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_overdeep_recursion() {
        extern crate alloc;
        let mut s = alloc::string::String::new();
        for _ in 0..(MAX_SEXPR_DEPTH + 2) {
            s.push('(');
        }
        s.push('x');
        for _ in 0..(MAX_SEXPR_DEPTH + 2) {
            s.push(')');
        }
        let err = SExprValue::parse(s.as_bytes()).expect_err("must reject");
        assert_eq!(err.constraint_iri, DEPTH_BOUND_VIOLATION.constraint_iri);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn rejects_oversize_atom() {
        extern crate alloc;
        use alloc::string::String;
        let big: String = "a".repeat(MAX_SEXPR_ATOM_BYTES + 1);
        let err = SExprValue::parse(big.as_bytes()).expect_err("must reject");
        assert_eq!(err.constraint_iri, ATOM_WIDTH_VIOLATION.constraint_iri);
    }

    #[cfg(feature = "alloc")]
    const CANONICAL_FIXTURES: &[(&[u8], &[u8])] = &[
        (b"()", b"()"),
        (b"(a b c)", b"(1:a 1:b 1:c)"),
        (b"5:hello", b"5:hello"),
        (b"(hello world)", b"(5:hello 5:world)"),
        (b"((a) (b))", b"((1:a) (1:b))"),
        (b"(a (b c) d)", b"(1:a (1:b 1:c) 1:d)"),
        (b"(  a\t b\n c  )", b"(1:a 1:b 1:c)"),
        (b"(1:a 1:b 1:c)", b"(1:a 1:b 1:c)"),
    ];

    #[cfg(feature = "alloc")]
    #[test]
    fn canonicalizer_matches_rivest_canonical_form() {
        for (raw, expected) in CANONICAL_FIXTURES {
            let canon = canonicalize(raw).expect("valid");
            assert_eq!(canon, *expected, "raw={raw:?}");
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn canonicalize_is_idempotent_on_its_own_output() {
        for (raw, _expected) in CANONICAL_FIXTURES {
            let once = canonicalize(raw).expect("valid");
            let twice = canonicalize(&once).expect("re-canonicalises");
            assert_eq!(once, twice, "idempotence broken for {raw:?}");
        }
    }
}
