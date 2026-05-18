//! `SExprValue` — the typed S-expression carrier (wiki ADR-023 +
//! ADR-027 + ARCHITECTURE.md "Format-specific realizations" §
//! `uor-addr-sexp`).
//!
//! The PrismModel's `Input` for the S-expression realization is
//! [`SExprValue`], a typed carrier whose runtime bytes are a
//! structurally-tagged serialization of a canonical S-expression of
//! bounded depth and width. The three structural cases — Atom, Cons,
//! Nil — each map to a known tag in the byte layout; recursive
//! children live inside the same flat buffer.
//!
//! The host-boundary parser ([`SExprValue::parse`]) is the **only**
//! σ-projection that runs before construction. It validates that the
//! parsed value satisfies the typed-input bounds declared in
//! [`crate::sexp::shapes::bounds`]; failure surfaces as a
//! [`prism::pipeline::ShapeViolation`] with a constraint IRI keyed to
//! the violated bound.
//!
//! Canonicalization happens **inside the typed-iso surface** — the
//! ψ_9 resolver invokes the canonicalizer over the tagged bytes,
//! producing Rivest's canonical S-expression form
//! (`<n>:<bytes>` for atoms, `(car cdr)` for cons, `()` for nil)
//! that feeds the canonical hash axis.
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
//! All multi-byte length fields are big-endian. Total serialization
//! size is bounded by [`SEXPR_VALUE_MAX_BYTES`].
//!
//! # Input syntax
//!
//! [`SExprValue::parse`] admits two equivalent surface syntaxes:
//!
//! - **Canonical (Rivest)** — `<n>:<bytes>` for atoms,
//!   `(<canonical> <canonical>)` for cons, `()` for nil. Round-trip
//!   property: [`canonicalize`] is idempotent on canonical input.
//! - **Token list** — whitespace-separated tokens between
//!   parentheses, with each token interpreted as an atom whose bytes
//!   are the token's UTF-8 representation. The list `(a b c)`
//!   becomes `Cons(Atom("a"), Cons(Atom("b"), Cons(Atom("c"), Nil)))`.

extern crate alloc;

use alloc::vec::Vec;

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

// ─── Surface AST — only used by parser internals ───────────────────────

enum Surface {
    Atom(Vec<u8>),
    Cons(alloc::boxed::Box<Surface>, alloc::boxed::Box<Surface>),
    Nil,
}

// ─── SExprValue — the typed input carrier ────────────────────────────────

/// Typed S-expression input shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SExprValue {
    pub(crate) bytes: Vec<u8>,
}

impl SExprValue {
    /// Parse raw S-expression bytes into a typed `SExprValue`.
    ///
    /// Accepts both canonical Rivest form and the token-list sugar
    /// (see module-level docs).
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
        let text = core::str::from_utf8(raw).map_err(|_| INVALID_SEXPR_VIOLATION)?;
        let mut parser = Parser::new(text);
        let surface = parser.parse_expr(0)?;
        parser.skip_whitespace();
        if !parser.is_eof() {
            return Err(INVALID_SEXPR_VIOLATION);
        }
        let mut bytes = Vec::new();
        write_tagged(&surface, 0, &mut bytes)?;
        if bytes.len() > SEXPR_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        Ok(Self { bytes })
    }

    /// Borrow the structurally-tagged byte serialization.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Parse raw S-expression bytes and emit the canonical S-expression
/// bytes — the same bytes ψ_9 hashes inside the typed-iso surface.
///
/// # Errors
///
/// Surfaces any [`ShapeViolation`] [`SExprValue::parse`] would emit
/// for the same input.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, ShapeViolation> {
    let value = SExprValue::parse(raw)?;
    let mut canonical = Vec::with_capacity(value.bytes.len());
    canonicalize_into(&value.bytes, &mut canonical)?;
    Ok(canonical)
}

// ─── Surface-syntax parser (raw bytes → Surface tree) ────────────────────

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            src: text.as_bytes(),
            pos: 0,
        }
    }

    fn parse_expr(&mut self, depth: usize) -> Result<Surface, ShapeViolation> {
        if depth > MAX_SEXPR_DEPTH {
            return Err(DEPTH_BOUND_VIOLATION);
        }
        self.skip_whitespace();
        if self.is_eof() {
            return Err(INVALID_SEXPR_VIOLATION);
        }
        let b = self.src[self.pos];
        if b == b'(' {
            self.pos += 1;
            self.parse_list_body(depth + 1)
        } else if b.is_ascii_digit() && self.peek_canonical_atom() {
            self.parse_canonical_atom()
        } else {
            self.parse_token_atom()
        }
    }

    fn peek_canonical_atom(&self) -> bool {
        // Look ahead: digits followed by ':'
        let mut i = self.pos;
        while i < self.src.len() && self.src[i].is_ascii_digit() {
            i += 1;
        }
        i < self.src.len() && self.src[i] == b':' && i > self.pos
    }

    fn parse_canonical_atom(&mut self) -> Result<Surface, ShapeViolation> {
        let start = self.pos;
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let len_str = core::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| INVALID_SEXPR_VIOLATION)?;
        let len: usize = len_str.parse().map_err(|_| INVALID_SEXPR_VIOLATION)?;
        if self.pos >= self.src.len() || self.src[self.pos] != b':' {
            return Err(INVALID_SEXPR_VIOLATION);
        }
        self.pos += 1; // consume ':'
        if len > MAX_SEXPR_ATOM_BYTES {
            return Err(ATOM_WIDTH_VIOLATION);
        }
        if self.pos + len > self.src.len() {
            return Err(INVALID_SEXPR_VIOLATION);
        }
        let bytes = self.src[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(Surface::Atom(bytes))
    }

    fn parse_token_atom(&mut self) -> Result<Surface, ShapeViolation> {
        let start = self.pos;
        while self.pos < self.src.len() {
            let b = self.src[self.pos];
            if b.is_ascii_whitespace() || b == b'(' || b == b')' {
                break;
            }
            self.pos += 1;
        }
        let bytes = self.src[start..self.pos].to_vec();
        if bytes.is_empty() {
            return Err(INVALID_SEXPR_VIOLATION);
        }
        if bytes.len() > MAX_SEXPR_ATOM_BYTES {
            return Err(ATOM_WIDTH_VIOLATION);
        }
        Ok(Surface::Atom(bytes))
    }

    fn parse_list_body(&mut self, depth: usize) -> Result<Surface, ShapeViolation> {
        // Collect children until ')'.
        let mut children: Vec<Surface> = Vec::new();
        loop {
            self.skip_whitespace();
            if self.is_eof() {
                return Err(INVALID_SEXPR_VIOLATION);
            }
            if self.src[self.pos] == b')' {
                self.pos += 1;
                break;
            }
            if children.len() >= MAX_SEXPR_ELEMENTS {
                return Err(ELEMENTS_BOUND_VIOLATION);
            }
            children.push(self.parse_expr(depth)?);
        }
        // Build nested cons cells right-to-left.
        let mut acc = Surface::Nil;
        for child in children.into_iter().rev() {
            acc = Surface::Cons(alloc::boxed::Box::new(child), alloc::boxed::Box::new(acc));
        }
        Ok(acc)
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.src.len()
    }
}

// ─── Tagged-format writer (Surface tree → tagged bytes) ─────────────────

fn write_tagged(value: &Surface, depth: usize, out: &mut Vec<u8>) -> Result<(), ShapeViolation> {
    if depth > MAX_SEXPR_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    match value {
        Surface::Nil => {
            out.push(TAG_NIL);
        }
        Surface::Atom(bytes) => {
            if bytes.len() > MAX_SEXPR_ATOM_BYTES {
                return Err(ATOM_WIDTH_VIOLATION);
            }
            out.push(TAG_ATOM);
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        Surface::Cons(car, cdr) => {
            out.push(TAG_CONS);
            write_tagged(car, depth + 1, out)?;
            write_tagged(cdr, depth + 1, out)?;
        }
    }
    Ok(())
}

// ─── Tagged-format reader (tagged bytes → canonical bytes) ──────────────

/// Decode tagged bytes and emit Rivest canonical S-expression bytes
/// (`<n>:<bytes>` for atoms, `(car cdr)` for cons, `()` for nil).
/// Admitted by ADR-046's resolver-body iterative-resolution
/// discipline inside the ψ_9 resolver body.
pub(crate) fn canonicalize_into(tagged: &[u8], out: &mut Vec<u8>) -> Result<(), ShapeViolation> {
    let mut pos = 0;
    out.clear();
    write_canonical(tagged, &mut pos, 0, out)?;
    if pos != tagged.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    Ok(())
}

fn write_canonical(
    buf: &[u8],
    pos: &mut usize,
    depth: usize,
    out: &mut Vec<u8>,
) -> Result<(), ShapeViolation> {
    if depth > MAX_SEXPR_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    let tag = take_byte(buf, pos)?;
    match tag {
        TAG_NIL => {
            out.extend_from_slice(b"()");
            Ok(())
        }
        TAG_ATOM => {
            let len = take_u16(buf, pos)? as usize;
            let bytes = take_slice(buf, pos, len)?;
            let mut len_buf = itoa_buf();
            let len_str = format_usize_into(&mut len_buf, len);
            out.extend_from_slice(len_str);
            out.push(b':');
            out.extend_from_slice(bytes);
            Ok(())
        }
        TAG_CONS => {
            // Rivest canonical form for lists (Sexp.txt §4.3): flat
            // form `(s_1 s_2 ... s_n)`, not nested `(s_1 (s_2 (s_3 ())))`.
            // Walk the cons chain: open paren, write `car`, walk the
            // cdr chain — emitting space + cdr.car for each Cons,
            // stopping at Nil (proper list) or emitting a dotted-pair
            // continuation for Atom-tailed improper lists.
            out.push(b'(');
            // First element (the original Cons's car).
            write_canonical(buf, pos, depth + 1, out)?;
            // Walk the cdr chain.
            loop {
                let next_tag = take_byte(buf, pos)?;
                match next_tag {
                    TAG_NIL => {
                        out.push(b')');
                        return Ok(());
                    }
                    TAG_CONS => {
                        out.push(b' ');
                        write_canonical(buf, pos, depth + 1, out)?;
                        // continue walking this Cons's cdr
                    }
                    TAG_ATOM => {
                        // Improper-list tail — rare. Emit Rivest's
                        // dotted-pair extension form `(a . b)`. Our
                        // surface parser only produces proper lists,
                        // so this branch is unreachable for inputs
                        // built through `SExprValue::parse`; the
                        // branch is defensive for substrate-corrupted
                        // tagged bytes.
                        let len = take_u16(buf, pos)? as usize;
                        let bytes = take_slice(buf, pos, len)?;
                        out.extend_from_slice(b" . ");
                        let mut len_buf = itoa_buf();
                        let len_str = format_usize_into(&mut len_buf, len);
                        out.extend_from_slice(len_str);
                        out.push(b':');
                        out.extend_from_slice(bytes);
                        out.push(b')');
                        return Ok(());
                    }
                    _ => return Err(CORRUPT_TAGGED_BYTES),
                }
            }
        }
        _ => Err(CORRUPT_TAGGED_BYTES),
    }
}

// `usize → ASCII decimal` without alloc beyond a 20-byte scratch.
fn itoa_buf() -> [u8; 20] {
    [0u8; 20]
}

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

#[inline]
fn take_byte(buf: &[u8], pos: &mut usize) -> Result<u8, ShapeViolation> {
    if *pos >= buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let b = buf[*pos];
    *pos += 1;
    Ok(b)
}

#[inline]
fn take_u16(buf: &[u8], pos: &mut usize) -> Result<u16, ShapeViolation> {
    if *pos + 2 > buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let hi = buf[*pos];
    let lo = buf[*pos + 1];
    *pos += 2;
    Ok(u16::from_be_bytes([hi, lo]))
}

#[inline]
fn take_slice<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], ShapeViolation> {
    if *pos + len > buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let s = &buf[*pos..*pos + len];
    *pos += len;
    Ok(s)
}

/// Slice-output variant — the byte-output signature
/// [`crate::common::AddressInput::canonicalize_into`] requires.
pub(crate) fn canonicalize_into_slice(
    tagged: &[u8],
    out: &mut [u8],
) -> Result<usize, ShapeViolation> {
    let mut tmp = Vec::with_capacity(tagged.len());
    canonicalize_into(tagged, &mut tmp)?;
    if tmp.len() > out.len() {
        return Err(TOTAL_WIDTH_VIOLATION);
    }
    out[..tmp.len()].copy_from_slice(&tmp);
    Ok(tmp.len())
}

// ─── ConstrainedTypeShape + IntoBindingValue + AddressInput ──────────────

impl ConstrainedTypeShape for SExprValue {
    const IRI: &'static str = "https://uor.foundation/addr/SExprValue";
    /// One Site per tagged-byte position; per-byte sites carry the
    /// structurally-tagged S-expression value through the ψ-pipeline.
    const SITE_COUNT: usize = SEXPR_VALUE_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for SExprValue {}

impl IntoBindingValue for SExprValue {
    const MAX_BYTES: usize = SEXPR_VALUE_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if self.bytes.len() > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
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
        assert_eq!(v.bytes, vec![TAG_NIL]);
    }

    #[test]
    fn parses_atom_canonical_form() {
        let v = SExprValue::parse(b"5:hello").expect("valid canonical atom");
        assert_eq!(v.bytes[0], TAG_ATOM);
    }

    #[test]
    fn parses_token_list() {
        let v = SExprValue::parse(b"(a b c)").expect("valid token list");
        // Cons-of-Cons-of-Cons-of-Nil
        assert_eq!(v.bytes[0], TAG_CONS);
    }

    #[test]
    fn rejects_invalid_input() {
        let err = SExprValue::parse(b"((").expect_err("unbalanced parens");
        assert_eq!(err.constraint_iri, INVALID_SEXPR_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_overdeep_recursion() {
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

    #[test]
    fn rejects_oversize_atom() {
        let big = "a".repeat(MAX_SEXPR_ATOM_BYTES + 1);
        let err = SExprValue::parse(big.as_bytes()).expect_err("must reject");
        assert_eq!(err.constraint_iri, ATOM_WIDTH_VIOLATION.constraint_iri);
    }

    /// Canonical-form fixtures pinned against Rivest's "S-Expressions"
    /// (1997 draft, <https://people.csail.mit.edu/rivest/Sexp.txt>):
    /// flat list form `(s_1 s_2 ... s_n)` for proper lists, atoms as
    /// `<length>:<bytes>`, the empty list as `()`.
    const CANONICAL_FIXTURES: &[(&[u8], &[u8])] = &[
        (b"()", b"()"),
        (b"(a b c)", b"(1:a 1:b 1:c)"),
        (b"5:hello", b"5:hello"),
        (b"(hello world)", b"(5:hello 5:world)"),
        (b"((a) (b))", b"((1:a) (1:b))"),
        // Mixed-depth nesting.
        (b"(a (b c) d)", b"(1:a (1:b 1:c) 1:d)"),
        // Whitespace invariance — multiple spaces, tabs, newlines all
        // collapse in canonical form.
        (b"(  a\t b\n c  )", b"(1:a 1:b 1:c)"),
        // Canonical-form input round-trip — Rivest canonical is idempotent.
        (b"(1:a 1:b 1:c)", b"(1:a 1:b 1:c)"),
    ];

    #[test]
    fn canonicalizer_matches_rivest_canonical_form() {
        for (raw, expected) in CANONICAL_FIXTURES {
            let canon = canonicalize(raw).expect("valid");
            assert_eq!(canon, *expected, "raw={raw:?}");
        }
    }

    #[test]
    fn canonicalize_is_idempotent_on_its_own_output() {
        for (raw, _expected) in CANONICAL_FIXTURES {
            let once = canonicalize(raw).expect("valid");
            let twice = canonicalize(&once).expect("re-canonicalises");
            assert_eq!(once, twice, "idempotence broken for {raw:?}");
        }
    }
}
