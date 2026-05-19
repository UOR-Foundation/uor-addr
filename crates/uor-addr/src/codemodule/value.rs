//! `CodeModuleValue` — typed code-module AST carrier under the
//! Canonical Code-Module AST Serialization (CCMAS) form (see
//! [`crate::codemodule`] module docstring).
//!
//! CCMAS is shaped as Rivest canonical S-expressions over the AST's
//! grammar cases. The canonical-form byte output is a Rivest
//! `(s_1 s_2 ... s_n)` flat-list per Sexp.txt §4.3 with
//! `<length>:<bytes>` atoms per §4.2.
//!
//! # `no_std` + `no_alloc`
//!
//! [`CodeModuleValue`] is a fixed-size stack carrier. Constructors
//! write CCMAS bytes directly into the inline buffer; the parser
//! delegates to [`crate::sexp::SExprValue::parse`] for Rivest
//! canonical-form validation and then walks the canonical bytes
//! through the AST grammar to enforce typed-input bounds.

use prism::pipeline::{
    register_shape, ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation,
    ViolationKind,
};

use crate::codemodule::shapes::bounds::{
    CODEMODULE_VALUE_MAX_BYTES, MAX_CODEMODULE_DEPTH, MAX_CODEMODULE_ITEMS,
    MAX_CODEMODULE_NAME_BYTES,
};

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

const INVALID_AST_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/CodeModuleValue",
    constraint_iri: "https://uor.foundation/addr/CodeModuleValue/validCcmas",
    property_iri: "https://uor.foundation/addr/inputBytes",
    expected_range: "https://uor.foundation/addr/ValidCcmasBytes",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

const DEPTH_BOUND_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/CodeModuleValue",
    constraint_iri: "https://uor.foundation/addr/CodeModuleValue/depthBound",
    property_iri: "https://uor.foundation/addr/CodeModuleValue/depth",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_CODEMODULE_DEPTH as u32,
    kind: ViolationKind::CardinalityViolation,
};

const NAME_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/CodeModuleValue",
    constraint_iri: "https://uor.foundation/addr/CodeModuleValue/nameWidth",
    property_iri: "https://uor.foundation/addr/CodeModuleValue/nameByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_CODEMODULE_NAME_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const ITEMS_BOUND_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/CodeModuleValue",
    constraint_iri: "https://uor.foundation/addr/CodeModuleValue/itemsBound",
    property_iri: "https://uor.foundation/addr/CodeModuleValue/itemCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_CODEMODULE_ITEMS as u32,
    kind: ViolationKind::CardinalityViolation,
};

const TOTAL_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/CodeModuleValue",
    constraint_iri: "https://uor.foundation/addr/CodeModuleValue/serializedWidth",
    property_iri: "https://uor.foundation/addr/CodeModuleValue/totalByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: CODEMODULE_VALUE_MAX_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

// ─── CodeModuleValue — the typed input carrier ──────────────────────────

/// Typed code-module AST input shape. Runtime bytes are the CCMAS
/// canonical form (Rivest canonical S-expression over the AST's
/// grammar cases), stored in a fixed-size stack buffer.
#[derive(Clone)]
pub struct CodeModuleValue {
    pub(crate) bytes: [u8; CODEMODULE_VALUE_MAX_BYTES],
    pub(crate) len: u16,
}

impl core::fmt::Debug for CodeModuleValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CodeModuleValue")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl PartialEq for CodeModuleValue {
    fn eq(&self, other: &Self) -> bool {
        self.tagged_bytes() == other.tagged_bytes()
    }
}

impl Eq for CodeModuleValue {}

impl CodeModuleValue {
    fn empty() -> Self {
        Self {
            bytes: [0u8; CODEMODULE_VALUE_MAX_BYTES],
            len: 0,
        }
    }

    /// Parse raw CCMAS bytes into a typed `CodeModuleValue`. The
    /// parser delegates to [`crate::sexp::SExprValue::parse`] for
    /// Rivest canonical-form validation, then re-canonicalizes
    /// (idempotent on canonical input) and walks the AST grammar.
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        // Validate as a canonical S-expression. SExprValue::parse
        // handles both Rivest canonical form and the token-list
        // shorthand; we re-canonicalize via its slice-out
        // canonicalizer to obtain the canonical CCMAS bytes.
        let sexpr = crate::sexp::SExprValue::parse(raw).map_err(|_| INVALID_AST_VIOLATION)?;
        let mut me = Self::empty();
        let n = crate::sexp::value::canonicalize_into_slice(sexpr.tagged_bytes(), &mut me.bytes)
            .map_err(|_| INVALID_AST_VIOLATION)?;
        me.len = n as u16;
        if me.len as usize > CODEMODULE_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        // Walk the canonical bytes through the AST grammar to enforce
        // the typed-input bounds (depth, name width, item count).
        let mut walker = AstWalker {
            src: &me.bytes[..me.len as usize],
            pos: 0,
        };
        walker.walk_node(0)?;
        if walker.pos != me.len as usize {
            return Err(INVALID_AST_VIOLATION);
        }
        Ok(me)
    }

    /// Build a Module AST node.
    pub fn module(name: &str, items: &[CodeModuleValue]) -> Result<Self, ShapeViolation> {
        if name.len() > MAX_CODEMODULE_NAME_BYTES {
            return Err(NAME_WIDTH_VIOLATION);
        }
        if items.len() > MAX_CODEMODULE_ITEMS {
            return Err(ITEMS_BOUND_VIOLATION);
        }
        Self::ast_call("mod", name, items)
    }

    /// Build a Function AST node.
    pub fn function(
        name: &str,
        parameters: &[CodeModuleValue],
        return_type: &CodeModuleValue,
        body: &CodeModuleValue,
    ) -> Result<Self, ShapeViolation> {
        if name.len() > MAX_CODEMODULE_NAME_BYTES {
            return Err(NAME_WIDTH_VIOLATION);
        }
        if parameters.len() > MAX_CODEMODULE_ITEMS {
            return Err(ITEMS_BOUND_VIOLATION);
        }
        // `(3:fun <name> (params...) <return_type> <body>)`
        let mut me = Self::empty();
        me.push(b"(3:fun ")?;
        me.write_atom(name.as_bytes())?;
        me.push(b" (")?;
        for (i, p) in parameters.iter().enumerate() {
            if i > 0 {
                me.push_byte(b' ')?;
            }
            me.push(p.tagged_bytes())?;
        }
        me.push_byte(b')')?;
        me.push_byte(b' ')?;
        me.push(return_type.tagged_bytes())?;
        me.push_byte(b' ')?;
        me.push(body.tagged_bytes())?;
        me.push_byte(b')')?;
        Ok(me)
    }

    /// Build an Atom AST node (Identifier, Literal, etc.).
    pub fn atom(text: &str) -> Result<Self, ShapeViolation> {
        if text.len() > MAX_CODEMODULE_NAME_BYTES {
            return Err(NAME_WIDTH_VIOLATION);
        }
        let mut me = Self::empty();
        me.write_atom(text.as_bytes())?;
        Ok(me)
    }

    fn ast_call(tag: &str, name: &str, items: &[CodeModuleValue]) -> Result<Self, ShapeViolation> {
        let mut me = Self::empty();
        me.push_byte(b'(')?;
        me.write_atom(tag.as_bytes())?;
        me.push_byte(b' ')?;
        me.write_atom(name.as_bytes())?;
        for item in items {
            me.push_byte(b' ')?;
            me.push(item.tagged_bytes())?;
        }
        me.push_byte(b')')?;
        Ok(me)
    }

    /// Borrow the CCMAS canonical bytes.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    fn push_byte(&mut self, b: u8) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos >= CODEMODULE_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos] = b;
        self.len += 1;
        Ok(())
    }

    fn push(&mut self, data: &[u8]) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos + data.len() > CODEMODULE_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos..pos + data.len()].copy_from_slice(data);
        self.len += data.len() as u16;
        Ok(())
    }

    fn write_atom(&mut self, bytes: &[u8]) -> Result<(), ShapeViolation> {
        let mut len_buf = [0u8; 20];
        let len_str = format_usize_into(&mut len_buf, bytes.len());
        self.push(len_str)?;
        self.push_byte(b':')?;
        self.push(bytes)
    }
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

// ─── AST walker — validates the typed-input grammar over CCMAS bytes ────

struct AstWalker<'a> {
    src: &'a [u8],
    pos: usize,
}

impl AstWalker<'_> {
    fn walk_node(&mut self, depth: usize) -> Result<(), ShapeViolation> {
        if depth > MAX_CODEMODULE_DEPTH {
            return Err(DEPTH_BOUND_VIOLATION);
        }
        if self.pos >= self.src.len() {
            return Err(INVALID_AST_VIOLATION);
        }
        if self.src[self.pos] == b'(' {
            self.pos += 1;
            self.skip_ws();
            if self.pos < self.src.len() && self.src[self.pos] == b')' {
                self.pos += 1;
                return Ok(());
            }
            let mut child_count = 0;
            loop {
                self.skip_ws();
                if self.pos >= self.src.len() {
                    return Err(INVALID_AST_VIOLATION);
                }
                if self.src[self.pos] == b')' {
                    self.pos += 1;
                    return Ok(());
                }
                if child_count >= MAX_CODEMODULE_ITEMS {
                    return Err(ITEMS_BOUND_VIOLATION);
                }
                self.walk_node(depth + 1)?;
                child_count += 1;
            }
        } else if self.src[self.pos].is_ascii_digit() {
            self.walk_atom().map(|_| ())
        } else {
            Err(INVALID_AST_VIOLATION)
        }
    }

    fn walk_atom(&mut self) -> Result<&[u8], ShapeViolation> {
        let start = self.pos;
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if start == self.pos || self.pos >= self.src.len() || self.src[self.pos] != b':' {
            return Err(INVALID_AST_VIOLATION);
        }
        let len: usize = core::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| INVALID_AST_VIOLATION)?
            .parse()
            .map_err(|_| INVALID_AST_VIOLATION)?;
        self.pos += 1;
        if self.pos + len > self.src.len() {
            return Err(INVALID_AST_VIOLATION);
        }
        if len > MAX_CODEMODULE_NAME_BYTES {
            return Err(NAME_WIDTH_VIOLATION);
        }
        let bytes = &self.src[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos] == b' ' {
            self.pos += 1;
        }
    }
}

/// **Available only under the `alloc` feature.** Canonical-bytes
/// accessor — CCMAS bytes are the canonical form. The no_alloc
/// equivalent is [`canonicalize_into_slice`].
#[cfg(feature = "alloc")]
pub fn canonicalize(raw: &[u8]) -> Result<alloc::vec::Vec<u8>, ShapeViolation> {
    extern crate alloc;
    let value = CodeModuleValue::parse(raw)?;
    Ok(value.tagged_bytes().to_vec())
}

/// Slice-output canonicalizer.
pub fn canonicalize_into_slice(tagged: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
    if tagged.len() > out.len() {
        return Err(TOTAL_WIDTH_VIOLATION);
    }
    out[..tagged.len()].copy_from_slice(tagged);
    Ok(tagged.len())
}

// ─── ConstrainedTypeShape + IntoBindingValue + AddressInput ──────────────

impl ConstrainedTypeShape for CodeModuleValue {
    const IRI: &'static str = "https://uor.foundation/addr/CodeModuleValue";
    const SITE_COUNT: usize = CODEMODULE_VALUE_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for CodeModuleValue {}

impl IntoBindingValue for CodeModuleValue {
    const MAX_BYTES: usize = CODEMODULE_VALUE_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        let n = self.len as usize;
        if n > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..n].copy_from_slice(&self.bytes[..n]);
        Ok(n)
    }
}

register_shape!(CodeModuleValueRegistry, CodeModuleValue);

impl crate::common::AddressInput for CodeModuleValue {
    type Registry = CodeModuleValueRegistry;

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
    fn empty_module_round_trips() {
        let m = CodeModuleValue::module("empty", &[]).expect("valid");
        let parsed = CodeModuleValue::parse(m.tagged_bytes()).expect("re-parse");
        assert_eq!(m, parsed);
    }

    #[test]
    fn module_with_function_round_trips() {
        let body = CodeModuleValue::atom("42").expect("valid");
        let ret = CodeModuleValue::atom("u32").expect("valid");
        let f = CodeModuleValue::function("hello", &[], &ret, &body).expect("valid");
        let m = CodeModuleValue::module("greet", &[f]).expect("valid");
        let parsed = CodeModuleValue::parse(m.tagged_bytes()).expect("re-parse");
        assert_eq!(m, parsed);
    }

    #[test]
    fn rejects_invalid_ccmas() {
        let err = CodeModuleValue::parse(b"not ccmas").expect_err("must reject");
        assert_eq!(err.constraint_iri, INVALID_AST_VIOLATION.constraint_iri);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn rejects_oversize_name() {
        extern crate alloc;
        use alloc::string::String;
        let big: String = "a".repeat(MAX_CODEMODULE_NAME_BYTES + 1);
        let err = CodeModuleValue::atom(&big).expect_err("must reject");
        assert_eq!(err.constraint_iri, NAME_WIDTH_VIOLATION.constraint_iri);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn canonical_form_is_rivest_subset() {
        let m = CodeModuleValue::module("ex", &[]).expect("valid");
        let twice = crate::sexp::canonicalize(m.tagged_bytes()).expect("canon");
        assert_eq!(twice, m.tagged_bytes());
    }
}
