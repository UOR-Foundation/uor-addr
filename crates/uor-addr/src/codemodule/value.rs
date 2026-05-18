//! `CodeModuleValue` — typed code-module AST carrier under the
//! Canonical Code-Module AST Serialization (CCMAS) form (see
//! [`crate::codemodule`] module docstring).
//!
//! CCMAS is shaped as Rivest canonical S-expressions over the AST's
//! grammar cases. The canonical-form byte output is a Rivest
//! `(s_1 s_2 ... s_n)` flat-list per Sexp.txt §4.3 with
//! `<length>:<bytes>` atoms per §4.2.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

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

/// Typed code-module AST input shape. Runtime bytes are the
/// CCMAS canonical form (a Rivest canonical S-expression over the
/// AST's grammar cases).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeModuleValue {
    pub(crate) bytes: Vec<u8>,
}

impl CodeModuleValue {
    /// Parse raw CCMAS bytes (Rivest canonical S-expression with the
    /// `mod`/`fun`/`type`/`const`/`call` tag heads) into a typed
    /// `CodeModuleValue`. The parser validates the AST grammar plus
    /// the typed-input bounds.
    ///
    /// # Errors
    ///
    /// - `validCcmas` — not a valid CCMAS byte sequence.
    /// - `depthBound` — nesting exceeds [`MAX_CODEMODULE_DEPTH`].
    /// - `nameWidth` — an identifier exceeds [`MAX_CODEMODULE_NAME_BYTES`].
    /// - `itemsBound` — a list exceeds [`MAX_CODEMODULE_ITEMS`].
    /// - `serializedWidth` — exceeds [`CODEMODULE_VALUE_MAX_BYTES`].
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        // CCMAS is structurally a canonical S-expression. Parse via
        // the sexp grammar to inherit Rivest §4.2/§4.3 conformance,
        // then validate the AST grammar on top.
        let canonical = crate::sexp::canonicalize(raw).map_err(|_| INVALID_AST_VIOLATION)?;
        if canonical.len() > CODEMODULE_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        // Walk the canonical bytes through the AST grammar to enforce
        // the typed-input bounds.
        let mut walker = AstWalker {
            src: &canonical,
            pos: 0,
        };
        walker.walk_node(0)?;
        if walker.pos != canonical.len() {
            return Err(INVALID_AST_VIOLATION);
        }
        Ok(Self { bytes: canonical })
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

    /// Build a Function AST node. `parameters` and `body` are
    /// pre-built AST nodes.
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
        // (3:fun <name> (params...) <return_type> <body>)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"(3:fun ");
        write_atom(name.as_bytes(), &mut bytes);
        bytes.push(b' ');
        bytes.push(b'(');
        for (i, p) in parameters.iter().enumerate() {
            if i > 0 {
                bytes.push(b' ');
            }
            bytes.extend_from_slice(&p.bytes);
        }
        bytes.push(b')');
        bytes.push(b' ');
        bytes.extend_from_slice(&return_type.bytes);
        bytes.push(b' ');
        bytes.extend_from_slice(&body.bytes);
        bytes.push(b')');
        if bytes.len() > CODEMODULE_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        Ok(Self { bytes })
    }

    /// Build an Atom AST node (Identifier, Literal, etc.).
    pub fn atom(text: &str) -> Result<Self, ShapeViolation> {
        if text.len() > MAX_CODEMODULE_NAME_BYTES {
            return Err(NAME_WIDTH_VIOLATION);
        }
        let mut bytes = Vec::new();
        write_atom(text.as_bytes(), &mut bytes);
        Ok(Self { bytes })
    }

    fn ast_call(tag: &str, name: &str, items: &[CodeModuleValue]) -> Result<Self, ShapeViolation> {
        let mut bytes = Vec::new();
        bytes.push(b'(');
        write_atom(tag.as_bytes(), &mut bytes);
        bytes.push(b' ');
        write_atom(name.as_bytes(), &mut bytes);
        for item in items {
            bytes.push(b' ');
            bytes.extend_from_slice(&item.bytes);
        }
        bytes.push(b')');
        if bytes.len() > CODEMODULE_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        Ok(Self { bytes })
    }

    /// Borrow the CCMAS canonical bytes.
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn write_atom(bytes: &[u8], out: &mut Vec<u8>) {
    let mut len_buf = [0u8; 20];
    let len_str = format_usize_into(&mut len_buf, bytes.len());
    out.extend_from_slice(len_str);
    out.push(b':');
    out.extend_from_slice(bytes);
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
            // Empty list `()` — Nil case from the sexp grammar
            // (admissible in CCMAS where a function's params list or
            // a module's items list is empty).
            if self.pos < self.src.len() && self.src[self.pos] == b')' {
                self.pos += 1;
                return Ok(());
            }
            // Walk children — each child is either an atom or a
            // nested list. The first child is the AST node's tag
            // head (e.g. `3:mod`, `3:fun`, `4:call`) when the list
            // represents a tagged AST case; for an untagged
            // sub-list (e.g. a parameter list) it's just the first
            // element. Both shapes are admissible here.
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
        self.pos += 1; // ':'
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

/// Canonical-bytes accessor. The CCMAS bytes ARE the canonical form
/// (Rivest §4.2/§4.3 over the AST grammar).
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, ShapeViolation> {
    let value = CodeModuleValue::parse(raw)?;
    Ok(value.bytes)
}

/// Slice-output canonicalizer.
pub(crate) fn canonicalize_into_slice(
    tagged: &[u8],
    out: &mut [u8],
) -> Result<usize, ShapeViolation> {
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
        if self.bytes.len() > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
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

#[allow(unused_imports)]
use String as _StringPlaceholder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_module_round_trips() {
        let m = CodeModuleValue::module("empty", &[]).expect("valid");
        let parsed = CodeModuleValue::parse(&m.bytes).expect("re-parse");
        assert_eq!(m, parsed);
    }

    #[test]
    fn module_with_function_round_trips() {
        let body = CodeModuleValue::atom("42").expect("valid");
        let ret = CodeModuleValue::atom("u32").expect("valid");
        let f = CodeModuleValue::function("hello", &[], &ret, &body).expect("valid");
        let m = CodeModuleValue::module("greet", &[f]).expect("valid");
        let parsed = CodeModuleValue::parse(&m.bytes).expect("re-parse");
        assert_eq!(m, parsed);
    }

    #[test]
    fn rejects_invalid_ccmas() {
        let err = CodeModuleValue::parse(b"not ccmas").expect_err("must reject");
        assert_eq!(err.constraint_iri, INVALID_AST_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_oversize_name() {
        let big: String = "a".repeat(MAX_CODEMODULE_NAME_BYTES + 1);
        let err = CodeModuleValue::atom(&big).expect_err("must reject");
        assert_eq!(err.constraint_iri, NAME_WIDTH_VIOLATION.constraint_iri);
    }

    #[test]
    fn canonical_form_is_rivest_subset() {
        // CCMAS extends Rivest canonical S-expressions; the byte
        // output is a valid Rivest expression.
        let m = CodeModuleValue::module("ex", &[]).expect("valid");
        // The Rivest canonical form for the same logical structure
        // should re-canonicalize unchanged.
        let twice = crate::sexp::canonicalize(&m.bytes).expect("canon");
        assert_eq!(twice, m.bytes);
    }
}
