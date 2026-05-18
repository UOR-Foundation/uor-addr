//! `XmlValue` — typed XML carrier with W3C Canonical XML 1.1
//! (subset) byte-output discipline.
//!
//! See [`crate::xml`] module docstring for the supported subset
//! and the deviations from full XML-C14N 1.1 (out of scope for typed
//! content-addressing).
//!
//! ## Surface input
//!
//! [`XmlValue::parse`] accepts a UTF-8 XML 1.0 byte sequence — a
//! single root element with optional nested children (Element,
//! Text, CDATA, PI). The parser **rejects**:
//!
//! - Documents with DTDs, external entities, or namespace prefixes
//!   (out of scope for typed content-addressing).
//! - Document-level processing instructions outside the root
//!   element.
//! - Documents lacking a single root element.
//!
//! ## Tagged byte layout
//!
//! ```text
//! XmlValue ::= Tag(1 byte) Payload
//!   Tag = 0x10 Element  — u16 BE name_len || name || u16 BE attr_count ||
//!                          attr_count × (u16 BE name_len || name || u16 BE value_len || value) ||
//!                          u16 BE child_count || child_count × XmlValue
//!   Tag = 0x11 Text     — u32 BE length || bytes (UTF-8)
//!   Tag = 0x12 ProcessingInstruction
//!                      — u16 BE target_len || target || u32 BE data_len || data
//! ```
//!
//! CDATA sections in surface input are expanded to `Text` per
//! XML-C14N 1.1 §1.1's CDATA-to-text rule. Attributes are stored
//! in their parse-order; the canonicalizer re-orders them
//! lexicographically per C14N rule 3.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use prism::pipeline::{
    register_shape, ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation,
    ViolationKind,
};

use crate::xml::shapes::bounds::{
    MAX_XML_ATTRIBUTES, MAX_XML_DEPTH, MAX_XML_ELEMENT_NAME_BYTES, MAX_XML_TEXT_BYTES,
    XML_VALUE_MAX_BYTES,
};

// ─── Tag bytes ──────────────────────────────────────────────────────────

pub(crate) const TAG_ELEMENT: u8 = 0x10;
pub(crate) const TAG_TEXT: u8 = 0x11;
pub(crate) const TAG_PI: u8 = 0x12;

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

const INVALID_XML_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/XmlValue",
    constraint_iri: "https://uor.foundation/addr/XmlValue/validXml",
    property_iri: "https://uor.foundation/addr/inputBytes",
    expected_range: "https://uor.foundation/addr/ValidUtf8Xml",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

const DEPTH_BOUND_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/XmlValue",
    constraint_iri: "https://uor.foundation/addr/XmlValue/depthBound",
    property_iri: "https://uor.foundation/addr/XmlValue/depth",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_XML_DEPTH as u32,
    kind: ViolationKind::CardinalityViolation,
};

const NAME_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/XmlValue",
    constraint_iri: "https://uor.foundation/addr/XmlValue/elementNameWidth",
    property_iri: "https://uor.foundation/addr/XmlValue/elementNameByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_XML_ELEMENT_NAME_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const ATTR_COUNT_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/XmlValue",
    constraint_iri: "https://uor.foundation/addr/XmlValue/attributeCountBound",
    property_iri: "https://uor.foundation/addr/XmlValue/attributeCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_XML_ATTRIBUTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const TEXT_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/XmlValue",
    constraint_iri: "https://uor.foundation/addr/XmlValue/textWidth",
    property_iri: "https://uor.foundation/addr/XmlValue/textByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_XML_TEXT_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const TOTAL_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/XmlValue",
    constraint_iri: "https://uor.foundation/addr/XmlValue/serializedWidth",
    property_iri: "https://uor.foundation/addr/XmlValue/totalByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: XML_VALUE_MAX_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const CORRUPT_TAGGED_BYTES: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/XmlValue",
    constraint_iri: "https://uor.foundation/addr/XmlValue/wellFormedTaggedBytes",
    property_iri: "https://uor.foundation/addr/XmlValue/taggedBytes",
    expected_range: "https://uor.foundation/addr/WellFormedTaggedXmlValue",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

// ─── Surface AST ────────────────────────────────────────────────────────

enum Node {
    Element {
        name: String,
        attrs: Vec<(String, String)>,
        children: Vec<Node>,
    },
    Text(String),
    Pi {
        target: String,
        data: String,
    },
}

// ─── XmlValue — the typed input carrier ─────────────────────────────────

/// Typed XML input shape. Runtime bytes are the structurally-tagged
/// serialization described in [`crate::xml`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlValue {
    pub(crate) bytes: Vec<u8>,
}

impl XmlValue {
    /// Parse raw XML bytes into a typed `XmlValue`.
    ///
    /// # Errors
    ///
    /// - `validXml` — input is not valid UTF-8 XML in the supported
    ///   subset (no DTDs, no external entities, no namespace
    ///   prefixes).
    /// - `depthBound` — nesting depth exceeds [`MAX_XML_DEPTH`].
    /// - `elementNameWidth` — an element/attribute name exceeds
    ///   [`MAX_XML_ELEMENT_NAME_BYTES`].
    /// - `attributeCountBound` — an element has more than
    ///   [`MAX_XML_ATTRIBUTES`] attributes.
    /// - `textWidth` — a text node exceeds [`MAX_XML_TEXT_BYTES`].
    /// - `serializedWidth` — the tagged serialization exceeds
    ///   [`XML_VALUE_MAX_BYTES`].
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let text = core::str::from_utf8(raw).map_err(|_| INVALID_XML_VIOLATION)?;
        let mut parser = Parser::new(text);
        parser.skip_whitespace();
        let root = parser.parse_element(0)?;
        parser.skip_whitespace();
        if !parser.is_eof() {
            return Err(INVALID_XML_VIOLATION);
        }
        let mut bytes = Vec::new();
        write_tagged(&root, 0, &mut bytes)?;
        if bytes.len() > XML_VALUE_MAX_BYTES {
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

/// Parse + canonicalize per the W3C XML-C14N 1.1 subset documented
/// in [`crate::xml`].
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, ShapeViolation> {
    let value = XmlValue::parse(raw)?;
    let mut canonical = Vec::with_capacity(value.bytes.len());
    canonicalize_into(&value.bytes, &mut canonical)?;
    Ok(canonical)
}

// ─── Surface parser (raw bytes → Node tree) ─────────────────────────────

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

    fn skip_whitespace(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn parse_element(&mut self, depth: usize) -> Result<Node, ShapeViolation> {
        if depth > MAX_XML_DEPTH {
            return Err(DEPTH_BOUND_VIOLATION);
        }
        if self.pos >= self.src.len() || self.src[self.pos] != b'<' {
            return Err(INVALID_XML_VIOLATION);
        }
        self.pos += 1;
        // Reject special tags except processing instructions handled elsewhere.
        if self.pos < self.src.len() && (self.src[self.pos] == b'!' || self.src[self.pos] == b'?') {
            return Err(INVALID_XML_VIOLATION);
        }
        let name = self.parse_name()?;
        let attrs = self.parse_attrs()?;
        self.skip_whitespace();
        if self.pos >= self.src.len() {
            return Err(INVALID_XML_VIOLATION);
        }
        if self.src[self.pos] == b'/' {
            // Self-closing.
            self.pos += 1;
            if self.pos >= self.src.len() || self.src[self.pos] != b'>' {
                return Err(INVALID_XML_VIOLATION);
            }
            self.pos += 1;
            return Ok(Node::Element {
                name,
                attrs,
                children: Vec::new(),
            });
        }
        if self.src[self.pos] != b'>' {
            return Err(INVALID_XML_VIOLATION);
        }
        self.pos += 1;
        // Content until matching close tag.
        let mut children = Vec::new();
        loop {
            if self.pos >= self.src.len() {
                return Err(INVALID_XML_VIOLATION);
            }
            if self.src[self.pos] == b'<' {
                if self.pos + 1 < self.src.len() && self.src[self.pos + 1] == b'/' {
                    self.pos += 2;
                    let close_name = self.parse_name()?;
                    if close_name != name {
                        return Err(INVALID_XML_VIOLATION);
                    }
                    self.skip_whitespace();
                    if self.pos >= self.src.len() || self.src[self.pos] != b'>' {
                        return Err(INVALID_XML_VIOLATION);
                    }
                    self.pos += 1;
                    return Ok(Node::Element {
                        name,
                        attrs,
                        children,
                    });
                }
                // Nested element or PI or CDATA.
                if self.pos + 8 < self.src.len()
                    && &self.src[self.pos..self.pos + 9] == b"<![CDATA["
                {
                    self.pos += 9;
                    let start = self.pos;
                    while self.pos + 2 < self.src.len()
                        && &self.src[self.pos..self.pos + 3] != b"]]>"
                    {
                        self.pos += 1;
                    }
                    if self.pos + 2 >= self.src.len() {
                        return Err(INVALID_XML_VIOLATION);
                    }
                    let raw = &self.src[start..self.pos];
                    self.pos += 3;
                    let text = core::str::from_utf8(raw).map_err(|_| INVALID_XML_VIOLATION)?;
                    if text.len() > MAX_XML_TEXT_BYTES {
                        return Err(TEXT_WIDTH_VIOLATION);
                    }
                    // CDATA collapses to Text per XML-C14N 1.1 §1.1.
                    children.push(Node::Text(text.into()));
                    continue;
                }
                if self.pos + 1 < self.src.len() && self.src[self.pos + 1] == b'?' {
                    self.pos += 2;
                    let target = self.parse_name()?;
                    self.skip_whitespace();
                    let data_start = self.pos;
                    while self.pos + 1 < self.src.len()
                        && &self.src[self.pos..self.pos + 2] != b"?>"
                    {
                        self.pos += 1;
                    }
                    if self.pos + 1 >= self.src.len() {
                        return Err(INVALID_XML_VIOLATION);
                    }
                    let data = core::str::from_utf8(&self.src[data_start..self.pos])
                        .map_err(|_| INVALID_XML_VIOLATION)?;
                    self.pos += 2;
                    children.push(Node::Pi {
                        target,
                        data: data.trim_end().into(),
                    });
                    continue;
                }
                // Nested element.
                children.push(self.parse_element(depth + 1)?);
                continue;
            }
            // Text content.
            let start = self.pos;
            while self.pos < self.src.len() && self.src[self.pos] != b'<' {
                self.pos += 1;
            }
            let text = core::str::from_utf8(&self.src[start..self.pos])
                .map_err(|_| INVALID_XML_VIOLATION)?;
            // Decode entity references (subset).
            let decoded = decode_entities(text)?;
            if decoded.len() > MAX_XML_TEXT_BYTES {
                return Err(TEXT_WIDTH_VIOLATION);
            }
            if !decoded.is_empty() {
                children.push(Node::Text(decoded));
            }
        }
    }

    fn parse_name(&mut self) -> Result<String, ShapeViolation> {
        let start = self.pos;
        while self.pos < self.src.len() {
            let b = self.src[self.pos];
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let name = core::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| INVALID_XML_VIOLATION)?
            .to_string();
        if name.is_empty() {
            return Err(INVALID_XML_VIOLATION);
        }
        if name.len() > MAX_XML_ELEMENT_NAME_BYTES {
            return Err(NAME_WIDTH_VIOLATION);
        }
        Ok(name)
    }

    fn parse_attrs(&mut self) -> Result<Vec<(String, String)>, ShapeViolation> {
        let mut attrs = Vec::new();
        loop {
            self.skip_whitespace();
            if self.pos >= self.src.len() {
                return Err(INVALID_XML_VIOLATION);
            }
            if self.src[self.pos] == b'>' || self.src[self.pos] == b'/' {
                return Ok(attrs);
            }
            if attrs.len() >= MAX_XML_ATTRIBUTES {
                return Err(ATTR_COUNT_VIOLATION);
            }
            let name = self.parse_name()?;
            self.skip_whitespace();
            if self.pos >= self.src.len() || self.src[self.pos] != b'=' {
                return Err(INVALID_XML_VIOLATION);
            }
            self.pos += 1;
            self.skip_whitespace();
            if self.pos >= self.src.len() {
                return Err(INVALID_XML_VIOLATION);
            }
            let quote = self.src[self.pos];
            if quote != b'"' && quote != b'\'' {
                return Err(INVALID_XML_VIOLATION);
            }
            self.pos += 1;
            let start = self.pos;
            while self.pos < self.src.len() && self.src[self.pos] != quote {
                self.pos += 1;
            }
            if self.pos >= self.src.len() {
                return Err(INVALID_XML_VIOLATION);
            }
            let value = core::str::from_utf8(&self.src[start..self.pos])
                .map_err(|_| INVALID_XML_VIOLATION)?;
            self.pos += 1;
            let decoded = decode_entities(value)?;
            attrs.push((name, decoded));
        }
    }
}

fn decode_entities(text: &str) -> Result<String, ShapeViolation> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        // Read until ';'
        let mut entity = String::new();
        loop {
            match chars.next() {
                Some(';') => break,
                Some(ch) => entity.push(ch),
                None => return Err(INVALID_XML_VIOLATION),
            }
        }
        match entity.as_str() {
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "amp" => out.push('&'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            s if s.starts_with("#x") || s.starts_with("#X") => {
                let n = u32::from_str_radix(&s[2..], 16).map_err(|_| INVALID_XML_VIOLATION)?;
                let ch = char::from_u32(n).ok_or(INVALID_XML_VIOLATION)?;
                out.push(ch);
            }
            s if s.starts_with('#') => {
                let n: u32 = s[1..].parse().map_err(|_| INVALID_XML_VIOLATION)?;
                let ch = char::from_u32(n).ok_or(INVALID_XML_VIOLATION)?;
                out.push(ch);
            }
            _ => return Err(INVALID_XML_VIOLATION),
        }
    }
    Ok(out)
}

// ─── Tagged-format writer ───────────────────────────────────────────────

fn write_tagged(node: &Node, depth: usize, out: &mut Vec<u8>) -> Result<(), ShapeViolation> {
    if depth > MAX_XML_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    match node {
        Node::Element {
            name,
            attrs,
            children,
        } => {
            out.push(TAG_ELEMENT);
            put_u16(out, name.len() as u16);
            out.extend_from_slice(name.as_bytes());
            put_u16(out, attrs.len() as u16);
            for (k, v) in attrs {
                put_u16(out, k.len() as u16);
                out.extend_from_slice(k.as_bytes());
                put_u16(out, v.len() as u16);
                out.extend_from_slice(v.as_bytes());
            }
            put_u16(out, children.len() as u16);
            for child in children {
                write_tagged(child, depth + 1, out)?;
            }
        }
        Node::Text(t) => {
            if t.len() > MAX_XML_TEXT_BYTES {
                return Err(TEXT_WIDTH_VIOLATION);
            }
            out.push(TAG_TEXT);
            put_u32(out, t.len() as u32);
            out.extend_from_slice(t.as_bytes());
        }
        Node::Pi { target, data } => {
            out.push(TAG_PI);
            put_u16(out, target.len() as u16);
            out.extend_from_slice(target.as_bytes());
            put_u32(out, data.len() as u32);
            out.extend_from_slice(data.as_bytes());
        }
    }
    Ok(())
}

#[inline]
fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

// ─── Tagged-format → canonical XML (subset) ─────────────────────────────

pub(crate) fn canonicalize_into(tagged: &[u8], out: &mut Vec<u8>) -> Result<(), ShapeViolation> {
    let mut pos = 0;
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
    if depth > MAX_XML_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    let tag = take_byte(buf, pos)?;
    match tag {
        TAG_ELEMENT => {
            let name_len = take_u16(buf, pos)? as usize;
            let name = take_slice(buf, pos, name_len)?;
            let attr_count = take_u16(buf, pos)? as usize;
            // Collect attributes into a BTreeMap so canonical-XML 1.1
            // §1.1 rule 3's lexicographic attribute ordering applies.
            let mut attrs: BTreeMap<&[u8], &[u8]> = BTreeMap::new();
            for _ in 0..attr_count {
                let k_len = take_u16(buf, pos)? as usize;
                let k = take_slice(buf, pos, k_len)?;
                let v_len = take_u16(buf, pos)? as usize;
                let v = take_slice(buf, pos, v_len)?;
                attrs.insert(k, v);
            }
            let child_count = take_u16(buf, pos)? as usize;
            out.push(b'<');
            out.extend_from_slice(name);
            for (k, v) in &attrs {
                out.push(b' ');
                out.extend_from_slice(k);
                out.extend_from_slice(b"=\"");
                escape_attr(v, out);
                out.push(b'"');
            }
            out.push(b'>');
            for _ in 0..child_count {
                write_canonical(buf, pos, depth + 1, out)?;
            }
            out.extend_from_slice(b"</");
            out.extend_from_slice(name);
            out.push(b'>');
            Ok(())
        }
        TAG_TEXT => {
            let len = take_u32(buf, pos)? as usize;
            let bytes = take_slice(buf, pos, len)?;
            escape_text(bytes, out);
            Ok(())
        }
        TAG_PI => {
            let target_len = take_u16(buf, pos)? as usize;
            let target = take_slice(buf, pos, target_len)?;
            let data_len = take_u32(buf, pos)? as usize;
            let data = take_slice(buf, pos, data_len)?;
            out.extend_from_slice(b"<?");
            out.extend_from_slice(target);
            if !data.is_empty() {
                out.push(b' ');
                out.extend_from_slice(data);
            }
            out.extend_from_slice(b"?>");
            Ok(())
        }
        _ => Err(CORRUPT_TAGGED_BYTES),
    }
}

/// XML-C14N 1.1 §1.1 rule 4 — attribute-value character replacement.
fn escape_attr(bytes: &[u8], out: &mut Vec<u8>) {
    for &b in bytes {
        match b {
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\t' => out.extend_from_slice(b"&#x9;"),
            b'\n' => out.extend_from_slice(b"&#xA;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
}

/// XML-C14N 1.1 §1.1 rule 5 — text-content character replacement.
fn escape_text(bytes: &[u8], out: &mut Vec<u8>) {
    for &b in bytes {
        match b {
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
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
    let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

#[inline]
fn take_u32(buf: &[u8], pos: &mut usize) -> Result<u32, ShapeViolation> {
    if *pos + 4 > buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let v = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(v)
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

/// Slice-output canonicalizer.
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

impl ConstrainedTypeShape for XmlValue {
    const IRI: &'static str = "https://uor.foundation/addr/XmlValue";
    const SITE_COUNT: usize = XML_VALUE_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for XmlValue {}

impl IntoBindingValue for XmlValue {
    const MAX_BYTES: usize = XML_VALUE_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if self.bytes.len() > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

register_shape!(XmlValueRegistry, XmlValue);

impl crate::common::AddressInput for XmlValue {
    type Registry = XmlValueRegistry;

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
    fn parses_empty_element() {
        let v = XmlValue::parse(b"<root/>").expect("valid");
        assert_eq!(v.bytes[0], TAG_ELEMENT);
    }

    #[test]
    fn canonicalizes_with_lexicographic_attribute_ordering() {
        // XML-C14N 1.1 §1.1 rule 3 — attribute lexicographic ordering.
        let canon = canonicalize(br#"<root b="2" a="1"/>"#).expect("valid");
        assert_eq!(canon, br#"<root a="1" b="2"></root>"#);
    }

    #[test]
    fn canonicalizer_collapses_cdata_to_text() {
        let canon = canonicalize(b"<root><![CDATA[<hello>]]></root>").expect("valid");
        assert_eq!(canon, b"<root>&lt;hello&gt;</root>");
    }

    #[test]
    fn canonicalizer_escapes_attribute_values() {
        let canon = canonicalize(br#"<root attr="&lt;v&gt;"/>"#).expect("valid");
        assert_eq!(canon, br#"<root attr="&lt;v&gt;"></root>"#);
    }

    #[test]
    fn canonicalizer_is_idempotent() {
        let inputs: &[&[u8]] = &[
            b"<root/>",
            b"<root><child/></root>",
            br#"<root a="1" b="2"><child>text</child></root>"#,
        ];
        for raw in inputs {
            let once = canonicalize(raw).expect("valid");
            let twice = canonicalize(&once).expect("re-canonicalises");
            assert_eq!(once, twice, "idempotence broken for {raw:?}");
        }
    }

    #[test]
    fn rejects_mismatched_close_tag() {
        let err = XmlValue::parse(b"<a></b>").expect_err("mismatch");
        assert_eq!(err.constraint_iri, INVALID_XML_VIOLATION.constraint_iri);
    }

    #[test]
    fn rejects_overdeep_nesting() {
        let mut s = String::new();
        for i in 0..(MAX_XML_DEPTH + 2) {
            s.push_str(&alloc::format!("<n{i}>"));
        }
        for i in (0..(MAX_XML_DEPTH + 2)).rev() {
            s.push_str(&alloc::format!("</n{i}>"));
        }
        let err = XmlValue::parse(s.as_bytes()).expect_err("overdeep");
        assert_eq!(err.constraint_iri, DEPTH_BOUND_VIOLATION.constraint_iri);
    }
}
