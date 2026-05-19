//! `XmlValue` — typed XML carrier with W3C Canonical XML 1.1 (subset)
//! byte-output discipline.
//!
//! See [`crate::xml`] module docstring for the supported subset and
//! the deviations from full XML-C14N 1.1.
//!
//! # `no_std` + `no_alloc`
//!
//! [`XmlValue::parse`] is a single-pass tokenizer that writes tagged
//! bytes directly into a fixed-size stack buffer. There is no
//! intermediate AST. [`canonicalize_into_slice`] walks the tagged
//! bytes and emits the canonical-XML 1.1 form into the caller's
//! `out` slice, with attribute sorting performed via stack-local
//! offset arrays.
//!
//! # Surface input
//!
//! [`XmlValue::parse`] accepts a UTF-8 XML 1.0 byte sequence — a
//! single root element with optional nested children (Element, Text,
//! CDATA, PI). The parser **rejects**:
//!
//! - Documents with DTDs, external entities, or namespace prefixes.
//! - Document-level processing instructions outside the root element.
//! - Documents lacking a single root element.
//!
//! # Tagged byte layout
//!
//! ```text
//! XmlValue ::= Tag(1 byte) Payload
//!   Tag = 0x10 Element  — u16 BE name_len || name || u16 BE attr_count ||
//!                          attr_count × (u16 BE name_len || name || u16 BE value_len || value) ||
//!                          u16 BE child_count || child_count × XmlValue
//!   Tag = 0x11 Text     — u32 BE length || bytes (UTF-8, entity-decoded)
//!   Tag = 0x12 ProcessingInstruction
//!                      — u16 BE target_len || target || u32 BE data_len || data
//! ```

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

// ─── XmlValue — the typed input carrier ─────────────────────────────────

/// Typed XML input shape. Runtime bytes are the structurally-tagged
/// serialization described in [`crate::xml`], stored in a fixed-size
/// stack buffer.
#[derive(Clone)]
pub struct XmlValue {
    pub(crate) bytes: [u8; XML_VALUE_MAX_BYTES],
    pub(crate) len: u16,
}

impl core::fmt::Debug for XmlValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XmlValue")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl PartialEq for XmlValue {
    fn eq(&self, other: &Self) -> bool {
        self.tagged_bytes() == other.tagged_bytes()
    }
}

impl Eq for XmlValue {}

impl XmlValue {
    /// Parse raw XML bytes into a typed `XmlValue`.
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        core::str::from_utf8(raw).map_err(|_| INVALID_XML_VIOLATION)?;
        let mut value = Self {
            bytes: [0u8; XML_VALUE_MAX_BYTES],
            len: 0,
        };
        let mut p = Parser::new(raw);
        p.skip_ws();
        let mut text_scratch = [0u8; MAX_XML_TEXT_BYTES];
        parse_element(&mut p, &mut value, 0, &mut text_scratch)?;
        p.skip_ws();
        if !p.is_eof() {
            return Err(INVALID_XML_VIOLATION);
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
        if pos >= XML_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos] = b;
        self.len += 1;
        Ok(())
    }

    fn push_u16_be(&mut self, v: u16) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos + 2 > XML_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        let b = v.to_be_bytes();
        self.bytes[pos] = b[0];
        self.bytes[pos + 1] = b[1];
        self.len += 2;
        Ok(())
    }

    fn push_u32_be(&mut self, v: u32) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos + 4 > XML_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        let b = v.to_be_bytes();
        self.bytes[pos..pos + 4].copy_from_slice(&b);
        self.len += 4;
        Ok(())
    }

    fn extend(&mut self, data: &[u8]) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos + data.len() > XML_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos..pos + data.len()].copy_from_slice(data);
        self.len += data.len() as u16;
        Ok(())
    }

    /// Patch a u16 at the given byte offset (used to backpatch
    /// child / attr counts after walking).
    fn patch_u16_be(&mut self, offset: usize, v: u16) -> Result<(), ShapeViolation> {
        if offset + 2 > self.len as usize {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        let b = v.to_be_bytes();
        self.bytes[offset] = b[0];
        self.bytes[offset + 1] = b[1];
        Ok(())
    }
}

// ─── Convenience alloc surface (feature = "alloc") ──────────────────────

/// Parse + canonicalize per the W3C XML-C14N 1.1 subset documented in
/// [`crate::xml`]. **Available only under the `alloc` feature.**
#[cfg(feature = "alloc")]
pub fn canonicalize(raw: &[u8]) -> Result<alloc::vec::Vec<u8>, ShapeViolation> {
    extern crate alloc;
    let value = XmlValue::parse(raw)?;
    let mut out = alloc::vec![0u8; XML_VALUE_MAX_BYTES * 2];
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

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.src.len()
    }
}

fn parse_element(
    p: &mut Parser<'_>,
    out: &mut XmlValue,
    depth: usize,
    text_scratch: &mut [u8; MAX_XML_TEXT_BYTES],
) -> Result<(), ShapeViolation> {
    if depth > MAX_XML_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    if p.pos >= p.src.len() || p.src[p.pos] != b'<' {
        return Err(INVALID_XML_VIOLATION);
    }
    p.pos += 1;
    if p.pos < p.src.len() && (p.src[p.pos] == b'!' || p.src[p.pos] == b'?') {
        return Err(INVALID_XML_VIOLATION);
    }
    // Element opening tag: write TAG_ELEMENT, name, then placeholder for
    // attr_count, attrs, placeholder for child_count, children.
    out.push_byte(TAG_ELEMENT)?;
    let name_start_in_src = p.pos;
    let name_len = parse_name_len(p)?;
    let name_bytes = &p.src[name_start_in_src..name_start_in_src + name_len];
    if name_len > MAX_XML_ELEMENT_NAME_BYTES {
        return Err(NAME_WIDTH_VIOLATION);
    }
    out.push_u16_be(name_len as u16)?;
    out.extend(name_bytes)?;
    // Reserve attr_count slot
    let attr_count_offset = out.len as usize;
    out.push_u16_be(0)?;
    let mut attr_count: u32 = 0;
    loop {
        p.skip_ws();
        if p.pos >= p.src.len() {
            return Err(INVALID_XML_VIOLATION);
        }
        if p.src[p.pos] == b'>' || p.src[p.pos] == b'/' {
            break;
        }
        if attr_count as usize >= MAX_XML_ATTRIBUTES {
            return Err(ATTR_COUNT_VIOLATION);
        }
        parse_attr(p, out, text_scratch)?;
        attr_count += 1;
    }
    out.patch_u16_be(attr_count_offset, attr_count as u16)?;
    if p.src[p.pos] == b'/' {
        // Self-closing — emit zero children, no body to parse.
        p.pos += 1;
        if p.pos >= p.src.len() || p.src[p.pos] != b'>' {
            return Err(INVALID_XML_VIOLATION);
        }
        p.pos += 1;
        out.push_u16_be(0)?;
        return Ok(());
    }
    if p.src[p.pos] != b'>' {
        return Err(INVALID_XML_VIOLATION);
    }
    p.pos += 1;
    // Reserve child_count slot
    let child_count_offset = out.len as usize;
    out.push_u16_be(0)?;
    let mut child_count: u32 = 0;
    loop {
        if p.pos >= p.src.len() {
            return Err(INVALID_XML_VIOLATION);
        }
        if p.src[p.pos] == b'<' {
            // Possible: close tag, CDATA, PI, or nested element.
            if p.pos + 1 < p.src.len() && p.src[p.pos + 1] == b'/' {
                // Close tag.
                p.pos += 2;
                let close_start = p.pos;
                let close_len = parse_name_len(p)?;
                let close_name = &p.src[close_start..close_start + close_len];
                if close_name != name_bytes {
                    return Err(INVALID_XML_VIOLATION);
                }
                p.skip_ws();
                if p.pos >= p.src.len() || p.src[p.pos] != b'>' {
                    return Err(INVALID_XML_VIOLATION);
                }
                p.pos += 1;
                out.patch_u16_be(child_count_offset, child_count as u16)?;
                return Ok(());
            }
            // CDATA
            if p.pos + 8 < p.src.len() && &p.src[p.pos..p.pos + 9] == b"<![CDATA[" {
                p.pos += 9;
                let start = p.pos;
                while p.pos + 2 < p.src.len() && &p.src[p.pos..p.pos + 3] != b"]]>" {
                    p.pos += 1;
                }
                if p.pos + 2 >= p.src.len() {
                    return Err(INVALID_XML_VIOLATION);
                }
                let cdata = &p.src[start..p.pos];
                p.pos += 3;
                if cdata.len() > MAX_XML_TEXT_BYTES {
                    return Err(TEXT_WIDTH_VIOLATION);
                }
                if !cdata.is_empty() {
                    // CDATA collapses to Text per XML-C14N 1.1 §1.1.
                    out.push_byte(TAG_TEXT)?;
                    out.push_u32_be(cdata.len() as u32)?;
                    out.extend(cdata)?;
                    child_count += 1;
                }
                continue;
            }
            // PI
            if p.pos + 1 < p.src.len() && p.src[p.pos + 1] == b'?' {
                p.pos += 2;
                let target_start = p.pos;
                let target_len = parse_name_len(p)?;
                let target = &p.src[target_start..target_start + target_len];
                p.skip_ws();
                let data_start = p.pos;
                while p.pos + 1 < p.src.len() && &p.src[p.pos..p.pos + 2] != b"?>" {
                    p.pos += 1;
                }
                if p.pos + 1 >= p.src.len() {
                    return Err(INVALID_XML_VIOLATION);
                }
                let raw_data = &p.src[data_start..p.pos];
                p.pos += 2;
                // Trim trailing ASCII whitespace (matching prior behavior).
                let mut end = raw_data.len();
                while end > 0 && raw_data[end - 1].is_ascii_whitespace() {
                    end -= 1;
                }
                let data = &raw_data[..end];
                out.push_byte(TAG_PI)?;
                out.push_u16_be(target_len as u16)?;
                out.extend(target)?;
                out.push_u32_be(data.len() as u32)?;
                out.extend(data)?;
                child_count += 1;
                continue;
            }
            // Nested element.
            parse_element(p, out, depth + 1, text_scratch)?;
            child_count += 1;
            continue;
        }
        // Text content.
        let text_start = p.pos;
        while p.pos < p.src.len() && p.src[p.pos] != b'<' {
            p.pos += 1;
        }
        let raw_text = &p.src[text_start..p.pos];
        let decoded_len = decode_entities_into(raw_text, text_scratch)?;
        if decoded_len > MAX_XML_TEXT_BYTES {
            return Err(TEXT_WIDTH_VIOLATION);
        }
        if decoded_len > 0 {
            out.push_byte(TAG_TEXT)?;
            out.push_u32_be(decoded_len as u32)?;
            out.extend(&text_scratch[..decoded_len])?;
            child_count += 1;
        }
    }
}

fn parse_name_len(p: &mut Parser<'_>) -> Result<usize, ShapeViolation> {
    let start = p.pos;
    while p.pos < p.src.len() {
        let b = p.src[p.pos];
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' {
            p.pos += 1;
        } else {
            break;
        }
    }
    let len = p.pos - start;
    if len == 0 {
        return Err(INVALID_XML_VIOLATION);
    }
    if len > MAX_XML_ELEMENT_NAME_BYTES {
        return Err(NAME_WIDTH_VIOLATION);
    }
    Ok(len)
}

fn parse_attr(
    p: &mut Parser<'_>,
    out: &mut XmlValue,
    text_scratch: &mut [u8; MAX_XML_TEXT_BYTES],
) -> Result<(), ShapeViolation> {
    let name_start = p.pos;
    let name_len = parse_name_len(p)?;
    let name_bytes = &p.src[name_start..name_start + name_len];
    out.push_u16_be(name_len as u16)?;
    out.extend(name_bytes)?;
    p.skip_ws();
    if p.pos >= p.src.len() || p.src[p.pos] != b'=' {
        return Err(INVALID_XML_VIOLATION);
    }
    p.pos += 1;
    p.skip_ws();
    if p.pos >= p.src.len() {
        return Err(INVALID_XML_VIOLATION);
    }
    let quote = p.src[p.pos];
    if quote != b'"' && quote != b'\'' {
        return Err(INVALID_XML_VIOLATION);
    }
    p.pos += 1;
    let value_start = p.pos;
    while p.pos < p.src.len() && p.src[p.pos] != quote {
        p.pos += 1;
    }
    if p.pos >= p.src.len() {
        return Err(INVALID_XML_VIOLATION);
    }
    let raw_value = &p.src[value_start..p.pos];
    p.pos += 1;
    let decoded_len = decode_entities_into(raw_value, text_scratch)?;
    out.push_u16_be(decoded_len as u16)?;
    out.extend(&text_scratch[..decoded_len])
}

fn decode_entities_into(
    text: &[u8],
    scratch: &mut [u8; MAX_XML_TEXT_BYTES],
) -> Result<usize, ShapeViolation> {
    let mut out_len = 0usize;
    let mut i = 0;
    while i < text.len() {
        let b = text[i];
        if b != b'&' {
            if out_len >= scratch.len() {
                return Err(TEXT_WIDTH_VIOLATION);
            }
            scratch[out_len] = b;
            out_len += 1;
            i += 1;
            continue;
        }
        // Find entity end ';'.
        let entity_start = i + 1;
        let mut j = entity_start;
        while j < text.len() && text[j] != b';' {
            j += 1;
        }
        if j >= text.len() {
            return Err(INVALID_XML_VIOLATION);
        }
        let entity = &text[entity_start..j];
        let cp = match entity {
            b"lt" => '<' as u32,
            b"gt" => '>' as u32,
            b"amp" => '&' as u32,
            b"quot" => '"' as u32,
            b"apos" => '\'' as u32,
            _ if entity.starts_with(b"#x") || entity.starts_with(b"#X") => {
                let hex = &entity[2..];
                let s = core::str::from_utf8(hex).map_err(|_| INVALID_XML_VIOLATION)?;
                u32::from_str_radix(s, 16).map_err(|_| INVALID_XML_VIOLATION)?
            }
            _ if entity.starts_with(b"#") => {
                let dec = &entity[1..];
                let s = core::str::from_utf8(dec).map_err(|_| INVALID_XML_VIOLATION)?;
                s.parse::<u32>().map_err(|_| INVALID_XML_VIOLATION)?
            }
            _ => return Err(INVALID_XML_VIOLATION),
        };
        let c = char::from_u32(cp).ok_or(INVALID_XML_VIOLATION)?;
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        let bytes = s.as_bytes();
        if out_len + bytes.len() > scratch.len() {
            return Err(TEXT_WIDTH_VIOLATION);
        }
        scratch[out_len..out_len + bytes.len()].copy_from_slice(bytes);
        out_len += bytes.len();
        i = j + 1;
    }
    Ok(out_len)
}

// ─── Streaming canonicalizer (tagged bytes → canonical XML) ─────────────

pub fn canonicalize_into_slice(tagged: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
    let mut w = SliceWriter::new(out);
    let mut pos = 0;
    emit_node(tagged, &mut pos, &mut w, 0)?;
    if pos != tagged.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    Ok(w.pos)
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

fn read_byte(buf: &[u8], pos: &mut usize) -> Result<u8, ShapeViolation> {
    if *pos >= buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let b = buf[*pos];
    *pos += 1;
    Ok(b)
}

fn read_u16_be(buf: &[u8], pos: &mut usize) -> Result<u16, ShapeViolation> {
    if *pos + 2 > buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_u32_be(buf: &[u8], pos: &mut usize) -> Result<u32, ShapeViolation> {
    if *pos + 4 > buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let v = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn read_slice<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], ShapeViolation> {
    if *pos + len > buf.len() {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    let s = &buf[*pos..*pos + len];
    *pos += len;
    Ok(s)
}

fn emit_node(
    tagged: &[u8],
    pos: &mut usize,
    w: &mut SliceWriter<'_>,
    depth: usize,
) -> Result<(), ShapeViolation> {
    if depth > MAX_XML_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    let tag = read_byte(tagged, pos)?;
    match tag {
        TAG_ELEMENT => emit_element(tagged, pos, w, depth),
        TAG_TEXT => {
            let len = read_u32_be(tagged, pos)? as usize;
            let bytes = read_slice(tagged, pos, len)?;
            escape_text_into(bytes, w)
        }
        TAG_PI => {
            let target_len = read_u16_be(tagged, pos)? as usize;
            let target = read_slice(tagged, pos, target_len)?;
            let data_len = read_u32_be(tagged, pos)? as usize;
            let data = read_slice(tagged, pos, data_len)?;
            w.write(b"<?")?;
            w.write(target)?;
            if !data.is_empty() {
                w.write_byte(b' ')?;
                w.write(data)?;
            }
            w.write(b"?>")
        }
        _ => Err(CORRUPT_TAGGED_BYTES),
    }
}

fn emit_element(
    tagged: &[u8],
    pos: &mut usize,
    w: &mut SliceWriter<'_>,
    depth: usize,
) -> Result<(), ShapeViolation> {
    let name_len = read_u16_be(tagged, pos)? as usize;
    let name = read_slice(tagged, pos, name_len)?;
    let attr_count = read_u16_be(tagged, pos)? as usize;
    if attr_count > MAX_XML_ATTRIBUTES {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    // Collect attribute (name_start, name_len, value_start, value_len)
    // offsets into a stack array, then sort by name bytes per
    // XML-C14N 1.1 §1.1 rule 3.
    let mut attr_starts = [0u16; MAX_XML_ATTRIBUTES];
    for slot in attr_starts[..attr_count].iter_mut() {
        *slot = *pos as u16;
        let k_len = read_u16_be(tagged, pos)? as usize;
        *pos += k_len;
        if *pos > tagged.len() {
            return Err(CORRUPT_TAGGED_BYTES);
        }
        let v_len = read_u16_be(tagged, pos)? as usize;
        *pos += v_len;
        if *pos > tagged.len() {
            return Err(CORRUPT_TAGGED_BYTES);
        }
    }
    insertion_sort_attrs(&mut attr_starts[..attr_count], tagged);
    let child_count = read_u16_be(tagged, pos)? as usize;
    w.write_byte(b'<')?;
    w.write(name)?;
    for &attr_off in &attr_starts[..attr_count] {
        let mut p = attr_off as usize;
        let k_len = read_u16_be(tagged, &mut p)? as usize;
        let k = read_slice(tagged, &mut p, k_len)?;
        let v_len = read_u16_be(tagged, &mut p)? as usize;
        let v = read_slice(tagged, &mut p, v_len)?;
        w.write_byte(b' ')?;
        w.write(k)?;
        w.write(b"=\"")?;
        escape_attr_into(v, w)?;
        w.write_byte(b'"')?;
    }
    w.write_byte(b'>')?;
    for _ in 0..child_count {
        emit_node(tagged, pos, w, depth + 1)?;
    }
    w.write(b"</")?;
    w.write(name)?;
    w.write_byte(b'>')
}

fn insertion_sort_attrs(entries: &mut [u16], tagged: &[u8]) {
    for i in 1..entries.len() {
        let mut j = i;
        while j > 0 {
            let a = attr_name(entries[j - 1] as usize, tagged);
            let b = attr_name(entries[j] as usize, tagged);
            if a > b {
                entries.swap(j - 1, j);
                j -= 1;
            } else {
                break;
            }
        }
    }
}

fn attr_name(off: usize, tagged: &[u8]) -> &[u8] {
    if off + 2 > tagged.len() {
        return &[];
    }
    let name_len = u16::from_be_bytes([tagged[off], tagged[off + 1]]) as usize;
    let start = off + 2;
    if start + name_len > tagged.len() {
        return &[];
    }
    &tagged[start..start + name_len]
}

/// XML-C14N 1.1 §1.1 rule 4 — attribute-value character replacement.
fn escape_attr_into(bytes: &[u8], w: &mut SliceWriter<'_>) -> Result<(), ShapeViolation> {
    for &b in bytes {
        match b {
            b'<' => w.write(b"&lt;")?,
            b'>' => w.write(b"&gt;")?,
            b'&' => w.write(b"&amp;")?,
            b'"' => w.write(b"&quot;")?,
            b'\t' => w.write(b"&#x9;")?,
            b'\n' => w.write(b"&#xA;")?,
            b'\r' => w.write(b"&#xD;")?,
            _ => w.write_byte(b)?,
        }
    }
    Ok(())
}

/// XML-C14N 1.1 §1.1 rule 5 — text-content character replacement.
fn escape_text_into(bytes: &[u8], w: &mut SliceWriter<'_>) -> Result<(), ShapeViolation> {
    for &b in bytes {
        match b {
            b'<' => w.write(b"&lt;")?,
            b'>' => w.write(b"&gt;")?,
            b'&' => w.write(b"&amp;")?,
            b'\r' => w.write(b"&#xD;")?,
            _ => w.write_byte(b)?,
        }
    }
    Ok(())
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
        let n = self.len as usize;
        if n > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..n].copy_from_slice(&self.bytes[..n]);
        Ok(n)
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

    #[cfg(feature = "alloc")]
    #[test]
    fn canonicalizes_with_lexicographic_attribute_ordering() {
        let canon = canonicalize(br#"<root b="2" a="1"/>"#).expect("valid");
        assert_eq!(canon, br#"<root a="1" b="2"></root>"#);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn canonicalizer_collapses_cdata_to_text() {
        let canon = canonicalize(b"<root><![CDATA[<hello>]]></root>").expect("valid");
        assert_eq!(canon, b"<root>&lt;hello&gt;</root>");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn canonicalizer_escapes_attribute_values() {
        let canon = canonicalize(br#"<root attr="&lt;v&gt;"/>"#).expect("valid");
        assert_eq!(canon, br#"<root attr="&lt;v&gt;"></root>"#);
    }

    #[cfg(feature = "alloc")]
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

    #[cfg(feature = "alloc")]
    #[test]
    fn rejects_overdeep_nesting() {
        extern crate alloc;
        use alloc::format;
        use alloc::string::String;
        let mut s = String::new();
        for i in 0..(MAX_XML_DEPTH + 2) {
            s.push_str(&format!("<n{i}>"));
        }
        for i in (0..(MAX_XML_DEPTH + 2)).rev() {
            s.push_str(&format!("</n{i}>"));
        }
        let err = XmlValue::parse(s.as_bytes()).expect_err("overdeep");
        assert_eq!(err.constraint_iri, DEPTH_BOUND_VIOLATION.constraint_iri);
    }
}
