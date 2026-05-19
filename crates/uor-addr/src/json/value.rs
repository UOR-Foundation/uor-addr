//! `JsonValue` — the typed JSON-value carrier (wiki ADR-023, ADR-027).
//!
//! Runtime form is a structurally-tagged byte serialization of an
//! RFC 8259 JSON value, stored in a fixed-size stack buffer of
//! [`JSON_VALUE_MAX_BYTES`] bytes. The six JSON cases — object, array,
//! string, number, boolean, null — each map to a known tag in the
//! byte layout; recursive children live inside the same flat buffer.
//!
//! # `no_std` + `no_alloc`
//!
//! `JsonValue::parse` is a hand-rolled JSON tokenizer over `&[u8]`.
//! It performs:
//!
//! - RFC 8259 §3 syntactic validation
//! - JSON-string escape decoding (UTF-8 + `\uXXXX` + surrogate pairs)
//! - UAX #15 NFC normalization at the host boundary via
//!   [`crate::canonical::nfc::normalize_into`]
//! - JCS-RFC8785 §3.2.2.3 / ECMA-262 7.1.12.1 number canonicalization
//!   (integer pass-through plus `ryu`-based `f64` shortest-round-trip)
//!
//! No allocator, no `serde_json`. Every working buffer is a
//! stack-resident array sized by the typed-input bounds declared in
//! [`crate::json::shapes::bounds`].
//!
//! # Tagged byte layout
//!
//! ```text
//! JsonValue ::= Tag(1 byte) Payload
//!   Tag = 0x00 Null         — no payload
//!   Tag = 0x01 BoolFalse    — no payload
//!   Tag = 0x02 BoolTrue     — no payload
//!   Tag = 0x03 Number       — u16 BE length || N bytes (canonical ASCII)
//!   Tag = 0x04 String       — u16 BE length || N bytes (UTF-8, NFC)
//!   Tag = 0x05 Array        — u16 BE count  || count × JsonValue
//!   Tag = 0x06 Object       — u16 BE count  || count × (u16 BE keylen || keybytes || JsonValue)
//! ```
//!
//! All multi-byte length / count fields are big-endian. Strings and
//! object keys are NFC-normalized at parse time, so the canonical-form
//! emitter ([`canonicalize_into_slice`]) is purely structural — it
//! sorts object entries by NFC byte order and emits JCS syntax around
//! already-canonical content.

use prism::pipeline::{
    register_shape, ConstrainedTypeShape, ConstraintRef, IntoBindingValue, ShapeViolation,
    ViolationKind,
};

use crate::canonical::nfc;
use crate::json::shapes::bounds::{
    JSON_VALUE_MAX_BYTES, MAX_ARRAY_ELEMENTS, MAX_JSON_DEPTH, MAX_NUMBER_DIGITS, MAX_OBJECT_KEYS,
    MAX_STRING_BYTES,
};

// ─── Tag byte constants ─────────────────────────────────────────────────

pub(crate) const TAG_NULL: u8 = 0x00;
pub(crate) const TAG_FALSE: u8 = 0x01;
pub(crate) const TAG_TRUE: u8 = 0x02;
pub(crate) const TAG_NUMBER: u8 = 0x03;
pub(crate) const TAG_STRING: u8 = 0x04;
pub(crate) const TAG_ARRAY: u8 = 0x05;
pub(crate) const TAG_OBJECT: u8 = 0x06;

// ─── ShapeViolation IRIs ────────────────────────────────────────────────

const INVALID_JSON_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/validUtf8Json",
    property_iri: "https://uor.foundation/addr/inputBytes",
    expected_range: "https://uor.foundation/addr/ValidUtf8Json",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

const DEPTH_BOUND_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/depthBound",
    property_iri: "https://uor.foundation/addr/JsonValue/depth",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_JSON_DEPTH as u32,
    kind: ViolationKind::CardinalityViolation,
};

const STRING_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/stringWidth",
    property_iri: "https://uor.foundation/addr/JsonValue/stringByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_STRING_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const NUMBER_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/numberWidth",
    property_iri: "https://uor.foundation/addr/JsonValue/numberDigitCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_NUMBER_DIGITS as u32,
    kind: ViolationKind::CardinalityViolation,
};

const OBJECT_KEYS_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/objectKeysBound",
    property_iri: "https://uor.foundation/addr/JsonValue/objectKeyCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_OBJECT_KEYS as u32,
    kind: ViolationKind::CardinalityViolation,
};

const ARRAY_ELEMENTS_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/arrayElementsBound",
    property_iri: "https://uor.foundation/addr/JsonValue/arrayElementCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: MAX_ARRAY_ELEMENTS as u32,
    kind: ViolationKind::CardinalityViolation,
};

const TOTAL_WIDTH_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/serializedWidth",
    property_iri: "https://uor.foundation/addr/JsonValue/totalByteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: JSON_VALUE_MAX_BYTES as u32,
    kind: ViolationKind::CardinalityViolation,
};

const CORRUPT_TAGGED_BYTES: ShapeViolation = ShapeViolation {
    shape_iri: "https://uor.foundation/addr/JsonValue",
    constraint_iri: "https://uor.foundation/addr/JsonValue/wellFormedTaggedBytes",
    property_iri: "https://uor.foundation/addr/JsonValue/taggedBytes",
    expected_range: "https://uor.foundation/addr/WellFormedTaggedJsonValue",
    min_count: 0,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

// ─── JsonValue — the typed input carrier ────────────────────────────────

/// Typed JSON-value input shape. Runtime bytes are the
/// structurally-tagged serialization documented in the module
/// header, stored in a fixed-size stack buffer. Construction goes
/// through [`JsonValue::parse`] which validates every typed-input
/// bound.
#[derive(Clone)]
pub struct JsonValue {
    /// Structurally-tagged byte serialization. Length tracked by
    /// `len`; well-formed per the module header's grammar.
    pub(crate) bytes: [u8; JSON_VALUE_MAX_BYTES],
    /// Number of valid tagged bytes in `bytes[..len]`.
    pub(crate) len: u16,
}

impl core::fmt::Debug for JsonValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JsonValue")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl PartialEq for JsonValue {
    fn eq(&self, other: &Self) -> bool {
        self.tagged_bytes() == other.tagged_bytes()
    }
}

impl Eq for JsonValue {}

impl JsonValue {
    /// Parse raw JSON bytes into a typed `JsonValue`.
    ///
    /// # Errors
    ///
    /// - `validUtf8Json` — input is not valid UTF-8 JSON.
    /// - `depthBound` — nesting depth exceeds [`MAX_JSON_DEPTH`].
    /// - `stringWidth` — a string value or object key's NFC form
    ///   exceeds [`MAX_STRING_BYTES`] UTF-8 bytes.
    /// - `numberWidth` — a number's canonical text exceeds
    ///   [`MAX_NUMBER_DIGITS`] characters.
    /// - `objectKeysBound` — an object has more than
    ///   [`MAX_OBJECT_KEYS`] keys.
    /// - `arrayElementsBound` — an array has more than
    ///   [`MAX_ARRAY_ELEMENTS`] elements.
    /// - `serializedWidth` — the tagged byte serialization exceeds
    ///   [`JSON_VALUE_MAX_BYTES`].
    pub fn parse(raw: &[u8]) -> Result<Self, ShapeViolation> {
        let mut value = Self {
            bytes: [0u8; JSON_VALUE_MAX_BYTES],
            len: 0,
        };
        let mut p = Parser::new(raw);
        p.skip_ws();
        // Stack-resident scratch buffer for JSON-string unescape
        // (before NFC normalization). Bounded by the raw JSON-input
        // width: a JSON string's raw bytes between quotes are part
        // of `raw`, so the unescape output (which only shrinks) fits
        // inside `MAX_STRING_BYTES * 3` — the conservative pre-NFC
        // tolerance (UAX #15 NFC expansion factor ≤ 3).
        let mut str_scratch = [0u8; MAX_STRING_BYTES * 3];
        parse_value(&mut p, &mut value, 0, &mut str_scratch)?;
        p.skip_ws();
        if !p.is_eof() {
            return Err(INVALID_JSON_VIOLATION);
        }
        if value.len as usize > JSON_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        Ok(value)
    }

    /// Borrow the structurally-tagged byte serialization. This is
    /// the runtime form the ψ-pipeline carries through every
    /// resolver carrier; it is **not** the canonical-form bytes the
    /// SHA-256 axis hashes. ψ_9 derives the canonical bytes from
    /// these via [`canonicalize_into_slice`].
    #[must_use]
    pub fn tagged_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    fn push_byte(&mut self, b: u8) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos >= JSON_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos] = b;
        self.len += 1;
        Ok(())
    }

    fn push_u16_be(&mut self, v: u16) -> Result<(), ShapeViolation> {
        let pos = self.len as usize;
        if pos + 2 > JSON_VALUE_MAX_BYTES {
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
        if pos + data.len() > JSON_VALUE_MAX_BYTES {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        self.bytes[pos..pos + data.len()].copy_from_slice(data);
        self.len += data.len() as u16;
        Ok(())
    }
}

// ─── Convenience alloc surface (feature = "alloc") ──────────────────────

/// Parse raw JSON bytes and emit the JCS-RFC8785 + Unicode NFC
/// canonical-form bytes — the same bytes ψ_9 hashes inside the
/// typed-iso surface.
///
/// **Available only under the `alloc` feature.** The no_alloc
/// equivalent is [`canonicalize_into_slice`] which writes into a
/// caller-supplied `&mut [u8]`. The κ-derivation pipeline itself is
/// alloc-free; this convenience wrapper exists so std/alloc-bearing
/// consumers don't have to size and pass their own output buffer.
///
/// # Errors
///
/// Surfaces any [`ShapeViolation`] [`JsonValue::parse`] would emit
/// for the same input.
#[cfg(feature = "alloc")]
pub fn canonicalize(raw: &[u8]) -> Result<alloc::vec::Vec<u8>, ShapeViolation> {
    extern crate alloc;
    let value = JsonValue::parse(raw)?;
    let mut out = alloc::vec![0u8; JSON_VALUE_MAX_BYTES];
    let n = canonicalize_into_slice(value.tagged_bytes(), &mut out)?;
    out.truncate(n);
    Ok(out)
}

// ─── Streaming JSON tokenizer ───────────────────────────────────────────

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> Result<u8, ShapeViolation> {
        if self.is_eof() {
            return Err(INVALID_JSON_VIOLATION);
        }
        Ok(self.input[self.pos])
    }

    fn bump(&mut self) -> Result<u8, ShapeViolation> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.input.len() {
            match self.input[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), ShapeViolation> {
        if self.bump()? != byte {
            return Err(INVALID_JSON_VIOLATION);
        }
        Ok(())
    }

    fn expect_lit(&mut self, lit: &[u8]) -> Result<(), ShapeViolation> {
        if self.pos + lit.len() > self.input.len() {
            return Err(INVALID_JSON_VIOLATION);
        }
        if &self.input[self.pos..self.pos + lit.len()] != lit {
            return Err(INVALID_JSON_VIOLATION);
        }
        self.pos += lit.len();
        Ok(())
    }
}

fn parse_value(
    p: &mut Parser<'_>,
    out: &mut JsonValue,
    depth: usize,
    str_scratch: &mut [u8; MAX_STRING_BYTES * 3],
) -> Result<(), ShapeViolation> {
    if depth > MAX_JSON_DEPTH {
        return Err(DEPTH_BOUND_VIOLATION);
    }
    p.skip_ws();
    match p.peek()? {
        b'n' => {
            p.expect_lit(b"null")?;
            out.push_byte(TAG_NULL)
        }
        b't' => {
            p.expect_lit(b"true")?;
            out.push_byte(TAG_TRUE)
        }
        b'f' => {
            p.expect_lit(b"false")?;
            out.push_byte(TAG_FALSE)
        }
        b'"' => parse_string(p, out, str_scratch),
        b'-' | b'0'..=b'9' => parse_number(p, out),
        b'[' => parse_array(p, out, depth + 1, str_scratch),
        b'{' => parse_object(p, out, depth + 1, str_scratch),
        _ => Err(INVALID_JSON_VIOLATION),
    }
}

fn parse_array(
    p: &mut Parser<'_>,
    out: &mut JsonValue,
    depth: usize,
    str_scratch: &mut [u8; MAX_STRING_BYTES * 3],
) -> Result<(), ShapeViolation> {
    p.expect(b'[')?;
    out.push_byte(TAG_ARRAY)?;
    let count_pos = out.len as usize;
    out.push_u16_be(0)?; // placeholder for count
    let mut count: u32 = 0;
    p.skip_ws();
    if p.peek()? == b']' {
        p.pos += 1;
        return Ok(());
    }
    loop {
        if count as usize >= MAX_ARRAY_ELEMENTS {
            return Err(ARRAY_ELEMENTS_VIOLATION);
        }
        parse_value(p, out, depth, str_scratch)?;
        count += 1;
        p.skip_ws();
        match p.bump()? {
            b',' => {
                p.skip_ws();
                continue;
            }
            b']' => break,
            _ => return Err(INVALID_JSON_VIOLATION),
        }
    }
    let count_bytes = (count as u16).to_be_bytes();
    out.bytes[count_pos] = count_bytes[0];
    out.bytes[count_pos + 1] = count_bytes[1];
    Ok(())
}

fn parse_object(
    p: &mut Parser<'_>,
    out: &mut JsonValue,
    depth: usize,
    str_scratch: &mut [u8; MAX_STRING_BYTES * 3],
) -> Result<(), ShapeViolation> {
    p.expect(b'{')?;
    out.push_byte(TAG_OBJECT)?;
    let count_pos = out.len as usize;
    out.push_u16_be(0)?; // placeholder
    let mut count: u32 = 0;
    p.skip_ws();
    if p.peek()? == b'}' {
        p.pos += 1;
        return Ok(());
    }
    loop {
        if count as usize >= MAX_OBJECT_KEYS {
            return Err(OBJECT_KEYS_VIOLATION);
        }
        p.skip_ws();
        if p.peek()? != b'"' {
            return Err(INVALID_JSON_VIOLATION);
        }
        // Parse the key as a string. Reuse the string parser; the
        // key is emitted as `(u16 len, key bytes, value)` in tagged
        // form. We push only the key length + bytes (no TAG_STRING
        // prefix) since the object grammar places the key inline.
        parse_object_key(p, out, str_scratch)?;
        p.skip_ws();
        p.expect(b':')?;
        p.skip_ws();
        parse_value(p, out, depth, str_scratch)?;
        count += 1;
        p.skip_ws();
        match p.bump()? {
            b',' => continue,
            b'}' => break,
            _ => return Err(INVALID_JSON_VIOLATION),
        }
    }
    let count_bytes = (count as u16).to_be_bytes();
    out.bytes[count_pos] = count_bytes[0];
    out.bytes[count_pos + 1] = count_bytes[1];
    Ok(())
}

fn parse_object_key(
    p: &mut Parser<'_>,
    out: &mut JsonValue,
    str_scratch: &mut [u8; MAX_STRING_BYTES * 3],
) -> Result<(), ShapeViolation> {
    let nfc_len = decode_string_into_nfc(p, str_scratch)?;
    if nfc_len > MAX_STRING_BYTES {
        return Err(STRING_WIDTH_VIOLATION);
    }
    out.push_u16_be(nfc_len as u16)?;
    out.extend(&str_scratch[..nfc_len])
}

fn parse_string(
    p: &mut Parser<'_>,
    out: &mut JsonValue,
    str_scratch: &mut [u8; MAX_STRING_BYTES * 3],
) -> Result<(), ShapeViolation> {
    let nfc_len = decode_string_into_nfc(p, str_scratch)?;
    if nfc_len > MAX_STRING_BYTES {
        return Err(STRING_WIDTH_VIOLATION);
    }
    out.push_byte(TAG_STRING)?;
    out.push_u16_be(nfc_len as u16)?;
    out.extend(&str_scratch[..nfc_len])
}

/// Decode a JSON string literal at the parser's cursor, applying
/// `\…` escape handling + NFC normalization. Writes the NFC-normalized
/// UTF-8 bytes into `scratch` and returns the byte length written.
///
/// The cursor advances past the closing `"`.
fn decode_string_into_nfc(
    p: &mut Parser<'_>,
    scratch: &mut [u8; MAX_STRING_BYTES * 3],
) -> Result<usize, ShapeViolation> {
    p.expect(b'"')?;
    // Decode escapes into a stage-1 buffer; NFC-normalize into a
    // stage-2 buffer. Since scratch is 3× MAX_STRING_BYTES, we use
    // the first 2× as stage-1 and the last 1× as stage-2 reserve —
    // but the NFC normalizer writes byte-by-byte into a destination
    // independent of input, so we use a separate small stage-1
    // buffer instead.
    let mut stage1 = [0u8; MAX_STRING_BYTES * 2];
    let mut stage1_len = 0usize;
    loop {
        if p.is_eof() {
            return Err(INVALID_JSON_VIOLATION);
        }
        let b = p.input[p.pos];
        match b {
            b'"' => {
                p.pos += 1;
                break;
            }
            b'\\' => {
                p.pos += 1;
                let esc = p.bump()?;
                match esc {
                    b'"' => write_byte(&mut stage1, &mut stage1_len, b'"')?,
                    b'\\' => write_byte(&mut stage1, &mut stage1_len, b'\\')?,
                    b'/' => write_byte(&mut stage1, &mut stage1_len, b'/')?,
                    b'b' => write_byte(&mut stage1, &mut stage1_len, 0x08)?,
                    b'f' => write_byte(&mut stage1, &mut stage1_len, 0x0C)?,
                    b'n' => write_byte(&mut stage1, &mut stage1_len, 0x0A)?,
                    b'r' => write_byte(&mut stage1, &mut stage1_len, 0x0D)?,
                    b't' => write_byte(&mut stage1, &mut stage1_len, 0x09)?,
                    b'u' => {
                        let cp = decode_u_escape(p)?;
                        write_code_point(&mut stage1, &mut stage1_len, cp)?;
                    }
                    _ => return Err(INVALID_JSON_VIOLATION),
                }
            }
            // Unescaped control characters (U+0000..U+001F) are
            // forbidden by RFC 8259 §7.
            0x00..=0x1F => return Err(INVALID_JSON_VIOLATION),
            // Pass through. UTF-8 validity is checked by the NFC
            // normalizer in the next stage.
            _ => {
                write_byte(&mut stage1, &mut stage1_len, b)?;
                p.pos += 1;
            }
        }
    }
    // NFC-normalize stage1 into the scratch buffer.
    let nfc_len = nfc::normalize_into(&stage1[..stage1_len], &mut scratch[..])
        .map_err(|_| INVALID_JSON_VIOLATION)?;
    Ok(nfc_len)
}

fn write_byte(buf: &mut [u8], len: &mut usize, b: u8) -> Result<(), ShapeViolation> {
    if *len >= buf.len() {
        return Err(STRING_WIDTH_VIOLATION);
    }
    buf[*len] = b;
    *len += 1;
    Ok(())
}

fn write_code_point(buf: &mut [u8], len: &mut usize, cp: u32) -> Result<(), ShapeViolation> {
    let c = char::from_u32(cp).ok_or(INVALID_JSON_VIOLATION)?;
    let mut tmp = [0u8; 4];
    let s = c.encode_utf8(&mut tmp);
    let bytes = s.as_bytes();
    if *len + bytes.len() > buf.len() {
        return Err(STRING_WIDTH_VIOLATION);
    }
    buf[*len..*len + bytes.len()].copy_from_slice(bytes);
    *len += bytes.len();
    Ok(())
}

fn decode_u_escape(p: &mut Parser<'_>) -> Result<u32, ShapeViolation> {
    let high = decode_hex4(p)?;
    // High surrogate?
    if (0xD800..=0xDBFF).contains(&high) {
        // Must be followed by `\u` low surrogate.
        if p.input.get(p.pos..p.pos + 2) != Some(b"\\u") {
            return Err(INVALID_JSON_VIOLATION);
        }
        p.pos += 2;
        let low = decode_hex4(p)?;
        if !(0xDC00..=0xDFFF).contains(&low) {
            return Err(INVALID_JSON_VIOLATION);
        }
        Ok(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
    } else if (0xDC00..=0xDFFF).contains(&high) {
        // Lone low surrogate — not a valid Unicode scalar.
        Err(INVALID_JSON_VIOLATION)
    } else {
        Ok(high)
    }
}

fn decode_hex4(p: &mut Parser<'_>) -> Result<u32, ShapeViolation> {
    if p.pos + 4 > p.input.len() {
        return Err(INVALID_JSON_VIOLATION);
    }
    let mut v: u32 = 0;
    for _ in 0..4 {
        let d = p.input[p.pos];
        p.pos += 1;
        let nibble = match d {
            b'0'..=b'9' => (d - b'0') as u32,
            b'a'..=b'f' => 10 + (d - b'a') as u32,
            b'A'..=b'F' => 10 + (d - b'A') as u32,
            _ => return Err(INVALID_JSON_VIOLATION),
        };
        v = (v << 4) | nibble;
    }
    Ok(v)
}

fn parse_number(p: &mut Parser<'_>, out: &mut JsonValue) -> Result<(), ShapeViolation> {
    let start = p.pos;
    let mut has_decimal = false;
    let mut has_exponent = false;
    // optional '-'
    if p.peek()? == b'-' {
        p.pos += 1;
    }
    // int part: "0" | digit1-9 *DIGIT
    match p.peek()? {
        b'0' => {
            p.pos += 1;
        }
        b'1'..=b'9' => {
            p.pos += 1;
            while let Ok(b) = p.peek() {
                if b.is_ascii_digit() {
                    p.pos += 1;
                } else {
                    break;
                }
            }
        }
        _ => return Err(INVALID_JSON_VIOLATION),
    }
    // optional fractional part
    if p.peek().ok() == Some(b'.') {
        has_decimal = true;
        p.pos += 1;
        let frac_start = p.pos;
        while let Ok(b) = p.peek() {
            if b.is_ascii_digit() {
                p.pos += 1;
            } else {
                break;
            }
        }
        if p.pos == frac_start {
            return Err(INVALID_JSON_VIOLATION);
        }
    }
    // optional exponent
    if let Ok(b) = p.peek() {
        if b == b'e' || b == b'E' {
            has_exponent = true;
            p.pos += 1;
            if let Ok(s) = p.peek() {
                if s == b'+' || s == b'-' {
                    p.pos += 1;
                }
            }
            let exp_start = p.pos;
            while let Ok(d) = p.peek() {
                if d.is_ascii_digit() {
                    p.pos += 1;
                } else {
                    break;
                }
            }
            if p.pos == exp_start {
                return Err(INVALID_JSON_VIOLATION);
            }
        }
    }
    let raw = &p.input[start..p.pos];
    let canon = canonicalize_number(raw, has_decimal || has_exponent)?;
    let bytes = canon.as_bytes();
    if bytes.len() > MAX_NUMBER_DIGITS {
        return Err(NUMBER_WIDTH_VIOLATION);
    }
    out.push_byte(TAG_NUMBER)?;
    out.push_u16_be(bytes.len() as u16)?;
    out.extend(bytes)
}

/// Maximum canonical-number byte length — `ryu::Buffer` formats any
/// `f64` in at most ~24 bytes; 32 gives headroom.
const NUMBER_CANON_BUF: usize = 32;

// ─── Streaming JCS canonicalizer (tagged bytes → canonical bytes) ───────

/// Decode tagged bytes and emit the JCS-RFC8785 + Unicode NFC
/// canonical-form bytes into `out`. Returns the number of bytes
/// written. The ψ_9 resolver invokes this inside its resolver body
/// per ADR-046's iterative-resolution discipline.
///
/// Strings and numbers in the tagged form are already canonical
/// (NFC + JCS number rules applied at parse time), so this walker is
/// purely structural — sorts object entries by NFC key bytes, emits
/// JCS syntax (quotes, commas, colons) around already-canonical
/// content.
///
/// # Errors
///
/// - [`CORRUPT_TAGGED_BYTES`] — the tagged buffer is truncated or
///   carries an unknown structural tag. Unreachable for `JsonValue`
///   instances constructed through [`JsonValue::parse`].
/// - [`TOTAL_WIDTH_VIOLATION`] — the canonical-form bytes exceed
///   `out.len()`. The caller is responsible for sizing `out` large
///   enough; [`JSON_VALUE_MAX_BYTES`] suffices because JCS+NFC
///   canonicalization is byte-output-bounded by the tagged input
///   width.
pub fn canonicalize_into_slice(tagged: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
    let mut writer = SliceWriter::new(out);
    let mut pos = 0;
    emit_value(tagged, &mut pos, &mut writer)?;
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
) -> Result<(), ShapeViolation> {
    let tag = read_byte(tagged, pos)?;
    match tag {
        TAG_NULL => w.write(b"null"),
        TAG_FALSE => w.write(b"false"),
        TAG_TRUE => w.write(b"true"),
        TAG_NUMBER => {
            let len = read_u16_be(tagged, pos)? as usize;
            let bytes = read_slice(tagged, pos, len)?;
            w.write(bytes)
        }
        TAG_STRING => {
            let len = read_u16_be(tagged, pos)? as usize;
            let bytes = read_slice(tagged, pos, len)?;
            emit_json_string(bytes, w)
        }
        TAG_ARRAY => {
            let count = read_u16_be(tagged, pos)? as usize;
            w.write_byte(b'[')?;
            for i in 0..count {
                if i > 0 {
                    w.write_byte(b',')?;
                }
                emit_value(tagged, pos, w)?;
            }
            w.write_byte(b']')
        }
        TAG_OBJECT => emit_object(tagged, pos, w),
        _ => Err(CORRUPT_TAGGED_BYTES),
    }
}

fn emit_object(
    tagged: &[u8],
    pos: &mut usize,
    w: &mut SliceWriter<'_>,
) -> Result<(), ShapeViolation> {
    let count = read_u16_be(tagged, pos)? as usize;
    if count > MAX_OBJECT_KEYS {
        return Err(CORRUPT_TAGGED_BYTES);
    }
    // Stack-local entry-offset array for this object level. Each
    // entry's offset points at the start of its `u16 keylen` in
    // `tagged`. Reusing the arena across recursion levels would
    // halve stack memory but would require interior-mutable
    // bookkeeping; stack-local keeps the code straightforward and
    // fits within ≤ MAX_JSON_DEPTH × MAX_OBJECT_KEYS × 2 bytes =
    // 16 KiB worst case.
    let mut entries = [0u16; MAX_OBJECT_KEYS];
    for slot in entries[..count].iter_mut() {
        *slot = *pos as u16;
        let key_len = read_u16_be(tagged, pos)? as usize;
        *pos += key_len;
        if *pos > tagged.len() {
            return Err(CORRUPT_TAGGED_BYTES);
        }
        skip_value(tagged, pos)?;
    }
    // Stable sort by NFC key bytes (lex byte order; strings are
    // pre-normalized at parse time so byte order == NFC order).
    insertion_sort_by_key(&mut entries[..count], tagged);
    w.write_byte(b'{')?;
    for (i, &entry_off) in entries[..count].iter().enumerate() {
        if i > 0 {
            w.write_byte(b',')?;
        }
        let mut p = entry_off as usize;
        let key_len = read_u16_be(tagged, &mut p)? as usize;
        let key_bytes = read_slice(tagged, &mut p, key_len)?;
        emit_json_string(key_bytes, w)?;
        w.write_byte(b':')?;
        emit_value(tagged, &mut p, w)?;
    }
    w.write_byte(b'}')
}

/// Stable insertion sort on `entries` by the key bytes each entry
/// points to in `tagged`. Key bytes are at `tagged[off+2..off+2+keylen]`
/// where `off` is the entry offset.
fn insertion_sort_by_key(entries: &mut [u16], tagged: &[u8]) {
    for i in 1..entries.len() {
        let mut j = i;
        while j > 0 {
            let a = entry_key(entries[j - 1] as usize, tagged);
            let b = entry_key(entries[j] as usize, tagged);
            if a > b {
                entries.swap(j - 1, j);
                j -= 1;
            } else {
                break;
            }
        }
    }
}

fn entry_key(off: usize, tagged: &[u8]) -> &[u8] {
    if off + 2 > tagged.len() {
        return &[];
    }
    let key_len = u16::from_be_bytes([tagged[off], tagged[off + 1]]) as usize;
    let start = off + 2;
    if start + key_len > tagged.len() {
        return &[];
    }
    &tagged[start..start + key_len]
}

fn skip_value(tagged: &[u8], pos: &mut usize) -> Result<(), ShapeViolation> {
    let tag = read_byte(tagged, pos)?;
    match tag {
        TAG_NULL | TAG_FALSE | TAG_TRUE => Ok(()),
        TAG_NUMBER | TAG_STRING => {
            let len = read_u16_be(tagged, pos)? as usize;
            *pos += len;
            if *pos > tagged.len() {
                Err(CORRUPT_TAGGED_BYTES)
            } else {
                Ok(())
            }
        }
        TAG_ARRAY => {
            let count = read_u16_be(tagged, pos)? as usize;
            for _ in 0..count {
                skip_value(tagged, pos)?;
            }
            Ok(())
        }
        TAG_OBJECT => {
            let count = read_u16_be(tagged, pos)? as usize;
            for _ in 0..count {
                let key_len = read_u16_be(tagged, pos)? as usize;
                *pos += key_len;
                if *pos > tagged.len() {
                    return Err(CORRUPT_TAGGED_BYTES);
                }
                skip_value(tagged, pos)?;
            }
            Ok(())
        }
        _ => Err(CORRUPT_TAGGED_BYTES),
    }
}

/// Emit `bytes` as a JCS-compliant JSON string literal: surrounding
/// `"` quotes, characters U+0000..U+001F + `"` + `\` escaped per
/// JCS §3.2.2.2, everything else passed through.
fn emit_json_string(bytes: &[u8], w: &mut SliceWriter<'_>) -> Result<(), ShapeViolation> {
    w.write_byte(b'"')?;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' => {
                w.write(b"\\\"")?;
                i += 1;
            }
            b'\\' => {
                w.write(b"\\\\")?;
                i += 1;
            }
            0x08 => {
                w.write(b"\\b")?;
                i += 1;
            }
            0x09 => {
                w.write(b"\\t")?;
                i += 1;
            }
            0x0A => {
                w.write(b"\\n")?;
                i += 1;
            }
            0x0C => {
                w.write(b"\\f")?;
                i += 1;
            }
            0x0D => {
                w.write(b"\\r")?;
                i += 1;
            }
            0x00..=0x1F => {
                // JCS §3.2.2.2: other control characters → \uXXXX
                let mut buf = [0u8; 6];
                buf[0] = b'\\';
                buf[1] = b'u';
                buf[2] = b'0';
                buf[3] = b'0';
                buf[4] = nibble_hex(b >> 4);
                buf[5] = nibble_hex(b & 0x0f);
                w.write(&buf)?;
                i += 1;
            }
            _ => {
                w.write_byte(b)?;
                i += 1;
            }
        }
    }
    w.write_byte(b'"')
}

fn nibble_hex(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + (n - 10),
        _ => b'0',
    }
}

// ─── Number canonicalization implementation ─────────────────────────────

/// Owned canonical-number bytes — a 32-byte stack carrier returned
/// from [`canonicalize_number`]. JCS §3.2.2.3 / ECMA-262 7.1.12.1
/// canonical forms (`ryu` shortest-round-trip output, or integer
/// pass-through) fit in ≤ 24 bytes for any `f64`; we round to 32.
struct NumberCanonOwned {
    buf: [u8; NUMBER_CANON_BUF],
    len: u8,
}

impl NumberCanonOwned {
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

/// Canonicalize a JSON number literal per JCS-RFC8785 §3.2.2.3
/// (ECMA-262 7.1.12.1).
///
/// - Integer-syntax literals (no `.`, no `e`/`E`, and not the
///   `-0` negative-zero literal) pass through verbatim — RFC 8259 §6
///   forbids leading zeros and explicit `+` signs, so the input is
///   already in ECMA-262 ToString form.
/// - Float-syntax literals (or `-0`, which ECMA-262 ToString routes
///   through `f64`) parse to `f64` and serialize via `ryu` — the same
///   shortest-round-trip path modern `serde_json` uses.
fn canonicalize_number(
    raw: &[u8],
    is_float_syntax: bool,
) -> Result<NumberCanonOwned, ShapeViolation> {
    let mut owned = NumberCanonOwned {
        buf: [0u8; NUMBER_CANON_BUF],
        len: 0,
    };
    let is_negative_zero = raw == b"-0";
    if is_float_syntax || is_negative_zero {
        let s = core::str::from_utf8(raw).map_err(|_| INVALID_JSON_VIOLATION)?;
        let v: f64 = s.parse().map_err(|_| INVALID_JSON_VIOLATION)?;
        let mut ryu_buf = ryu::Buffer::new();
        let formatted = ryu_buf.format(v).as_bytes();
        if formatted.len() > owned.buf.len() {
            return Err(NUMBER_WIDTH_VIOLATION);
        }
        owned.buf[..formatted.len()].copy_from_slice(formatted);
        owned.len = formatted.len() as u8;
    } else {
        if raw.len() > owned.buf.len() {
            return Err(NUMBER_WIDTH_VIOLATION);
        }
        owned.buf[..raw.len()].copy_from_slice(raw);
        owned.len = raw.len() as u8;
    }
    Ok(owned)
}

// ─── JsonValueRef — tagged-byte navigator for schema admission ──────────
//
// Schema descendants (`crate::schema::*`) walk a parsed JSON value to
// validate JSON-LD admission predicates without serde_json. The walk
// reads directly out of [`JsonValue::tagged_bytes`] using the tag
// layout documented in the module header. Keys and string values are
// already NFC-normalized; numeric values carry their canonical
// ASCII text. The navigator never allocates.

/// Zero-copy view into a tagged-byte JSON value (or sub-value).
/// Constructed via [`JsonValueRef::root`]; descendants reach children
/// via [`JsonValueRef::get`], [`JsonValueRef::iter_object`], etc.
#[derive(Clone, Copy)]
pub struct JsonValueRef<'a> {
    tagged: &'a [u8],
    offset: usize,
}

impl<'a> JsonValueRef<'a> {
    /// Root navigator over a parsed [`JsonValue`].
    pub fn root(value: &'a JsonValue) -> Self {
        Self {
            tagged: value.tagged_bytes(),
            offset: 0,
        }
    }

    /// Tag byte at this position.
    pub fn tag(&self) -> u8 {
        self.tagged[self.offset]
    }

    pub fn is_null(&self) -> bool {
        self.tag() == TAG_NULL
    }
    pub fn is_bool(&self) -> bool {
        matches!(self.tag(), TAG_FALSE | TAG_TRUE)
    }
    pub fn is_number(&self) -> bool {
        self.tag() == TAG_NUMBER
    }
    pub fn is_string(&self) -> bool {
        self.tag() == TAG_STRING
    }
    pub fn is_array(&self) -> bool {
        self.tag() == TAG_ARRAY
    }
    pub fn is_object(&self) -> bool {
        self.tag() == TAG_OBJECT
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self.tag() {
            TAG_FALSE => Some(false),
            TAG_TRUE => Some(true),
            _ => None,
        }
    }

    /// Borrow the NFC-normalized UTF-8 byte content of a string value.
    /// `None` if the value is not a string.
    pub fn as_str(&self) -> Option<&'a [u8]> {
        if !self.is_string() {
            return None;
        }
        let mut p = self.offset + 1;
        let len = read_u16_be(self.tagged, &mut p).ok()? as usize;
        Some(&self.tagged[p..p + len])
    }

    /// Borrow the canonical-form ASCII text of a number value.
    pub fn as_number_str(&self) -> Option<&'a [u8]> {
        if !self.is_number() {
            return None;
        }
        let mut p = self.offset + 1;
        let len = read_u16_be(self.tagged, &mut p).ok()? as usize;
        Some(&self.tagged[p..p + len])
    }

    /// Look up an object entry by its NFC key bytes. Returns the
    /// referenced value, or `None` if `self` is not an object or
    /// the key is absent.
    pub fn get(&self, key: &[u8]) -> Option<JsonValueRef<'a>> {
        let mut iter = self.iter_object()?;
        iter.find_map(|(k, v)| if k == key { Some(v) } else { None })
    }

    /// Iterate object entries `(key_bytes, value_ref)` in **tagged-form
    /// order** (parser-emitted input order; not canonical-sort order).
    /// Returns `None` if `self` is not an object.
    pub fn iter_object(&self) -> Option<ObjectIter<'a>> {
        if !self.is_object() {
            return None;
        }
        let mut p = self.offset + 1;
        let count = read_u16_be(self.tagged, &mut p).ok()? as usize;
        Some(ObjectIter {
            tagged: self.tagged,
            pos: p,
            remaining: count,
        })
    }

    /// Iterate array elements `value_ref`. Returns `None` if `self`
    /// is not an array.
    pub fn iter_array(&self) -> Option<ArrayIter<'a>> {
        if !self.is_array() {
            return None;
        }
        let mut p = self.offset + 1;
        let count = read_u16_be(self.tagged, &mut p).ok()? as usize;
        Some(ArrayIter {
            tagged: self.tagged,
            pos: p,
            remaining: count,
        })
    }
}

/// Iterator over an object's `(key_bytes, value)` entries.
pub struct ObjectIter<'a> {
    tagged: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for ObjectIter<'a> {
    type Item = (&'a [u8], JsonValueRef<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let key_len = read_u16_be(self.tagged, &mut self.pos).ok()? as usize;
        let key_end = self.pos + key_len;
        let key = &self.tagged[self.pos..key_end];
        self.pos = key_end;
        let value_offset = self.pos;
        self.pos = skip_to_end(self.tagged, self.pos).ok()?;
        self.remaining -= 1;
        Some((
            key,
            JsonValueRef {
                tagged: self.tagged,
                offset: value_offset,
            },
        ))
    }
}

/// Iterator over an array's elements.
pub struct ArrayIter<'a> {
    tagged: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for ArrayIter<'a> {
    type Item = JsonValueRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let value_offset = self.pos;
        self.pos = skip_to_end(self.tagged, self.pos).ok()?;
        self.remaining -= 1;
        Some(JsonValueRef {
            tagged: self.tagged,
            offset: value_offset,
        })
    }
}

/// Advance past one value starting at `pos`, returning the new
/// position. Used by the navigator iterators to walk past skipped
/// entries.
fn skip_to_end(tagged: &[u8], pos: usize) -> Result<usize, ShapeViolation> {
    let mut p = pos;
    let tag = read_byte(tagged, &mut p)?;
    match tag {
        TAG_NULL | TAG_FALSE | TAG_TRUE => Ok(p),
        TAG_NUMBER | TAG_STRING => {
            let len = read_u16_be(tagged, &mut p)? as usize;
            Ok(p + len)
        }
        TAG_ARRAY => {
            let count = read_u16_be(tagged, &mut p)? as usize;
            for _ in 0..count {
                p = skip_to_end(tagged, p)?;
            }
            Ok(p)
        }
        TAG_OBJECT => {
            let count = read_u16_be(tagged, &mut p)? as usize;
            for _ in 0..count {
                let key_len = read_u16_be(tagged, &mut p)? as usize;
                p += key_len;
                p = skip_to_end(tagged, p)?;
            }
            Ok(p)
        }
        _ => Err(CORRUPT_TAGGED_BYTES),
    }
}

// ─── ConstrainedTypeShape + IntoBindingValue impls ──────────────────────

impl ConstrainedTypeShape for JsonValue {
    const IRI: &'static str = "https://uor.foundation/addr/JsonValue";
    const SITE_COUNT: usize = JSON_VALUE_MAX_BYTES;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for JsonValue {}

impl IntoBindingValue for JsonValue {
    const MAX_BYTES: usize = JSON_VALUE_MAX_BYTES;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        let n = self.len as usize;
        if n > out.len() {
            return Err(TOTAL_WIDTH_VIOLATION);
        }
        out[..n].copy_from_slice(&self.bytes[..n]);
        Ok(n)
    }
}

register_shape!(JsonValueRegistry, JsonValue);

impl crate::common::AddressInput for JsonValue {
    type Registry = JsonValueRegistry;

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
    fn parses_simple_object() {
        let v = JsonValue::parse(br#"{"foo":"bar"}"#).expect("valid");
        assert_eq!(v.bytes[0], TAG_OBJECT);
    }

    #[test]
    fn rejects_invalid_json() {
        let err = JsonValue::parse(b"not json").expect_err("must reject");
        assert_eq!(err.shape_iri, INVALID_JSON_VIOLATION.shape_iri);
    }

    #[test]
    fn rejects_overdeep_recursion() {
        extern crate alloc;
        use alloc::string::String;
        let mut s = String::new();
        for _ in 0..(MAX_JSON_DEPTH + 2) {
            s.push('[');
        }
        for _ in 0..(MAX_JSON_DEPTH + 2) {
            s.push(']');
        }
        let err = JsonValue::parse(s.as_bytes()).expect_err("must reject");
        assert_eq!(err.constraint_iri, DEPTH_BOUND_VIOLATION.constraint_iri);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn rejects_oversize_string() {
        extern crate alloc;
        use alloc::format;
        use alloc::string::String;
        let big: String = "a".repeat(MAX_STRING_BYTES + 1);
        let raw = format!("\"{big}\"");
        let err = JsonValue::parse(raw.as_bytes()).expect_err("must reject");
        assert_eq!(err.constraint_iri, STRING_WIDTH_VIOLATION.constraint_iri);
    }

    #[cfg(feature = "alloc")]
    const CANONICAL_FIXTURES: &[(&[u8], &[u8])] = &[
        (br#"{"foo":"bar"}"#, br#"{"foo":"bar"}"#),
        (br#"{"b": 1, "a": 2}"#, br#"{"a":2,"b":1}"#),
        (
            br#"{"nested": {"deep": {"value": "found"}}}"#,
            br#"{"nested":{"deep":{"value":"found"}}}"#,
        ),
        (
            br#"{"int": 42, "bool": true, "null_val": null}"#,
            br#"{"bool":true,"int":42,"null_val":null}"#,
        ),
        (b"[1, 2, 3]", b"[1,2,3]"),
        (br#"["a", "b", "c"]"#, br#"["a","b","c"]"#),
    ];

    #[cfg(feature = "alloc")]
    #[test]
    fn canonicalizer_matches_reference_for_inline_fixtures() {
        for (raw, expected) in CANONICAL_FIXTURES {
            let canon = canonicalize(raw).expect("valid");
            assert_eq!(canon, *expected, "raw={raw:?}");
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn canonicalizer_collapses_unicode_decomposed_to_composed() {
        let decomposed = "{\"name\": \"cafe\u{0301}\"}".as_bytes();
        let composed = "{\"name\":\"caf\u{00E9}\"}".as_bytes();
        assert_eq!(
            canonicalize(decomposed).expect("valid"),
            canonicalize(composed).expect("valid")
        );
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
