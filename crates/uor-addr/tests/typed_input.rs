//! CT — Typed-input class: claims that follow from the
//! `JsonValue`-typed input surface (CONFORMANCE.md §CT). The typed
//! input shape lets us distinguish `42` from `"42"`, reject
//! oversize/over-deep inputs at construction, and prove
//! structural-equivalence classes collapse to a single κ-label.
//!
//! Run via `just test` (debug) or `just conformance` (release).

#![allow(non_snake_case)]

use uor_addr::json::{address, canonicalize, AddressFailure, JsonValue, MAX_JSON_DEPTH};

// ───────────────────────────────────────────────────────────────────────────
// CT-T — Type distinction. Different scalar types must produce distinct
// κ-labels even when their textual rendering looks similar.
// ───────────────────────────────────────────────────────────────────────────

/// CT-T01 — `42` and `"42"` produce distinct κ-labels.
#[test]
fn ct_t01__integer_distinct_from_string_of_same_digits() {
    let int_addr = address(b"42").expect("valid").address;
    let str_addr = address(br#""42""#).expect("valid").address;
    assert_ne!(int_addr, str_addr);
}

/// CT-T02 — `null` and `false` produce distinct κ-labels.
#[test]
fn ct_t02__null_distinct_from_false() {
    let null_addr = address(b"null").expect("valid").address;
    let false_addr = address(b"false").expect("valid").address;
    assert_ne!(null_addr, false_addr);
}

/// CT-T03 — `true`, `false`, `null` are pairwise distinct.
#[test]
fn ct_t03__three_scalars_pairwise_distinct() {
    let t = address(b"true").expect("valid").address;
    let f = address(b"false").expect("valid").address;
    let n = address(b"null").expect("valid").address;
    assert_ne!(t, f);
    assert_ne!(t, n);
    assert_ne!(f, n);
}

/// CT-T04 — empty object and empty array are distinct.
#[test]
fn ct_t04__empty_object_distinct_from_empty_array() {
    let obj = address(b"{}").expect("valid").address;
    let arr = address(b"[]").expect("valid").address;
    assert_ne!(obj, arr);
}

/// CT-T05 — `[1,2,3]` (numbers) and `["1","2","3"]` (strings) distinct.
#[test]
fn ct_t05__number_array_distinct_from_string_array() {
    let nums = address(b"[1,2,3]").expect("valid").address;
    let strs = address(br#"["1","2","3"]"#).expect("valid").address;
    assert_ne!(nums, strs);
}

// ───────────────────────────────────────────────────────────────────────────
// CT-E — Structural equivalence. Inputs that differ only in syntactic
// noise (key order, whitespace, Unicode normalisation form) must
// collapse to one κ-label.
// ───────────────────────────────────────────────────────────────────────────

/// CT-E01 — key ordering invariance (re-statement of CD-I01a at the
/// typed-input layer).
#[test]
fn ct_e01__key_ordering_invariance() {
    let a = address(br#"{"alpha":1,"beta":2,"gamma":3}"#)
        .expect("valid")
        .address;
    let b = address(br#"{"gamma":3,"beta":2,"alpha":1}"#)
        .expect("valid")
        .address;
    assert_eq!(a, b);
}

/// CT-E02 — whitespace invariance (re-statement at the typed-input layer).
#[test]
fn ct_e02__whitespace_invariance() {
    let a = address(b"{ \"x\" : [ 1 , 2 , 3 ] }")
        .expect("valid")
        .address;
    let b = address(br#"{"x":[1,2,3]}"#).expect("valid").address;
    assert_eq!(a, b);
}

/// CT-E03 — Unicode-NFC invariance: composed `caf\u{00E9}` ≡ decomposed
/// `cafe\u{0301}`.
#[test]
fn ct_e03__nfc_invariance() {
    let composed = address("{\"x\":\"caf\u{00E9}\"}".as_bytes())
        .expect("valid")
        .address;
    let decomposed = address("{\"x\":\"cafe\u{0301}\"}".as_bytes())
        .expect("valid")
        .address;
    assert_eq!(composed, decomposed);
}

/// CT-E04 — nested key ordering invariance through depth 3.
#[test]
fn ct_e04__nested_key_ordering_invariance() {
    let a = br#"{"z":{"y":{"x":1,"w":2}},"a":1}"#;
    let b = br#"{"a":1,"z":{"y":{"w":2,"x":1}}}"#;
    let addr_a = address(a).expect("valid").address;
    let addr_b = address(b).expect("valid").address;
    assert_eq!(addr_a, addr_b);
}

/// CT-E05 — object members sort by the UTF-16 code units of their keys
/// (RFC 8785 §3.2.3), at any depth. Code-point order and UTF-16 order
/// differ only when the first differing characters of two sibling keys
/// are a U+E000..U+FFFF one and an astral-plane one; the astral key comes
/// first. Both input orders must canonicalize to the pinned bytes and
/// mint the pinned κ-label.
#[test]
fn ct_e05__members_sort_by_utf16_code_units() {
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            // U+FF11 (full-width one) vs U+1D400 (mathematical bold A).
            "{\"\u{FF11}\":1,\"\u{1D400}\":2}",
            "{\"\u{1D400}\":2,\"\u{FF11}\":1}",
            "{\"\u{1D400}\":2,\"\u{FF11}\":1}",
            "sha256:05c7d52a4d1707689b620f9672547238ad89696481cd125cf838266fb86a6c69",
        ),
        (
            // The same pair one level down.
            "{\"outer\":{\"\u{FF11}\":1,\"\u{1D400}\":2}}",
            "{\"outer\":{\"\u{1D400}\":2,\"\u{FF11}\":1}}",
            "{\"outer\":{\"\u{1D400}\":2,\"\u{FF11}\":1}}",
            "sha256:8c5a8c983233c60a5d2f078ecd92c1671b90b2f812285eb3e3b995a6b550b261",
        ),
        (
            // Keys that share a prefix and differ at the second character.
            "{\"k\u{FF11}\":1,\"k\u{1D400}\":2}",
            "{\"k\u{1D400}\":2,\"k\u{FF11}\":1}",
            "{\"k\u{1D400}\":2,\"k\u{FF11}\":1}",
            "sha256:4f7ab3d9f48fd71756926fbc88b18cf1bf38f9b1e9ab11c6abdb546ea0bac553",
        ),
        (
            // Below U+E000 both orders agree: "z" stays ahead of the astral key.
            "{\"\u{1D400}\":2,\"z\":1}",
            "{\"z\":1,\"\u{1D400}\":2}",
            "{\"z\":1,\"\u{1D400}\":2}",
            "sha256:3780b53953e06d45a69f63edb33fbdaea641f688fa31693107be5eeeda211d3e",
        ),
    ];
    for (one_order, other_order, canonical, label) in cases {
        for raw in [one_order, other_order] {
            assert_eq!(
                canonicalize(raw.as_bytes()).expect("valid"),
                canonical.as_bytes(),
                "canonical bytes for {raw}"
            );
            assert_eq!(
                &address(raw.as_bytes()).expect("valid").address[..],
                *label,
                "κ-label for {raw}"
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// CT-B — Bound-enforcement at construction. The typed-input parser
// rejects inputs that violate any AddrBounds typed-input ceiling.
// ───────────────────────────────────────────────────────────────────────────

/// CT-B01 — over-deep nesting is rejected at parse (the stack-safety
/// depth guard remains, surfacing as InvalidJson).
#[test]
fn ct_b01__over_deep_nesting_rejected_at_parse() {
    let mut s = String::new();
    for _ in 0..(MAX_JSON_DEPTH + 4) {
        s.push('[');
    }
    for _ in 0..(MAX_JSON_DEPTH + 4) {
        s.push(']');
    }
    let err = address(s.as_bytes()).expect_err("must reject");
    assert!(matches!(err, AddressFailure::InvalidJson));
}

/// CT-B02 — wide strings are admitted (ADR-060 removed the width cap).
#[test]
fn ct_b02__wide_string_admitted() {
    let big: String = "a".repeat(100_000);
    let raw = format!("\"{big}\"");
    assert!(address(raw.as_bytes()).is_ok());
}

/// CT-B03 — exactly-at-bound depth is accepted.
#[test]
fn ct_b03__exactly_at_depth_bound_accepted() {
    let mut s = String::new();
    for _ in 0..MAX_JSON_DEPTH {
        s.push('[');
    }
    s.push('1');
    for _ in 0..MAX_JSON_DEPTH {
        s.push(']');
    }
    let addr = address(s.as_bytes()).expect("at-bound depth must be accepted");
    assert_eq!(addr.address.len(), 71);
}

/// CT-B04 — invalid JSON syntax is rejected with InvalidJson (not TooLarge).
#[test]
fn ct_b04__invalid_json_rejected_distinct_from_size_bound() {
    let err = address(b"not json").expect_err("must reject");
    assert!(matches!(err, AddressFailure::InvalidJson));
}

/// CT-B05 — an object that repeats a member name is rejected with
/// InvalidJson, at any depth, including names that only become equal
/// after escape decoding or NFC normalization. The same name in sibling
/// objects is still admitted.
#[test]
fn ct_b05__duplicate_member_names_rejected() {
    let cases: &[(&str, &[u8])] = &[
        ("plain", br#"{"a":1,"a":2}"#),
        (
            "nfc_equivalent",
            "{\"caf\u{00E9}\":1,\"cafe\u{0301}\":2}".as_bytes(),
        ),
        ("escape_spelled", br#"{"a":1,"a":2}"#),
        ("nested", br#"{"outer":{"x":1,"x":2}}"#),
        ("nested_in_array", br#"[{"k":true},{"k":1,"k":2}]"#),
    ];
    for (name, raw) in cases {
        let err = address(raw).expect_err(name);
        assert!(
            matches!(err, AddressFailure::InvalidJson),
            "{name}: {err:?}"
        );
        let parse_err = JsonValue::parse(raw).expect_err(name);
        assert!(
            parse_err.constraint_iri.contains("validUtf8Json"),
            "{name}: {}",
            parse_err.constraint_iri
        );
    }

    // Repeating a name across different objects is not a duplicate.
    address(br#"{"x":{"a":1},"y":{"a":2}}"#).expect("sibling objects may share names");
    address(br#"[{"a":1},{"a":2}]"#).expect("array elements may share names");
}

// ───────────────────────────────────────────────────────────────────────────
// CT-C — Cost-model commitment. The PrismModel declares
// `EmptyCommitment` (ADR-048); the model's typed-iso surface carries no
// auxiliary cost dimension beyond the κ-derivation.
// ───────────────────────────────────────────────────────────────────────────

/// CT-C01 — `EmptyCommitment` is the declared cost-model commitment.
#[test]
fn ct_c01__cost_model_is_empty_commitment() {
    // Compile-time check: re-export reaches our public surface.
    let _: uor_addr::EmptyCommitment = Default::default();
}

// ───────────────────────────────────────────────────────────────────────────
// CT-P — Parse-side typed-input bound: the JsonValue parser surface.
// ───────────────────────────────────────────────────────────────────────────

/// CT-P01 — JsonValue::parse on a valid input returns Ok with
/// non-empty tagged bytes.
#[test]
fn ct_p01__parse_returns_tagged_bytes() {
    let v = JsonValue::parse(br#"{"k":42}"#).expect("valid");
    assert!(!v.tagged_bytes().is_empty());
}

/// CT-P02 — JsonValue::parse rejects invalid JSON.
#[test]
fn ct_p02__parse_rejects_invalid_json() {
    let err = JsonValue::parse(b"{").expect_err("invalid JSON must fail");
    assert!(err.constraint_iri.contains("validUtf8Json"));
}
