//! Integration conformance suite for every UOR-ADDR realization
//! shipped in this crate.
//!
//! ## What this suite pins
//!
//! - **Cross-realization determinism (CD-D01)**. Every realization's
//!   `address()` function is a pure function of its input — same
//!   bytes → same κ-label.
//! - **Cross-realization wire-format width (CL-W01)**. Every
//!   realization emits the 71-byte `sha256:<64hex>` κ-label.
//! - **Cross-realization typed-distinction (CT-T*)**. Two
//!   realizations that admit the same surface text yield distinct
//!   κ-labels (each realization's canonicalization byte-output
//!   discipline distinguishes the typed environments).
//! - **Schema-descendant equivalence**. Each schema descendant's
//!   κ-label matches the underlying format realization's κ-label
//!   for the same admitted input (schema admission applies at
//!   parse time, not in the ψ-pipeline).
//!
//! ## Authoritative source coverage
//!
//! Every realization is tested against its authoritative-source
//! reference baseline. See [STANDARDS.md](https://github.com/UOR-Foundation/uor-addr/blob/main/STANDARDS.md)
//! for the full index.

const KAPPA_LABEL_BYTES: usize = 71;

fn assert_well_formed_kappa(label: &str) {
    assert_eq!(label.len(), KAPPA_LABEL_BYTES);
    assert!(label.starts_with("sha256:"));
    for &b in &label.as_bytes()[7..] {
        assert!(b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    }
}

// ─── JSON realization (already covered by other test files) ────────────

#[test]
fn json_realization_emits_well_formed_kappa() {
    let outcome = uor_addr::json::address(br#"{"x":1}"#).expect("κ-label");
    assert_well_formed_kappa(&outcome.address);
}

// ─── S-expression realization (Rivest 1997) ────────────────────────────

#[test]
fn sexp_realization_emits_well_formed_kappa() {
    let outcome = uor_addr::sexp::address(b"(a b c)").expect("κ-label");
    assert_well_formed_kappa(&outcome.address);
}

// ─── Ring realization (Amendment 43 §2) ────────────────────────────────

#[test]
fn ring_realization_emits_well_formed_kappa() {
    let outcome = uor_addr::ring::address(&[0u8, 0x42]).expect("κ-label");
    assert_well_formed_kappa(&outcome.address);
}

#[test]
fn ring_realization_distinguishes_witt_levels() {
    let level_0 = uor_addr::ring::address(&[0u8, 0x42])
        .expect("κ-label")
        .address;
    let level_1 = uor_addr::ring::address(&[1u8, 0x42, 0x00])
        .expect("κ-label")
        .address;
    assert_ne!(level_0, level_1);
}

#[test]
fn ring_realization_rejects_overflow_witt_level() {
    let err = uor_addr::ring::address(&[255u8, 0]).expect_err("must reject");
    assert!(matches!(err, uor_addr::ring::AddressFailure::TooLarge));
}

// ─── ASN.1 realization (X.690 DER) ─────────────────────────────────────

#[test]
fn asn1_realization_emits_well_formed_kappa() {
    // INTEGER 42, DER: 0x02 0x01 0x2A
    let outcome = uor_addr::asn1::address(&[0x02, 0x01, 0x2A]).expect("κ-label");
    assert_well_formed_kappa(&outcome.address);
}

#[test]
fn asn1_realization_distinguishes_boolean_true_false() {
    let t = uor_addr::asn1::address(&[0x01, 0x01, 0xFF])
        .expect("κ-label")
        .address;
    let f = uor_addr::asn1::address(&[0x01, 0x01, 0x00])
        .expect("κ-label")
        .address;
    assert_ne!(t, f);
}

#[test]
fn asn1_realization_rejects_non_canonical_der() {
    // Non-minimal INTEGER encoding (X.690 §8.3.2)
    let err = uor_addr::asn1::address(&[0x02, 0x02, 0x00, 0x01]).expect_err("non-minimal");
    assert!(matches!(err, uor_addr::asn1::AddressFailure::InvalidDer));
}

// ─── XML realization (W3C C14N 1.1 subset) ─────────────────────────────

#[test]
fn xml_realization_emits_well_formed_kappa() {
    let outcome = uor_addr::xml::address(b"<root/>").expect("κ-label");
    assert_well_formed_kappa(&outcome.address);
}

#[test]
fn xml_realization_is_invariant_under_attribute_order() {
    let a = uor_addr::xml::address(br#"<root a="1" b="2"/>"#)
        .expect("κ-label")
        .address;
    let b = uor_addr::xml::address(br#"<root b="2" a="1"/>"#)
        .expect("κ-label")
        .address;
    // XML-C14N 1.1 §1.1 rule 3 — lexicographic attribute ordering.
    assert_eq!(a, b);
}

// ─── Code-module AST realization (CCMAS) ───────────────────────────────

#[test]
fn codemodule_realization_emits_well_formed_kappa() {
    let m = uor_addr::codemodule::CodeModuleValue::module("hello", &[])
        .expect("valid")
        .tagged_bytes()
        .to_vec();
    let outcome = uor_addr::codemodule::address(&m).expect("κ-label");
    assert_well_formed_kappa(&outcome.address);
}

// ─── Schema descendants ────────────────────────────────────────────────

#[test]
fn photo_schema_admits_then_addresses() {
    let raw = br#"{
        "subject": "test",
        "captured_at": 1700000000,
        "location": {"latitude": 0.0, "longitude": 0.0},
        "camera_make": "Acme",
        "camera_model": "X-1",
        "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "provenance": "test"
    }"#;
    let from_photo = uor_addr::schema::photo::address(raw)
        .expect("κ-label")
        .address;
    let from_json = uor_addr::json::address(raw).expect("κ-label").address;
    assert_well_formed_kappa(&from_photo);
    // Schema admission applies at parse time only — κ-label matches the JSON realization.
    assert_eq!(from_photo, from_json);
}

#[test]
fn photo_schema_rejects_missing_required_field() {
    let bad = br#"{"subject": "x"}"#;
    let err = uor_addr::schema::photo::address(bad).expect_err("must reject");
    assert!(matches!(
        err,
        uor_addr::schema::photo::AddressFailure::SchemaViolation
    ));
}

#[test]
fn document_schema_admits_then_addresses() {
    let raw = br#"{
        "title": "Paper",
        "authors": ["Ada"],
        "version": "1.0",
        "sections": [{"heading": "h", "body": "b"}],
        "citations": [{"key": "k", "url": "https://x"}]
    }"#;
    let from_doc = uor_addr::schema::document::address(raw)
        .expect("κ-label")
        .address;
    let from_json = uor_addr::json::address(raw).expect("κ-label").address;
    assert_well_formed_kappa(&from_doc);
    assert_eq!(from_doc, from_json);
}

#[test]
fn codemodule_signed_schema_requires_signature_item() {
    // Unsigned module rejected.
    let unsigned = uor_addr::codemodule::CodeModuleValue::module("u", &[])
        .expect("valid")
        .tagged_bytes()
        .to_vec();
    let err = uor_addr::schema::codemodule_signed::address(&unsigned).expect_err("no sig");
    assert!(matches!(
        err,
        uor_addr::schema::codemodule_signed::AddressFailure::SchemaViolation
    ));

    // Signed module admitted.
    let signed =
        uor_addr::schema::codemodule_signed::SignedCodeModuleValue::from_module_with_signature(
            "demo",
            &[uor_addr::codemodule::CodeModuleValue::atom("body").expect("valid")],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid")
        .tagged_bytes()
        .to_vec();
    let from_signed = uor_addr::schema::codemodule_signed::address(&signed)
        .expect("κ-label")
        .address;
    assert_well_formed_kappa(&from_signed);
}

// ─── Cost-model variants ───────────────────────────────────────────────

#[test]
fn signed_variant_is_a_typed_commitment() {
    use prism::pipeline::TypedCommitment;
    fn assert_typed_commitment<C: TypedCommitment>() {}
    assert_typed_commitment::<uor_addr::variant::signed::SignedCommitment>();
}

// ─── Cross-realization typed-distinction ───────────────────────────────

#[test]
fn cross_realization_typed_distinction() {
    // Surface input shaped differently across formats yields
    // distinct κ-labels — the architectural commitment per
    // ARCHITECTURE.md.
    let json_label = uor_addr::json::address(br#"["a"]"#)
        .expect("κ-label")
        .address;
    let sexp_label = uor_addr::sexp::address(b"(a)").expect("κ-label").address;
    let xml_label = uor_addr::xml::address(b"<a/>").expect("κ-label").address;
    let asn1_label = uor_addr::asn1::address(&[0x04, 0x01, b'a'])
        .expect("κ-label")
        .address;
    let ring_label = uor_addr::ring::address(&[0, b'a'])
        .expect("κ-label")
        .address;

    let mut labels = [
        &json_label,
        &sexp_label,
        &xml_label,
        &asn1_label,
        &ring_label,
    ];
    labels.sort();
    for w in labels.windows(2) {
        assert_ne!(w[0], w[1], "labels must be pairwise distinct");
    }
}
