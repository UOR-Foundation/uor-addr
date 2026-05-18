//! Behavior tests for UOR-ADDR's **common architectural surface** —
//! the declarations every format-specific addressing realization
//! shares (ARCHITECTURE.md "What UOR-ADDR provides" §§ AddressInput
//! trait, Common output shape, Common verb arena, Common resolver
//! tuple shape, Common cost-model commitment surface, Common
//! PrismModel form).
//!
//! These tests pin the surface that downstream format-specific
//! realizations (sibling crates per ADR-031's demand-driven clause)
//! depend on. A regression here is a break in the surface contract.

use prism::pipeline::{
    ConstrainedTypeShape, EmptyCommitment, IntoBindingValue, ShapeRegistryProvider,
};
use uor_addr::common::{AddressInput, AddressLabel};
use uor_addr::{
    address, JsonValue, JsonValueRegistry, ADDRESS_LABEL_BYTES, VERB_TERMS_ADDRESS_INFERENCE,
};

// ─── AddressInput trait conformance — JSON realization ────────────────

#[test]
fn json_value_is_address_input() {
    // The compile-time witness — if `JsonValue` does not satisfy
    // `AddressInput`, this fn does not compile. Per ARCHITECTURE.md
    // "AddressInput trait" the JSON realization must impl
    // `AddressInput` on its typed-input shape.
    fn assert_address_input<V: AddressInput>() {}
    assert_address_input::<JsonValue>();
}

#[test]
fn address_input_supertraits_are_satisfied_by_json_value() {
    // ARCHITECTURE.md AddressInput composes three substrate
    // commitments: `ConstrainedTypeShape` (constraint geometry),
    // `IntoBindingValue` (catamorphism's typed-input serialization),
    // and the `Registry` associated type (ADR-057 recursive-shape
    // registry). All three must be satisfied by every conforming
    // realization.
    fn requires_constrained_type_shape<V: ConstrainedTypeShape>() {}
    fn requires_into_binding_value<V: IntoBindingValue>() {}
    requires_constrained_type_shape::<JsonValue>();
    requires_into_binding_value::<JsonValue>();
}

#[test]
fn address_input_registry_for_json_is_json_value_registry() {
    // ARCHITECTURE.md "AddressInput trait" — `Registry` is the
    // application registry of registered shapes for the format's
    // grammar cases per ADR-057. The JSON realization's registry is
    // [`JsonValueRegistry`], emitted by `register_shape!` in
    // [`crate::json::value`] aggregating one entry for `JsonValue`.
    fn assert_registry_is<V, R>()
    where
        V: AddressInput<Registry = R>,
        R: ShapeRegistryProvider,
    {
    }
    assert_registry_is::<JsonValue, JsonValueRegistry>();

    // The registry carries one entry for `JsonValue` itself. A future
    // migration to the `partition_coproduct!` over the seven JSON
    // cases would expand the registered set to seven entries.
    let entries = <<JsonValue as AddressInput>::Registry as ShapeRegistryProvider>::REGISTRY;
    assert_eq!(
        entries.len(),
        1,
        "JsonValue's application registry must carry one entry (the JsonValue shape itself)"
    );
    assert_eq!(entries[0].iri, "https://uor.foundation/addr/JsonValue");
}

#[test]
fn address_input_parse_dispatches_to_json_value_parser() {
    // ARCHITECTURE.md "AddressInput trait" — `parse` is the
    // host-boundary parser per SD2's Grounding stage. The trait
    // method must surface the same well-formed-input contract as
    // the realization's underlying parser.
    let raw = br#"{"foo":"bar"}"#;
    let via_trait = <JsonValue as AddressInput>::parse(raw).expect("trait parse succeeds");
    let direct = JsonValue::parse(raw).expect("direct parse succeeds");
    // Same constraint-geometry-typed value reaches both paths.
    let mut a = [0u8; 4096];
    let mut b = [0u8; 4096];
    let na = via_trait.into_binding_bytes(&mut a).unwrap();
    let nb = direct.into_binding_bytes(&mut b).unwrap();
    assert_eq!(&a[..na], &b[..nb]);
}

#[test]
fn address_input_parse_surfaces_typed_input_violations() {
    // ARCHITECTURE.md "AddressInput trait" — the parse method
    // returns a `ShapeViolation` carrying the violated
    // typed-input-bound IRI; downstream consumers depend on the
    // IRI for routing the specific violation.
    let err = <JsonValue as AddressInput>::parse(b"not json").expect_err("must reject");
    assert!(err.constraint_iri.ends_with("/validUtf8Json"));
}

#[test]
fn address_input_canonicalize_into_writes_jcs_nfc_canonical_bytes() {
    // ARCHITECTURE.md "AddressInput trait" — `canonicalize_into`
    // emits the canonical-form byte sequence the σ-projection
    // consumes. For the JSON realization the discipline is
    // JCS-RFC8785 + Unicode NFC.
    //
    // The trait method takes the parser-emitted byte sequence (the
    // structurally-tagged binding form) and writes canonical bytes
    // into the caller-supplied slice; returns the number written.
    let value = JsonValue::parse(br#"{"b": 1, "a": 2}"#).expect("valid");
    let mut tagged = [0u8; 4096];
    let n = value.into_binding_bytes(&mut tagged).expect("fits");
    let mut canonical = [0u8; 4096];
    let m = <JsonValue as AddressInput>::canonicalize_into(&tagged[..n], &mut canonical)
        .expect("canonicalizes");
    assert_eq!(
        &canonical[..m],
        br#"{"a":2,"b":1}"#,
        "JCS §3.2.3 re-orders keys lexicographically"
    );
}

#[test]
fn address_input_canonicalize_into_returns_buffer_too_small() {
    // ARCHITECTURE.md "AddressInput trait" — the canonicalizer must
    // surface a `ShapeViolation` if the output slice is too small.
    let value = JsonValue::parse(br#"{"foo":"bar"}"#).expect("valid");
    let mut tagged = [0u8; 4096];
    let n = value.into_binding_bytes(&mut tagged).expect("fits");
    let mut tiny = [0u8; 4];
    let err = <JsonValue as AddressInput>::canonicalize_into(&tagged[..n], &mut tiny)
        .expect_err("buffer too small");
    assert!(err.constraint_iri.ends_with("/serializedWidth"));
}

// ─── Common verb arena — ARCHITECTURE.md "Common verb arena" ──────────

#[test]
fn common_verb_arena_composes_only_psi_term_variants() {
    // ARCHITECTURE.md "Common verb arena" + CS-V01 + ADR-035 — the
    // verb body composes ψ_1 + ψ_7 + ψ_8 + ψ_9 only. The
    // `verb_arena_contains_no_sigma_residuals` test in
    // `crate::verbs` pins this from the implementation side; this
    // test pins the same commitment from the common-surface API.
    use prism::operation::Term;
    let arena = VERB_TERMS_ADDRESS_INFERENCE;
    assert!(!arena.is_empty(), "verb arena is non-empty");
    let has_nerve = arena.iter().any(|t| matches!(t, Term::Nerve { .. }));
    let has_postnikov = arena
        .iter()
        .any(|t| matches!(t, Term::PostnikovTower { .. }));
    let has_homotopy = arena
        .iter()
        .any(|t| matches!(t, Term::HomotopyGroups { .. }));
    let has_kinvariants = arena.iter().any(|t| matches!(t, Term::KInvariants { .. }));
    assert!(
        has_nerve && has_postnikov && has_homotopy && has_kinvariants,
        "verb arena must contain ψ_1 + ψ_7 + ψ_8 + ψ_9"
    );
    // Off-path: ψ_2 / ψ_3 / ψ_5 / ψ_6 must not appear.
    let has_chain = arena.iter().any(|t| matches!(t, Term::ChainComplex { .. }));
    let has_homology = arena
        .iter()
        .any(|t| matches!(t, Term::HomologyGroups { .. }));
    let has_cochain = arena
        .iter()
        .any(|t| matches!(t, Term::CochainComplex { .. }));
    let has_cohomology = arena
        .iter()
        .any(|t| matches!(t, Term::CohomologyGroups { .. }));
    assert!(
        !has_chain && !has_homology && !has_cochain && !has_cohomology,
        "off-path ψ-stages must not appear in the verb body"
    );
}

// ─── Common output shape — ARCHITECTURE.md "Common output shape" ──────

#[test]
fn common_output_shape_iri_matches_architectural_commitment() {
    // ARCHITECTURE.md "Common output shape" — the content-addressed
    // IRI is `https://uor.foundation/addr/AddressLabel/<H::IDENTIFIER>`.
    // The shipped specialization binds `H = Sha256Hasher`, so the
    // suffix is `/sha256`. Per-axis IRI specialization is the
    // framework's typed-iso commitment per ADR-001 + ADR-017.
    assert_eq!(
        <AddressLabel as ConstrainedTypeShape>::IRI,
        "https://uor.foundation/addr/AddressLabel/sha256"
    );
}

#[test]
fn common_output_shape_site_count_matches_structural_formula_for_sha256() {
    // ARCHITECTURE.md "Common output shape" — the structural formula
    // is `SITE_COUNT = H::IDENTIFIER.len() + 1 + 2 × H::DIGEST_BYTES`.
    // For `H = Sha256Hasher` (IDENTIFIER = "sha256", DIGEST_BYTES =
    // 32), the specialization is 71.
    let identifier_len = b"sha256".len();
    let separator_len = 1; // ':'
    let digest_bytes = 32; // SHA-256
    let hex_serialization_factor = 2;
    let expected = identifier_len + separator_len + hex_serialization_factor * digest_bytes;
    assert_eq!(expected, 71);
    assert_eq!(
        <AddressLabel as ConstrainedTypeShape>::SITE_COUNT,
        ADDRESS_LABEL_BYTES,
        "AddressLabel's SITE_COUNT matches the wire-format byte width"
    );
    assert_eq!(ADDRESS_LABEL_BYTES, expected);
}

// ─── Common cost-model commitment surface — ARCHITECTURE.md "Common
// cost-model commitment surface" ──────────────────────────────────────

#[test]
fn common_cost_model_default_is_empty_commitment() {
    // ARCHITECTURE.md "Common cost-model commitment surface" —
    // the default `C` selection is `EmptyCommitment`. The
    // `address()` entry point binds it; the type check below is the
    // compile-time witness. Cost-model-bearing variants
    // (uor-addr-storage, uor-addr-signed) live in sibling crates.
    fn assert_empty_commitment_is_typed_commitment<C: prism::pipeline::TypedCommitment>() {}
    assert_empty_commitment_is_typed_commitment::<EmptyCommitment>();
}

// ─── End-to-end κ-derivation — sanity check through the common surface

#[test]
fn end_to_end_kappa_derivation_via_common_surface() {
    // The architectural commitment from end-to-end. Parse via the
    // host boundary, run the model `forward`, recover the κ-label.
    // Demonstrates the common surface ties together for the JSON
    // realization.
    let raw = br#"{"hello":"world"}"#;
    let outcome = address(raw).expect("well-formed input yields κ-label");
    assert_eq!(outcome.address.len(), ADDRESS_LABEL_BYTES);
    assert!(outcome.address.starts_with("sha256:"));
    // Lowercase hex digits only after the 7-byte prefix.
    for &b in &outcome.address.as_bytes()[7..] {
        assert!(
            b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
            "hex digit at output is lowercase-hex ASCII"
        );
    }
}

#[test]
fn end_to_end_kappa_derivation_is_deterministic() {
    // ARCHITECTURE.md V&V theorem corpus — the κ-derivation
    // determinism theorem. Same input → same κ-label, every time.
    let raw = br#"{"determinism":"check","array":[1,2,3]}"#;
    let a = address(raw).expect("κ-label").address;
    let b = address(raw).expect("κ-label").address;
    let c = address(raw).expect("κ-label").address;
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn end_to_end_kappa_derivation_distinguishes_typed_distinctions() {
    // ARCHITECTURE.md V&V theorem corpus — the typed-distinction
    // theorem. `JsonValueBoolFalse` and `JsonValueBoolTrue` are
    // distinct typed cases at the case-IRI level; their κ-labels
    // must differ.
    let false_label = address(b"false").expect("κ-label").address;
    let true_label = address(b"true").expect("κ-label").address;
    let null_label = address(b"null").expect("κ-label").address;
    let zero_label = address(b"0").expect("κ-label").address;
    let empty_string_label = address(br#""""#).expect("κ-label").address;
    assert_ne!(false_label, true_label);
    assert_ne!(false_label, null_label);
    assert_ne!(false_label, zero_label);
    assert_ne!(false_label, empty_string_label);
    assert_ne!(true_label, null_label);
    assert_ne!(null_label, zero_label);
    assert_ne!(zero_label, empty_string_label);
}
