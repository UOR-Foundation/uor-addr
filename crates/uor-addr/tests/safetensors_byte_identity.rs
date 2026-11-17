//! CL-SAFETENSORS byte-identity: the Rust realization's κ-label matches the
//! spec-attested label committed alongside each fixture.
//!
//! Each `.kappa-label` is produced by `tools/canonical-safetensors.py`, which
//! decodes the header with Python's standard `json` module rather than the
//! Rust reader, and committed by `tools/synth-fixtures.py`.

#![cfg(feature = "safetensors")]

fn check(input: &[u8], expected_label: &str) {
    let outcome = uor_addr::safetensors::address(input).expect("valid safetensors fixture");
    assert_eq!(
        outcome.address.as_str(),
        expected_label.trim(),
        "Rust κ-label must equal the tools/canonical-safetensors.py attested label"
    );
}

#[test]
fn mixed_dtypes_matches_python_attestation() {
    check(
        include_bytes!("fixtures/safetensors/mixed-dtypes.safetensors"),
        include_str!("fixtures/safetensors/mixed-dtypes.kappa-label"),
    );
}

#[test]
fn empty_matches_python_attestation() {
    check(
        include_bytes!("fixtures/safetensors/empty.safetensors"),
        include_str!("fixtures/safetensors/empty.kappa-label"),
    );
}

#[test]
fn zero_sized_matches_python_attestation() {
    check(
        include_bytes!("fixtures/safetensors/zero-sized.safetensors"),
        include_str!("fixtures/safetensors/zero-sized.kappa-label"),
    );
}
