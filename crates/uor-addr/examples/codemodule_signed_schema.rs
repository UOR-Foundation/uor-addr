//! `uor-addr` — Signed code-module schema descendant comprehensive
//! example.
//!
//! Demonstrates
//! [`uor_addr::schema::codemodule_signed::address`] — the
//! schema-pinned descendant of the code-module AST realization
//! requiring a `(3:sig <64-hex>)` signature sub-form. Walks
//! construction, admission, rejection, and κ-label equivalence
//! with the underlying CCMAS realization.
//!
//! Run with `cargo run -p uor-addr --example codemodule_signed_schema`.

use uor_addr::codemodule::CodeModuleValue;
use uor_addr::schema::codemodule_signed::{
    address, AddressFailure, SignedCodeModuleValue, SIGNATURE_HEX_BYTES, SIGNATURE_TAG,
};

fn main() {
    println!("uor-addr — Signed code-module schema descendant (over uor_addr::codemodule)\n");

    println!("1. Schema constants");
    println!("   signature tag head:        \"{}\"", SIGNATURE_TAG);
    println!("   signature payload width:   {SIGNATURE_HEX_BYTES} hex chars (32-byte digest)\n");

    // 2. Build a signed module.
    let body = CodeModuleValue::atom("body").expect("valid");
    let ret_ty = CodeModuleValue::atom("u32").expect("valid");
    let f = CodeModuleValue::function("compute", &[], &ret_ty, &body).expect("valid");
    let sig_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let signed = SignedCodeModuleValue::from_module_with_signature(
        "demo",
        core::slice::from_ref(&f),
        sig_hex,
    )
    .expect("valid signed module");
    let outcome = address(signed.tagged_bytes()).expect("κ-label");
    println!("2. Build + admit a signed module");
    println!(
        "   tagged bytes:  {}",
        core::str::from_utf8(signed.tagged_bytes()).unwrap_or("<binary>")
    );
    println!("   κ-label:       {}\n", outcome.address);

    // 3. κ-label equivalence with the underlying codemodule realization.
    let from_codemodule = uor_addr::codemodule::address(signed.tagged_bytes())
        .expect("κ-label")
        .address;
    assert_eq!(outcome.address, from_codemodule);
    println!("3. κ-label matches the codemodule realization");
    println!("   (schema admission applies at parse time)");
    println!("   match: {} ✓\n", outcome.address == from_codemodule);

    // 4. Two signed modules with different signatures get distinct κ-labels.
    let alt_sig = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let signed_alt =
        SignedCodeModuleValue::from_module_with_signature("demo", &[f], alt_sig).expect("valid");
    let alt_addr = address(signed_alt.tagged_bytes()).expect("κ-label").address;
    assert_ne!(outcome.address, alt_addr);
    println!("4. Different signatures yield distinct κ-labels");
    println!("   sig 1: {}", &sig_hex[..16]);
    println!("   κ-label: {}", outcome.address);
    println!("   sig 2: {}", &alt_sig[..16]);
    println!("   κ-label: {}\n", alt_addr);

    // 5. Rejection cases.
    println!("5. Schema-violation rejections");
    // 5a. Unsigned module.
    let unsigned = CodeModuleValue::module("u", &[]).expect("valid");
    match address(unsigned.tagged_bytes()) {
        Err(AddressFailure::SchemaViolation) => println!("   module without signature rejected ✓"),
        other => panic!("expected SchemaViolation: {other:?}"),
    }
    // 5b. Wrong-length signature.
    match SignedCodeModuleValue::from_module_with_signature("m", &[], "shorthex") {
        Err(v) if v.constraint_iri.ends_with("/schemaConformance") => {
            println!("   wrong-length signature rejected ✓");
        }
        other => panic!("expected schemaConformance: {other:?}"),
    }
    // 5c. Non-hex signature.
    match SignedCodeModuleValue::from_module_with_signature(
        "m",
        &[],
        "ZZZ_not_hex_ZZZ_not_hex_ZZZ_not_hex_ZZZ_not_hex_ZZZ_not_hex_ZZZ_",
    ) {
        Err(v) if v.constraint_iri.ends_with("/schemaConformance") => {
            println!("   non-hex signature rejected ✓");
        }
        other => panic!("expected schemaConformance: {other:?}"),
    }

    println!("\nOK — signed-code-module schema admits sig sub-form, rejects malformed signatures.");
}
