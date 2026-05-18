//! `uor-addr` — Code-module AST realization comprehensive example.
//!
//! Demonstrates [`uor_addr::codemodule::address`] over the
//! Canonical Code-Module AST Serialization (CCMAS) grammar:
//! Module, Function, Type/Const, atom literals/identifiers. Shows
//! basic minting, determinism, structural typed-distinction, and
//! CCMAS-as-Rivest-canonical-S-expression-subset.
//!
//! Run with `cargo run -p uor-addr --example codemodule_realization`.

use uor_addr::codemodule::{address, AddressFailure, CodeModuleValue};

fn main() {
    println!("uor-addr — code-module AST realization (CCMAS)\n");

    // 1. Empty module.
    let empty_mod = CodeModuleValue::module("empty", &[]).expect("valid");
    let outcome = address(empty_mod.tagged_bytes()).expect("κ-label");
    println!("1. Empty Module");
    println!(
        "   surface:  {}",
        core::str::from_utf8(empty_mod.tagged_bytes()).unwrap_or("<binary>")
    );
    println!("   κ-label:  {}\n", outcome.address);

    // 2. Module with a function and atom literals.
    let body = CodeModuleValue::atom("42").expect("valid");
    let ret_ty = CodeModuleValue::atom("u32").expect("valid");
    let f = CodeModuleValue::function("greet", &[], &ret_ty, &body).expect("valid");
    let m = CodeModuleValue::module("demo", &[f]).expect("valid");
    let outcome = address(m.tagged_bytes()).expect("κ-label");
    println!("2. Module with Function");
    println!(
        "   surface:  {}",
        core::str::from_utf8(m.tagged_bytes()).unwrap_or("<binary>")
    );
    println!("   κ-label:  {}\n", outcome.address);

    // 3. Determinism.
    let a = address(m.tagged_bytes()).expect("κ-label").address;
    let b = address(m.tagged_bytes()).expect("κ-label").address;
    assert_eq!(a, b);
    println!("3. Determinism");
    println!("   run 1: {a}");
    println!("   run 2: {b}");
    println!("   match: {} ✓\n", a == b);

    // 4. CCMAS-as-Rivest-S-expression-subset: the κ-label produced
    //    by the codemodule realization differs from the sexp
    //    realization's κ-label for the same canonical bytes,
    //    because the typed-input IRI differs (CodeModuleValue vs
    //    SExprValue) and the AddressInput trait disambiguates
    //    canonicalization-output by V::IRI.
    //
    //    However, the surface canonical bytes ARE valid Rivest
    //    canonical S-expressions and a Rivest canonicalize round-
    //    trip is the identity on them — the underlying byte layer
    //    is shared.
    let rivest_round_trip = uor_addr::sexp::canonicalize(m.tagged_bytes()).expect("valid sexp");
    assert_eq!(rivest_round_trip, m.tagged_bytes());
    println!("4. CCMAS bytes are Rivest canonical S-expressions");
    println!("   sexp::canonicalize(codemodule bytes) == codemodule bytes ✓\n");

    // 5. Typed distinction — different AST shapes yield different κ-labels.
    let m0 = CodeModuleValue::module("a", &[]).expect("valid");
    let m1 = CodeModuleValue::module("b", &[]).expect("valid");
    let atom_a = CodeModuleValue::atom("a").expect("valid");
    let l0 = address(m0.tagged_bytes()).expect("κ-label").address;
    let l1 = address(m1.tagged_bytes()).expect("κ-label").address;
    let la = address(atom_a.tagged_bytes()).expect("κ-label").address;
    assert_ne!(l0, l1);
    assert_ne!(l0, la);
    assert_ne!(l1, la);
    println!("5. Typed distinction");
    println!("   Module \"a\":           {l0}");
    println!("   Module \"b\":           {l1}");
    println!("   Atom \"a\":             {la}");
    println!();

    // 6. Failure modes.
    println!("6. Failure modes");
    match address(b"not ccmas") {
        Err(AddressFailure::InvalidCcmas) => println!("   non-CCMAS input rejected ✓"),
        other => panic!("expected InvalidCcmas: {other:?}"),
    }
    // Oversize name should fail at atom construction.
    let too_long = "a".repeat(uor_addr::codemodule::MAX_CODEMODULE_NAME_BYTES + 1);
    match CodeModuleValue::atom(&too_long) {
        Err(v) if v.constraint_iri.ends_with("/nameWidth") => {
            println!("   oversize-name rejected via nameWidth ✓");
        }
        other => panic!("expected nameWidth: {other:?}"),
    }

    println!("\nOK — CCMAS realization shipped; Rivest-canonical byte layer shared.");
}
