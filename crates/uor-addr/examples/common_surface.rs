//! `uor-addr` — Common architectural surface comprehensive example.
//!
//! Demonstrates the [`uor_addr::common::AddressInput`] trait — the
//! shared trait every format-specific UOR-ADDR realization
//! implements. Walks parsing through the trait, canonicalize-into,
//! registry inspection per ADR-057, and cross-realization
//! polymorphism.
//!
//! Run with `cargo run -p uor-addr --example common_surface`.

use prism::pipeline::{IntoBindingValue, ShapeRegistryProvider};
use uor_addr::common::AddressInput;

fn show_realization<V: AddressInput>(name: &str, raw: &[u8]) {
    println!("─── {name} ─────────────────────────────────────");

    // 1. parse via the trait
    let v = <V as AddressInput>::parse(raw).expect("valid input");

    // 2. binding-table form (the ψ-pipeline's input encoding)
    let mut tagged = alloc::vec![0u8; <V as IntoBindingValue>::MAX_BYTES];
    let n = v.into_binding_bytes(&mut tagged).expect("fits");
    println!("   tagged byte count:    {n}");

    // 3. canonicalize via the trait
    let mut canonical = alloc::vec![0u8; <V as IntoBindingValue>::MAX_BYTES];
    let m =
        <V as AddressInput>::canonicalize_into(&tagged[..n], &mut canonical).expect("canonicalize");
    println!("   canonical byte count: {m}");

    // 4. registry inspection (ADR-057)
    let entries = <<V as AddressInput>::Registry as ShapeRegistryProvider>::REGISTRY;
    println!(
        "   ADR-057 registry:     {} entries; first IRI = {}",
        entries.len(),
        entries.first().map(|e| e.iri).unwrap_or("<empty>")
    );

    println!();
}

extern crate alloc;

fn main() {
    println!("uor-addr — common architectural surface (AddressInput trait)\n");

    println!("The AddressInput trait every realization implements:\n");
    println!("    pub trait AddressInput:");
    println!("        ConstrainedTypeShape + IntoBindingValue + Sized");
    println!("    {{");
    println!("        type Registry: ShapeRegistryProvider;");
    println!("        fn canonicalize_into(parser_emitted: &[u8], out: &mut [u8])");
    println!("            -> Result<usize, ShapeViolation>;");
    println!("        fn parse(input: &[u8]) -> Result<Self, ShapeViolation>;");
    println!("    }}\n");

    // Walk every format-specific realization through the trait.
    show_realization::<uor_addr::json::JsonValue>("json::JsonValue", br#"{"x":1}"#);
    show_realization::<uor_addr::sexp::SExprValue>("sexp::SExprValue", b"(a b c)");
    show_realization::<uor_addr::xml::XmlValue>("xml::XmlValue", b"<root/>");
    show_realization::<uor_addr::asn1::Asn1Value>("asn1::Asn1Value", &[0x02, 0x01, 0x2A]);
    show_realization::<uor_addr::ring::RingElement>("ring::RingElement", &[0u8, 0x42]);
    let m = uor_addr::codemodule::CodeModuleValue::module("demo", &[])
        .expect("valid")
        .tagged_bytes()
        .to_vec();
    show_realization::<uor_addr::codemodule::CodeModuleValue>("codemodule::CodeModuleValue", &m);

    println!("OK — every realization implements `AddressInput` and exposes its ADR-057 registry.");
}
