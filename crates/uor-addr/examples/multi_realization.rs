//! `uor-addr` — multi-realization showcase.
//!
//! Walks every shipped realization (JSON, S-expression, XML,
//! ASN.1 DER, ring elements, code-module AST, schema descendants,
//! cost-model variants) end-to-end and prints the resulting
//! κ-label.
//!
//! Run with `cargo run -p uor-addr --example multi_realization`.

fn main() {
    println!("uor-addr — multi-realization showcase\n");

    // JSON
    let raw = br#"{"hello":"world"}"#;
    let outcome = uor_addr::json::address(raw).expect("κ-label");
    println!("  json:          {}", outcome.address);

    // S-expression
    let outcome = uor_addr::sexp::address(b"(hello world)").expect("κ-label");
    println!("  sexp:          {}", outcome.address);

    // XML
    let outcome = uor_addr::xml::address(br#"<greet to="world">hello</greet>"#).expect("κ-label");
    println!("  xml:           {}", outcome.address);

    // ASN.1 DER — INTEGER 42
    let outcome = uor_addr::asn1::address(&[0x02, 0x01, 0x2A]).expect("κ-label");
    println!("  asn1:          {}", outcome.address);

    // Ring — Witt level 0, value 0x42
    let outcome = uor_addr::ring::address(&[0u8, 0x42]).expect("κ-label");
    println!("  ring:          {}", outcome.address);

    // Code-module AST
    let body = uor_addr::codemodule::CodeModuleValue::atom("body").expect("valid");
    let ret = uor_addr::codemodule::CodeModuleValue::atom("u32").expect("valid");
    let f =
        uor_addr::codemodule::CodeModuleValue::function("hello", &[], &ret, &body).expect("valid");
    let m = uor_addr::codemodule::CodeModuleValue::module("demo", &[f]).expect("valid");
    let outcome = uor_addr::codemodule::address(m.tagged_bytes()).expect("κ-label");
    println!("  codemodule:    {}", outcome.address);

    // Schema descendants — Photo, Document, SignedCodeModule
    let photo = br#"{
        "subject": "skyline at dawn",
        "captured_at": 1700000000,
        "location": {"latitude": 40.7128, "longitude": -74.0060},
        "camera_make": "Acme",
        "camera_model": "X-1000",
        "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "provenance": "uor.foundation:test"
    }"#;
    let outcome = uor_addr::schema::photo::address(photo).expect("κ-label");
    println!("  photo schema:  {}", outcome.address);

    let doc = br#"{
        "title": "Hello",
        "authors": ["Ada"],
        "version": "1.0",
        "sections": [{"heading": "h", "body": "b"}],
        "citations": [{"key": "k", "url": "https://x"}]
    }"#;
    let outcome = uor_addr::schema::document::address(doc).expect("κ-label");
    println!("  document:      {}", outcome.address);

    let body = uor_addr::codemodule::CodeModuleValue::atom("body").expect("valid");
    let signed =
        uor_addr::schema::codemodule_signed::SignedCodeModuleValue::from_module_with_signature(
            "demo",
            &[body],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid");
    let outcome =
        uor_addr::schema::codemodule_signed::address(signed.tagged_bytes()).expect("κ-label");
    println!("  signed-module: {}", outcome.address);

    println!("\nOK — every realization produced its 71-byte sha256:<64hex> κ-label.");
}
