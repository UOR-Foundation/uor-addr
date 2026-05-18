//! `uor-addr` — Document schema descendant comprehensive example.
//!
//! Demonstrates [`uor_addr::schema::document::address`] — the
//! schema-pinned descendant of the JSON realization for documents
//! with `title / authors[] / version / sections[].(heading+body) /
//! citations[].(key+url)` structure. Walks admission, rejection,
//! and JSON-realization κ-label equivalence.
//!
//! Run with `cargo run -p uor-addr --example document_schema`.

use uor_addr::schema::document::{address, AddressFailure, DocumentValue, REQUIRED_FIELDS};

fn main() {
    println!("uor-addr — Document schema descendant (over uor_addr::json)\n");

    // 1. Required-field surface.
    println!("1. Required top-level fields");
    for f in REQUIRED_FIELDS {
        println!("   - {f}");
    }
    println!();

    // 2. Admission of a valid document.
    let valid = br#"{
        "title": "On Content-Addressed Documents",
        "authors": ["Ada Lovelace", "Alan Turing"],
        "version": "1.0.0",
        "sections": [
            {"heading": "Introduction", "body": "We propose a typed content-addressing scheme."},
            {"heading": "Conclusion", "body": "Schemas pin admissibility; the kappa-label remains canonical."}
        ],
        "citations": [
            {"key": "rivest1997", "url": "https://people.csail.mit.edu/rivest/Sexp.txt"},
            {"key": "rfc8785",    "url": "https://datatracker.ietf.org/doc/rfc8785/"}
        ]
    }"#;
    let outcome = address(valid).expect("valid doc");
    let typed = DocumentValue::parse(valid).expect("typed doc");
    println!("2. Admission of valid document");
    println!("   tagged bytes len: {} bytes", typed.tagged_bytes().len());
    println!("   κ-label:          {}\n", outcome.address);

    // 3. κ-label equivalence with the underlying JSON realization.
    let from_json = uor_addr::json::address(valid).expect("κ-label").address;
    assert_eq!(outcome.address, from_json);
    println!("3. κ-label matches the JSON realization");
    println!("   match: {} ✓\n", outcome.address == from_json);

    // 4. Determinism.
    let a = address(valid).expect("κ-label").address;
    let b = address(valid).expect("κ-label").address;
    assert_eq!(a, b);
    println!("4. Determinism");
    println!("   κ-label (run 1): {a}");
    println!("   κ-label (run 2): {b}");
    println!("   match: {} ✓\n", a == b);

    // 5. Rejection cases.
    println!("5. Schema-violation rejections");
    let empty_authors = br#"{
        "title": "x", "authors": [], "version": "1.0",
        "sections": [], "citations": []
    }"#;
    match address(empty_authors) {
        Err(AddressFailure::SchemaViolation) => println!("   empty authors[] rejected ✓"),
        other => panic!("expected SchemaViolation: {other:?}"),
    }
    let section_missing_body = br#"{
        "title": "x", "authors": ["a"], "version": "1.0",
        "sections": [{"heading": "h"}],
        "citations": []
    }"#;
    match address(section_missing_body) {
        Err(AddressFailure::SchemaViolation) => println!("   section without body rejected ✓"),
        other => panic!("expected SchemaViolation: {other:?}"),
    }
    let citation_missing_url = br#"{
        "title": "x", "authors": ["a"], "version": "1.0",
        "sections": [],
        "citations": [{"key": "k"}]
    }"#;
    match address(citation_missing_url) {
        Err(AddressFailure::SchemaViolation) => println!("   citation without url rejected ✓"),
        other => panic!("expected SchemaViolation: {other:?}"),
    }

    println!("\nOK — Document schema descendant admits required structure, rejects violations.");
}
