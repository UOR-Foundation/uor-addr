//! `uor-addr` — Photo schema descendant comprehensive example.
//!
//! Demonstrates [`uor_addr::schema::photo::address`] — the
//! schema-pinned descendant of the JSON realization for Photo
//! content. Shows admission of a valid photo, rejection of
//! schema-violating inputs, κ-label equivalence with the underlying
//! JSON realization, and required-field surface inspection.
//!
//! Run with `cargo run -p uor-addr --example photo_schema`.

use uor_addr::schema::photo::{address, AddressFailure, PhotoValue, REQUIRED_FIELDS};

fn main() {
    println!("uor-addr — Photo schema descendant (over uor_addr::json)\n");

    // 1. Required-field surface.
    println!("1. Required fields per Photo schema");
    for f in REQUIRED_FIELDS {
        println!("   - {f}");
    }
    println!();

    // 2. Admission of a valid photo.
    let valid = br#"{
        "subject": "skyline at dawn",
        "captured_at": 1700000000,
        "location": {"latitude": 40.7128, "longitude": -74.0060},
        "camera_make": "Acme",
        "camera_model": "X-1000",
        "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "provenance": "uor.foundation:demo"
    }"#;
    let outcome = address(valid).expect("valid photo");
    let typed = PhotoValue::parse(valid).expect("typed photo");
    println!("2. Admission of valid photo");
    println!("   tagged bytes len: {} bytes", typed.tagged_bytes().len());
    println!("   κ-label:          {}\n", outcome.address);

    // 3. κ-label equivalence with the underlying JSON realization.
    let from_json = uor_addr::json::address(valid).expect("κ-label").address;
    assert_eq!(outcome.address, from_json);
    println!("3. κ-label matches the JSON realization");
    println!("   (schema admission applies at parse time, not in the ψ-pipeline)");
    println!("   match: {} ✓\n", outcome.address == from_json);

    // 4. Determinism over the schema-admitted input.
    let a = address(valid).expect("κ-label").address;
    let b = address(valid).expect("κ-label").address;
    assert_eq!(a, b);
    println!("4. Determinism");
    println!("   κ-label run 1: {a}");
    println!("   κ-label run 2: {b}");
    println!("   match: {} ✓\n", a == b);

    // 5. Rejection cases.
    println!("5. Schema-violation rejections");
    // 5a. Missing required field
    let no_subject = br#"{
        "captured_at": 0,
        "location": {"latitude": 0.0, "longitude": 0.0},
        "camera_make": "x", "camera_model": "y",
        "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "provenance": "p"
    }"#;
    match address(no_subject) {
        Err(AddressFailure::SchemaViolation) => println!("   missing subject rejected ✓"),
        other => panic!("expected SchemaViolation: {other:?}"),
    }
    // 5b. Wrong content_hash format
    let bad_hash = br#"{
        "subject": "x", "captured_at": 0,
        "location": {"latitude": 0.0, "longitude": 0.0},
        "camera_make": "x", "camera_model": "y",
        "content_hash": "tooshort",
        "provenance": "p"
    }"#;
    match address(bad_hash) {
        Err(AddressFailure::SchemaViolation) => println!("   short content_hash rejected ✓"),
        other => panic!("expected SchemaViolation: {other:?}"),
    }
    // 5c. Location missing latitude/longitude
    let bad_loc = br#"{
        "subject": "x", "captured_at": 0,
        "location": "north pole",
        "camera_make": "x", "camera_model": "y",
        "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "provenance": "p"
    }"#;
    match address(bad_loc) {
        Err(AddressFailure::SchemaViolation) => println!("   stringly-typed location rejected ✓"),
        other => panic!("expected SchemaViolation: {other:?}"),
    }

    println!("\nOK — Photo schema descendant admits required fields, rejects malformed inputs.");
}
