//! **`uor-addr-wasm` — WASM Component Model bindings for `uor-addr`**.
//!
//! Generates a Component-Model component from the WIT interface at
//! `wit/uor-addr.wit` via the `wit-bindgen` macro, exporting one
//! `*-address` function per UOR-ADDR realization.
//!
//! # Polyglot consumption
//!
//! Build with `cargo component build --release` (the Bytecode Alliance
//! component tooling) or `cargo build --target wasm32-wasip2
//! --release` (vanilla cargo with WASI Preview 2 + Component Model).
//! The resulting `.wasm` artifact is consumable from:
//!
//! - **JS / TS** via `jco transpile` → npm-publishable bindings.
//! - **Python** via `wasmtime-py`.
//! - **Go** via `wasmtime-go`.
//! - **.NET** via `Wasmtime.NET`.
//! - **Ruby / Java / C#** via their respective wasmtime bindings.
//!
//! All host paths produce the **same 71-byte κ-label byte-for-byte**
//! as the Rust + C ABI paths.
//!
//! # Allocator
//!
//! The WIT Component Model represents `list<u8>` and `string` as
//! heap-allocated Rust types in the binding layer (`Vec<u8>` and
//! `String`). Wasm runtimes ship an allocator; the binding turns on
//! the `alloc` feature of `uor-addr` accordingly. The underlying
//! ψ-pipeline remains no_alloc — only the host-input / host-output
//! marshalling at the Component Model boundary allocates.

// `uor-addr-wasm` targets `wasm32-wasip2` (the WASI Preview 2 +
// Component Model target). `std` is available on this target and is
// the canonical environment the Component Model runtime provides;
// dropping `std` here would force us to bundle a custom allocator
// instead of using the runtime's. The underlying `uor-addr`
// ψ-pipeline remains `no_alloc`; only the Component Model boundary
// (Vec/String marshalling) allocates.
//
// The `wit_bindgen::generate!` invocation emits Component-Model symbol
// exports that only link on `wasm32`; outside that target the crate
// compiles to an empty `rlib`/`cdylib` so the workspace builds without
// requiring `cargo component`/`wasm32-wasip2` everywhere.

#[cfg(target_arch = "wasm32")]
use std::string::ToString;
#[cfg(target_arch = "wasm32")]
use std::vec::Vec;

// `wit-bindgen` generates the Component Model glue from the WIT file
// at compile time. `world: "uor-addr"` matches the world declared in
// `wit/uor-addr.wit`.
#[cfg(target_arch = "wasm32")]
wit_bindgen::generate!({
    world: "uor-addr",
    path: "wit/uor-addr.wit",
});

/// Component-Model export root.
#[cfg(target_arch = "wasm32")]
struct UorAddrComponent;

#[cfg(target_arch = "wasm32")]
use exports::uor::addr::kappa::{AddressError, Guest, KappaLabel};

#[cfg(target_arch = "wasm32")]
impl Guest for UorAddrComponent {
    fn json_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
        match uor_addr::json::address(&input) {
            Ok(outcome) => Ok(outcome.address.as_str().to_string()),
            Err(uor_addr::json::AddressFailure::InvalidJson) => Err(AddressError::InvalidInput),
            Err(uor_addr::json::AddressFailure::TooLarge) => Err(AddressError::TooLarge),
            Err(uor_addr::json::AddressFailure::PipelineFailure) => {
                Err(AddressError::PipelineFailure)
            }
        }
    }

    fn sexp_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
        match uor_addr::sexp::address(&input) {
            Ok(outcome) => Ok(outcome.address.as_str().to_string()),
            Err(uor_addr::sexp::AddressFailure::InvalidSExpr) => Err(AddressError::InvalidInput),
            Err(uor_addr::sexp::AddressFailure::TooLarge) => Err(AddressError::TooLarge),
            Err(uor_addr::sexp::AddressFailure::PipelineFailure) => {
                Err(AddressError::PipelineFailure)
            }
        }
    }

    fn xml_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
        match uor_addr::xml::address(&input) {
            Ok(outcome) => Ok(outcome.address.as_str().to_string()),
            Err(uor_addr::xml::AddressFailure::InvalidXml) => Err(AddressError::InvalidInput),
            Err(uor_addr::xml::AddressFailure::TooLarge) => Err(AddressError::TooLarge),
            Err(uor_addr::xml::AddressFailure::PipelineFailure) => {
                Err(AddressError::PipelineFailure)
            }
        }
    }

    fn asn1_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
        match uor_addr::asn1::address(&input) {
            Ok(outcome) => Ok(outcome.address.as_str().to_string()),
            Err(uor_addr::asn1::AddressFailure::InvalidDer) => Err(AddressError::InvalidInput),
            Err(uor_addr::asn1::AddressFailure::TooLarge) => Err(AddressError::TooLarge),
            Err(uor_addr::asn1::AddressFailure::PipelineFailure) => {
                Err(AddressError::PipelineFailure)
            }
        }
    }

    fn ring_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
        match uor_addr::ring::address(&input) {
            Ok(outcome) => Ok(outcome.address.as_str().to_string()),
            Err(uor_addr::ring::AddressFailure::InvalidRingElement) => {
                Err(AddressError::InvalidInput)
            }
            Err(uor_addr::ring::AddressFailure::TooLarge) => Err(AddressError::TooLarge),
            Err(uor_addr::ring::AddressFailure::PipelineFailure) => {
                Err(AddressError::PipelineFailure)
            }
        }
    }

    fn codemodule_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
        match uor_addr::codemodule::address(&input) {
            Ok(outcome) => Ok(outcome.address.as_str().to_string()),
            Err(uor_addr::codemodule::AddressFailure::InvalidCcmas) => {
                Err(AddressError::InvalidInput)
            }
            Err(uor_addr::codemodule::AddressFailure::TooLarge) => Err(AddressError::TooLarge),
            Err(uor_addr::codemodule::AddressFailure::PipelineFailure) => {
                Err(AddressError::PipelineFailure)
            }
        }
    }

    fn schema_photo_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
        match uor_addr::schema::photo::address(&input) {
            Ok(outcome) => Ok(outcome.address.as_str().to_string()),
            Err(uor_addr::schema::photo::AddressFailure::SchemaViolation) => {
                Err(AddressError::InvalidInput)
            }
            Err(uor_addr::schema::photo::AddressFailure::TooLarge) => Err(AddressError::TooLarge),
            Err(uor_addr::schema::photo::AddressFailure::PipelineFailure) => {
                Err(AddressError::PipelineFailure)
            }
        }
    }

    fn schema_document_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
        match uor_addr::schema::document::address(&input) {
            Ok(outcome) => Ok(outcome.address.as_str().to_string()),
            Err(uor_addr::schema::document::AddressFailure::SchemaViolation) => {
                Err(AddressError::InvalidInput)
            }
            Err(uor_addr::schema::document::AddressFailure::TooLarge) => {
                Err(AddressError::TooLarge)
            }
            Err(uor_addr::schema::document::AddressFailure::PipelineFailure) => {
                Err(AddressError::PipelineFailure)
            }
        }
    }

    fn schema_codemodule_signed_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
        match uor_addr::schema::codemodule_signed::address(&input) {
            Ok(outcome) => Ok(outcome.address.as_str().to_string()),
            Err(uor_addr::schema::codemodule_signed::AddressFailure::SchemaViolation) => {
                Err(AddressError::InvalidInput)
            }
            Err(uor_addr::schema::codemodule_signed::AddressFailure::TooLarge) => {
                Err(AddressError::TooLarge)
            }
            Err(uor_addr::schema::codemodule_signed::AddressFailure::PipelineFailure) => {
                Err(AddressError::PipelineFailure)
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
export!(UorAddrComponent);
