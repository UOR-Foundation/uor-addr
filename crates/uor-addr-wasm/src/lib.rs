//! **`uor-addr-wasm` — WASM Component Model bindings for `uor-addr`**.
//!
//! Generates a Component-Model component from the WIT interface at
//! `wit/uor-addr.wit` via the `wit-bindgen` macro. Exports:
//!
//! - one `*-address` function per UOR-ADDR realization (κ-label only),
//! - one `*-address-with-witness` function per realization (returning
//!   an opaque `grounded` resource that carries the ψ-pipeline
//!   derivation),
//! - the `grounded` resource type with three methods:
//!   `kappa-label`, `content-fingerprint`, `verify`.
//!
//! # Polyglot consumption
//!
//! This crate is pure compute — it imports nothing from the host. Build
//! it for `wasm32-unknown-unknown` and componentize the resulting core
//! module (`jco new`, or `wasm-tools component new`) to obtain a
//! **zero-import Component Model component**. Prefer this over
//! `wasm32-wasip2`: the wasip2 target links std's WASI runtime
//! (`cli`/`io`/`exit`/`environment`) into the component even though it
//! is never called, which forces every host to provision WASI 0.2 and —
//! for the JS path — pins jco's Node-only `preview2-shim`, breaking
//! browser / Deno / Bun / Workers / bundler use.
//!
//! The zero-import component is consumable from:
//!
//! - **JS / TS** via `jco transpile` → npm-publishable bindings that run
//!   in any JS environment (see `bindings/npm/scripts/build.mjs`).
//! - **Python** via `wasmtime-py` (once it adds Component Model
//!   support; until then Python uses the C ABI path).
//! - **Go** via `wasmtime-go`.
//! - **.NET** via `Wasmtime.NET`.
//! - **Ruby / Java / C#** via their respective wasmtime bindings.
//!
//! All host paths produce the **same 71-byte κ-label byte-for-byte**
//! as the Rust + C ABI paths.
//!
//! # TC-05 replay across the wasm boundary
//!
//! `grounded.verify()` runs `Grounded<AddressLabel>::derivation()`
//! followed by `prism_verify::certify_from_trace`, returning the
//! re-derived κ-label. The verifier path does **not** re-invoke the
//! canonical SHA-256 hash axis (TC-05 / QS-05 — see CL-R\* in
//! CONFORMANCE.md). The resource carries the in-process `Grounded`
//! value; cross-process replay requires re-minting at the verifier
//! side (a deliberate constraint of the Component Model resource
//! lifecycle).
//!
//! # Allocator
//!
//! The WIT Component Model represents `list<u8>` and `string` as
//! heap-allocated Rust types in the binding layer (`Vec<u8>` and
//! `String`). Wasm runtimes ship an allocator; the binding turns on
//! the `alloc` feature of `uor-addr` accordingly. The underlying
//! ψ-pipeline remains no_alloc — only the host-input / host-output
//! marshalling at the Component Model boundary allocates.

// `uor-addr-wasm` targets `wasm32-unknown-unknown` (componentized
// post-build). Outside `wasm32`, the crate compiles to an empty
// `rlib`/`cdylib` so the workspace builds without a wasm toolchain
// everywhere. The Component Model symbol exports only link on `wasm32`.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

#[cfg(target_arch = "wasm32")]
mod component {
    use std::string::ToString;
    use std::vec::Vec;

    // `wit-bindgen` generates the Component Model glue from the WIT
    // file at compile time. `world: "uor-addr"` matches the world
    // declared in `wit/uor-addr.wit`. The `grounded` resource is
    // bound to `GroundedImpl` through the `Guest::Grounded` associated
    // type below — wit-bindgen 0.34 uses the associated-type pattern
    // (not the `with:` remap) for resources declared in the world's
    // exported interfaces.
    wit_bindgen::generate!({
        world: "uor-addr",
        path: "wit/uor-addr.wit",
        generate_all,
    });

    use exports::uor::addr::kappa::{
        AddressError, Grounded, Guest, GuestGrounded, KappaLabel, VerifyError,
    };

    /// Component-Model export root.
    pub struct UorAddrComponent;

    // ─── grounded resource: the foreign-managed witness handle ────────

    /// The Rust-side state behind the WIT `resource grounded`. Holds
    /// the `AddressOutcome` (which carries the sealed
    /// `Grounded<AddressLabel>` and the 71-byte κ-label) for the
    /// lifetime of the resource handle.
    ///
    /// wit-bindgen wraps this in a `Grounded` handle that the host
    /// consumes via the WIT method exports; the host's `own grounded`
    /// drop triggers `Drop` here, releasing the Rust state.
    pub struct GroundedImpl {
        outcome: uor_addr::AddressOutcome,
    }

    impl GuestGrounded for GroundedImpl {
        fn kappa_label(&self) -> KappaLabel {
            self.outcome.address.as_str().to_string()
        }

        fn content_fingerprint(&self) -> Vec<u8> {
            self.outcome
                .witness
                .grounded()
                .content_fingerprint()
                .as_bytes()
                .to_vec()
        }

        fn verify(&self) -> Result<KappaLabel, VerifyError> {
            // Replay the derivation through prism_verify. The replay
            // path re-walks the trace events the source pipeline
            // emitted; SHA-256 is *not* invoked again. The verifier's
            // certified fingerprint must equal the source `Grounded`'s
            // fingerprint (QS-05 replay equivalence).
            let grounded = self.outcome.witness.grounded();
            let trace: prism_verify::Trace<256> = grounded.derivation().replay();
            let certified = prism_verify::certify_from_trace(&trace).map_err(map_replay_error)?;

            // Defensive: the replayed certificate's fingerprint must
            // match the source `Grounded`'s. The CL-R01/CL-R02 tests
            // pin this; we re-check at the FFI boundary to catch any
            // substrate corruption between mint and verify.
            if certified.certificate().content_fingerprint() != grounded.content_fingerprint() {
                return Err(VerifyError::OutOfOrderEvent);
            }

            // Return the κ-label this Grounded carries. The replay
            // certificate is structurally equivalent; emitting the
            // pre-minted ASCII bytes is the natural form for the host.
            Ok(self.outcome.address.as_str().to_string())
        }
    }

    fn map_replay_error(e: prism_verify::ReplayError) -> VerifyError {
        match e {
            prism_verify::ReplayError::EmptyTrace => VerifyError::EmptyTrace,
            prism_verify::ReplayError::OutOfOrderEvent { .. } => VerifyError::OutOfOrderEvent,
            prism_verify::ReplayError::ZeroTarget { .. } => VerifyError::ZeroTarget,
            prism_verify::ReplayError::NonContiguousSteps { .. } => VerifyError::NonContiguousSteps,
            prism_verify::ReplayError::CapacityExceeded { .. } => VerifyError::CapacityExceeded,
            // `#[non_exhaustive]` upstream — any future ReplayError
            // variant lands here. Map defensively to the closest
            // existing WIT verify-error.
            _ => VerifyError::EmptyTrace,
        }
    }

    // ─── Helpers to factor out the κ-label-only path ────────────────

    macro_rules! map_addr {
        ($result:expr, $err_ty:path, $invalid:path) => {
            match $result {
                Ok(outcome) => Ok(outcome.address.as_str().to_string()),
                Err($invalid) => Err(AddressError::InvalidInput),
                Err(<$err_ty>::TooLarge) => Err(AddressError::TooLarge),
                Err(<$err_ty>::PipelineFailure) => Err(AddressError::PipelineFailure),
            }
        };
    }

    macro_rules! map_witness {
        ($result:expr, $err_ty:path, $invalid:path) => {
            match $result {
                Ok(outcome) => Ok(Grounded::new(GroundedImpl { outcome })),
                Err($invalid) => Err(AddressError::InvalidInput),
                Err(<$err_ty>::TooLarge) => Err(AddressError::TooLarge),
                Err(<$err_ty>::PipelineFailure) => Err(AddressError::PipelineFailure),
            }
        };
    }

    impl Guest for UorAddrComponent {
        type Grounded = GroundedImpl;

        // ─── κ-label-only entry points ──────────────────────────────

        fn json_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::json::address(&input),
                uor_addr::json::AddressFailure,
                uor_addr::json::AddressFailure::InvalidJson
            )
        }

        fn sexp_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::sexp::address(&input),
                uor_addr::sexp::AddressFailure,
                uor_addr::sexp::AddressFailure::InvalidSExpr
            )
        }

        fn xml_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::xml::address(&input),
                uor_addr::xml::AddressFailure,
                uor_addr::xml::AddressFailure::InvalidXml
            )
        }

        fn asn1_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::asn1::address(&input),
                uor_addr::asn1::AddressFailure,
                uor_addr::asn1::AddressFailure::InvalidDer
            )
        }

        fn ring_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::ring::address(&input),
                uor_addr::ring::AddressFailure,
                uor_addr::ring::AddressFailure::InvalidRingElement
            )
        }

        fn codemodule_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::codemodule::address(&input),
                uor_addr::codemodule::AddressFailure,
                uor_addr::codemodule::AddressFailure::InvalidCcmas
            )
        }

        fn schema_photo_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::schema::photo::address(&input),
                uor_addr::schema::photo::AddressFailure,
                uor_addr::schema::photo::AddressFailure::SchemaViolation
            )
        }

        fn schema_document_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::schema::document::address(&input),
                uor_addr::schema::document::AddressFailure,
                uor_addr::schema::document::AddressFailure::SchemaViolation
            )
        }

        fn schema_codemodule_signed_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::schema::codemodule_signed::address(&input),
                uor_addr::schema::codemodule_signed::AddressFailure,
                uor_addr::schema::codemodule_signed::AddressFailure::SchemaViolation
            )
        }

        // ─── Witness-bearing entry points ───────────────────────────

        fn json_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::json::address(&input),
                uor_addr::json::AddressFailure,
                uor_addr::json::AddressFailure::InvalidJson
            )
        }

        fn sexp_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::sexp::address(&input),
                uor_addr::sexp::AddressFailure,
                uor_addr::sexp::AddressFailure::InvalidSExpr
            )
        }

        fn xml_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::xml::address(&input),
                uor_addr::xml::AddressFailure,
                uor_addr::xml::AddressFailure::InvalidXml
            )
        }

        fn asn1_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::asn1::address(&input),
                uor_addr::asn1::AddressFailure,
                uor_addr::asn1::AddressFailure::InvalidDer
            )
        }

        fn ring_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::ring::address(&input),
                uor_addr::ring::AddressFailure,
                uor_addr::ring::AddressFailure::InvalidRingElement
            )
        }

        fn codemodule_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::codemodule::address(&input),
                uor_addr::codemodule::AddressFailure,
                uor_addr::codemodule::AddressFailure::InvalidCcmas
            )
        }

        fn schema_photo_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::schema::photo::address(&input),
                uor_addr::schema::photo::AddressFailure,
                uor_addr::schema::photo::AddressFailure::SchemaViolation
            )
        }

        fn schema_document_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::schema::document::address(&input),
                uor_addr::schema::document::AddressFailure,
                uor_addr::schema::document::AddressFailure::SchemaViolation
            )
        }

        fn schema_codemodule_signed_address_with_witness(
            input: Vec<u8>,
        ) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::schema::codemodule_signed::address(&input),
                uor_addr::schema::codemodule_signed::AddressFailure,
                uor_addr::schema::codemodule_signed::AddressFailure::SchemaViolation
            )
        }

        // ── GGUF v3 realization ──

        fn gguf_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::gguf::address(&input),
                uor_addr::gguf::AddressFailure,
                uor_addr::gguf::AddressFailure::InvalidGguf
            )
        }

        fn gguf_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::gguf::address(&input),
                uor_addr::gguf::AddressFailure,
                uor_addr::gguf::AddressFailure::InvalidGguf
            )
        }

        // ── ONNX IR v13 realization ──

        fn onnx_address(input: Vec<u8>) -> Result<KappaLabel, AddressError> {
            map_addr!(
                uor_addr::onnx::address(&input),
                uor_addr::onnx::AddressFailure,
                uor_addr::onnx::AddressFailure::InvalidOnnx
            )
        }

        fn onnx_address_with_witness(input: Vec<u8>) -> Result<Grounded, AddressError> {
            map_witness!(
                uor_addr::onnx::address(&input),
                uor_addr::onnx::AddressFailure,
                uor_addr::onnx::AddressFailure::InvalidOnnx
            )
        }
    }

    export!(UorAddrComponent);
}
