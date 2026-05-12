//! Cross-validation tests against the UOR Foundation reference endpoint.
//!
//! This file contains **two kinds of tests**:
//!
//! 1. **Offline byte-identity tests** — these run by default with
//!    `cargo test`. They bake harvested known-good outputs from
//!    `mcp.uor.foundation/mcp` into the test binary and assert that this
//!    crate produces identical addresses for the same inputs. No network
//!    required.
//!
//! 2. **Live MCP cross-validation** — gated behind `#[ignore]`. These tests
//!    actually call the canonical UOR Foundation reference endpoint
//!    (`https://mcp.uor.foundation/mcp`) over MCP / JSON-RPC / Server-Sent
//!    Events and compare the live response to this crate's output. Run with:
//!
//!    ```bash
//!    cargo test --test cross_validation -- --ignored
//!    ```
//!
//! The offline tests are the byte-identity invariants you ship. The live
//! tests are the proof you can re-run on demand that the offline fixtures
//! are still consistent with what the canonical reference produces.
//!
//! ## Fixture provenance
//!
//! The fixture table below was harvested from `mcp.uor.foundation/mcp`
//! on 2026-05-12 using the MCP tool `encode_address`. The server identifies
//! itself as `mcp-uor-server` v0.2.1 with algorithm `uor-sha256-v1` and
//! canonicalization `jcs-rfc8785+nfc`.
//!
//! To re-harvest fixtures (when the spec evolves or new test cases are
//! needed), see the `harvest_fixtures.sh` script in this directory.

use serde_json::{json, Value};
use std::sync::OnceLock;

// ============================================================================
// SECTION 1 — Harvested fixtures (offline byte-identity tests)
// ============================================================================

/// A canonical-form + content-address pair harvested from the UOR Foundation
/// reference endpoint. Each entry is the live response to
/// `encode_address(content=value)` at the time of harvesting.
struct Fixture {
    name: &'static str,
    value: fn() -> Value, // function so non-const Value can be a fixture
    expected_address: &'static str,
    expected_canonical_form: &'static str,
}

/// All fixtures. Add new ones by appending — never modify an existing entry
/// without re-harvesting from the live endpoint.
fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "simple_object",
            value: || json!({"foo": "bar"}),
            expected_address: "sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b",
            expected_canonical_form: r#"{"foo":"bar"}"#,
        },
        Fixture {
            name: "empty_object",
            value: || json!({}),
            expected_address: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            expected_canonical_form: "{}",
        },
        Fixture {
            name: "empty_array",
            value: || json!([]),
            expected_address: "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
            expected_canonical_form: "[]",
        },
        Fixture {
            name: "key_sort_test",
            value: || json!({"b": 1, "a": 2}),
            expected_address: "sha256:d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772",
            expected_canonical_form: r#"{"a":2,"b":1}"#,
        },
        Fixture {
            name: "unicode_muller",
            value: || json!({"name": "Müller"}),
            expected_address: "sha256:5e92260d138e28f7118a40c3c44be922d4569a39f9f1de676ca334cf19c3a37c",
            expected_canonical_form: r#"{"name":"Müller"}"#,
        },
        Fixture {
            name: "unicode_sao_paulo",
            value: || json!({"city": "São Paulo"}),
            expected_address: "sha256:0906524dcbec3bdb6aa4d7c22ed65d671ba32177b10823b6f256546280aa526b",
            expected_canonical_form: r#"{"city":"São Paulo"}"#,
        },
        Fixture {
            name: "unicode_cafe_composed",
            // U+00E9 — single composed code point for é
            value: || json!({"name": "caf\u{00E9}"}),
            expected_address: "sha256:645fa443126a8954fc6d871912b8fc67bc2ee8feae417efe55546251962ca74d",
            expected_canonical_form: r#"{"name":"café"}"#,
        },
        Fixture {
            name: "unicode_cafe_decomposed",
            // U+0065 U+0301 — 'e' + combining acute. Must produce the SAME
            // address as the composed form after NFC normalization. This is
            // the core test for the NFC step in canonical-bytes computation.
            value: || json!({"name": "cafe\u{0301}"}),
            expected_address: "sha256:645fa443126a8954fc6d871912b8fc67bc2ee8feae417efe55546251962ca74d",
            expected_canonical_form: r#"{"name":"café"}"#,
        },
        Fixture {
            name: "mixed_types",
            value: || json!({"int": 42, "bool": true, "null_val": null}),
            expected_address: "sha256:0966918f3851b97071b0e04d2576a2a86a197e71072b07061c8bfdaa6b6a5d2c",
            expected_canonical_form: r#"{"bool":true,"int":42,"null_val":null}"#,
        },
        Fixture {
            name: "nested",
            value: || json!({"nested": {"deep": {"value": "found"}}}),
            expected_address: "sha256:b18dce7d3cbf2ac3b908ad75c8420c4a42077192df69dffdbf786755724eff1d",
            expected_canonical_form: r#"{"nested":{"deep":{"value":"found"}}}"#,
        },
        Fixture {
            name: "string_array",
            value: || json!(["a", "b", "c"]),
            expected_address: "sha256:fa1844c2988ad15ab7b49e0ece09684500fad94df916859fb9a43ff85f5bb477",
            expected_canonical_form: r#"["a","b","c"]"#,
        },
        Fixture {
            name: "number_array",
            value: || json!([1, 2, 3]),
            expected_address: "sha256:a615eeaee21de5179de080de8c3052c8da901138406ba71c38c032845f7d54f4",
            expected_canonical_form: "[1,2,3]",
        },
    ]
}

#[test]
fn offline_byte_identity_against_harvested_fixtures() {
    let mut failures = Vec::new();
    for fixture in fixtures() {
        let value = (fixture.value)();
        let ours_addr = uor_addr_1::content_address(&value);
        let ours_canonical = String::from_utf8(uor_addr_1::to_canonical_bytes(&value))
            .expect("canonical bytes must be valid UTF-8");

        if ours_addr != fixture.expected_address {
            failures.push(format!(
                "[{}] address mismatch:\n  expected: {}\n  got:      {}",
                fixture.name, fixture.expected_address, ours_addr
            ));
        }
        if ours_canonical != fixture.expected_canonical_form {
            failures.push(format!(
                "[{}] canonical-form mismatch:\n  expected: {:?}\n  got:      {:?}",
                fixture.name, fixture.expected_canonical_form, ours_canonical
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} byte-identity failure(s) against UOR Foundation reference fixtures:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

// ============================================================================
// SECTION 2 — Live MCP cross-validation (gated behind #[ignore])
// ============================================================================

/// The canonical UOR Foundation MCP endpoint. Speaks MCP / JSON-RPC 2.0 over
/// HTTP with Server-Sent Events response framing.
const MCP_ENDPOINT: &str = "https://mcp.uor.foundation/mcp";

/// MCP session, initialized lazily on first use and shared across all
/// live tests in this binary. Cuts setup latency dramatically when running
/// `--ignored` with multiple live tests.
struct McpSession {
    session_id: String,
}

fn mcp_session() -> &'static McpSession {
    static SESSION: OnceLock<McpSession> = OnceLock::new();
    SESSION.get_or_init(|| {
        // Step 1: initialize. Server returns the session id in the
        // `mcp-session-id` response header.
        let init_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "uor-addr-1-cross-val",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        });
        let resp = ureq::post(MCP_ENDPOINT)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .send_json(&init_body)
            .expect("MCP initialize POST failed (network reachable?)");

        let session_id = resp
            .header("mcp-session-id")
            .expect("server did not return mcp-session-id header")
            .to_string();

        // Drain the initialize response body so the connection is reusable.
        // We don't actually need the init result for anything downstream;
        // ignoring parse failure is fine here.
        let _ = resp.into_string();

        // Step 2: send the `notifications/initialized` notification.
        // Per MCP spec the server must receive this before tool calls.
        let _ = ureq::post(MCP_ENDPOINT)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .set("mcp-session-id", &session_id)
            .send_json(&json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }));

        McpSession { session_id }
    })
}

/// Extract the JSON-RPC response from an SSE-framed body. The MCP endpoint
/// emits a stream of `data: ...` lines; the one we want carries a full
/// JSON-RPC envelope (`{"jsonrpc":"2.0", "id":..., "result":...}`).
fn parse_sse_jsonrpc(body: &str) -> Value {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("data: ") {
            if rest.starts_with('{') && rest.contains("\"jsonrpc\"") {
                return serde_json::from_str(rest).unwrap_or_else(|e| {
                    panic!("invalid JSON in SSE data line: {}\nbody:\n{}", e, body)
                });
            }
        }
    }
    panic!("no jsonrpc data line in SSE response:\n{}", body);
}

/// Call the live `encode_address` MCP tool and return the resulting
/// `sha256:<64hex>` content address. Reuses the shared session.
fn mcp_encode_address(value: &Value) -> String {
    let session = mcp_session();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {
            "name": "encode_address",
            "arguments": { "content": value }
        }
    });
    let resp = ureq::post(MCP_ENDPOINT)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json, text/event-stream")
        .set("mcp-session-id", &session.session_id)
        .send_json(&body)
        .expect("MCP encode_address POST failed");

    let raw = resp.into_string().expect("read response body");
    let rpc = parse_sse_jsonrpc(&raw);
    let texts = rpc["result"]["content"]
        .as_array()
        .expect("encode_address response missing result.content");
    let first = texts
        .first()
        .and_then(|t| t["text"].as_str())
        .expect("encode_address response missing first text element");
    first.to_string()
}

#[test]
#[ignore]
fn live_byte_identity_for_all_fixtures() {
    let mut failures = Vec::new();
    for fixture in fixtures() {
        let value = (fixture.value)();
        let live = mcp_encode_address(&value);
        let ours = uor_addr_1::content_address(&value);
        if live != ours {
            failures.push(format!(
                "[{}] live mismatch:\n  live (mcp): {}\n  ours:       {}",
                fixture.name, live, ours
            ));
        }
        // Also check that the harvested fixture in this file is still what
        // the live endpoint produces. If this assertion fails, the upstream
        // spec changed and we need to re-harvest.
        if live != fixture.expected_address {
            failures.push(format!(
                "[{}] harvested fixture drift detected — re-harvest needed:\n  current live: {}\n  harvested:    {}",
                fixture.name, live, fixture.expected_address
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} live cross-validation failure(s):\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
#[ignore]
fn live_smoke_test_simple_object() {
    // Smallest possible live test — useful for confirming the MCP wire-up
    // works at all when debugging.
    let v = json!({"foo": "bar"});
    let live = mcp_encode_address(&v);
    assert_eq!(
        live,
        "sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b",
        "live endpoint returned unexpected address — has the spec changed?"
    );
}
