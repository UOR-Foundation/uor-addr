//! # uor-addr-1
//!
//! Reference Rust implementation of **UOR-ADDR-1** — chain-agnostic canonical
//! content addressing for agent-produced content.
//!
//! UOR-ADDR-1 is a community proposal under the UOR Foundation. The standard
//! lives at:
//! <https://github.com/maurathat/verifiable-agent-settlement-standards>
//!
//! ## What this crate does
//!
//! Given any JSON-serializable value, this crate produces:
//!
//! 1. **Canonical bytes** — a deterministic byte representation that does not
//!    depend on map insertion order, Unicode normalization form, or any other
//!    non-semantic encoding choice. The canonical form is a simplified
//!    JCS-RFC8785 profile (sorted keys, no whitespace, no NaN/Infinity)
//!    operating on Unicode-NFC-normalized string values.
//!
//! 2. **A content address** — the SHA-256 digest of the canonical bytes,
//!    formatted as `sha256:<64hex>`. Two semantically-equal JSON values
//!    produce identical content addresses regardless of how they were
//!    constructed.
//!
//! ## Cross-validation with the UOR Foundation reference
//!
//! Outputs are designed to be byte-identical to the UOR Passport algorithm
//! `jcs-rfc8785+nfc` exposed by the UOR Foundation at
//! `https://mcp.uor.foundation/tools/encode_address`. Add a test under
//! `tests/cross_validation.rs` that compares this crate's output against a
//! known good fixture from that endpoint before relying on byte-identity in
//! production.
//!
//! ## Example
//!
//! ```
//! use uor_addr_1::content_address;
//! use serde_json::json;
//!
//! let v = json!({ "foo": "bar" });
//! let addr = content_address(&v);
//! assert!(addr.starts_with("sha256:"));
//! assert_eq!(addr.len(), 7 + 64);
//! ```
//!
//! ## What this crate does NOT do
//!
//! - It does not produce 128-bit fingerprints. The `uor-foundation` crate's
//!   `ContentAddress` type is a separate primitive used for compile-time
//!   type-enforcement inside the Prism framework; this crate is the
//!   application-layer content-addressing standard.
//! - It does not sign or verify. Pair this with an Ed25519 implementation
//!   (e.g. `ed25519-dalek`) — the content address is the message to be signed.
//! - It does not implement chain-specific bindings. Chain bindings consume
//!   this crate to compute content addresses, then settle them on-chain.

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// The canonical hex-prefix tag for UOR-ADDR-1 content addresses.
pub const ADDR_PREFIX: &str = "sha256:";

/// Compute the canonical-bytes representation of a JSON value per UOR-ADDR-1.
///
/// The algorithm:
///
/// 1. Recursively normalize all string keys and string values to Unicode NFC.
/// 2. Serialize to JSON with sorted keys, no whitespace separators
///    (`","` and `":"`), no ASCII escaping (UTF-8 passthrough), and rejecting
///    NaN/Infinity.
///
/// Returns the UTF-8-encoded canonical bytes.
///
/// ## Determinism
///
/// For any two semantically-equal `serde_json::Value` instances, this function
/// returns identical bytes. This is the foundational property — every other
/// guarantee (hash equality, signature stability, cross-platform interop)
/// follows from it.
pub fn to_canonical_bytes(value: &serde_json::Value) -> Vec<u8> {
    let nfc_value = nfc_recursive(value);
    serde_json::to_vec(&nfc_value).expect(
        "canonical serialization failed; this can only happen if the JSON \
         value contains a non-finite number, which the input filter should \
         have rejected upstream",
    )
}

/// Compute the raw 32-byte SHA-256 content address of a JSON value.
///
/// Use this when you need the digest as bytes — for example, as input to a
/// signature scheme, a hashlock condition, or a Merkle leaf.
///
/// For human-readable or wire-format use, prefer [`content_address`].
pub fn content_address_bytes(value: &serde_json::Value) -> [u8; 32] {
    let canonical = to_canonical_bytes(value);
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Compute the UOR-ADDR-1 string-form content address of a JSON value.
///
/// Returns a string of the form `sha256:<64-lowercase-hex>`. This is the
/// canonical wire format for UOR-ADDR-1 — what appears inside derivation
/// certs, task specs, and on-chain references.
///
/// # Example
///
/// ```
/// use uor_addr_1::content_address;
/// use serde_json::json;
///
/// let addr = content_address(&json!({"foo": "bar"}));
/// assert_eq!(&addr[..7], "sha256:");
/// ```
pub fn content_address(value: &serde_json::Value) -> String {
    let bytes = content_address_bytes(value);
    format!("{}{}", ADDR_PREFIX, hex::encode(bytes))
}

/// Recursively NFC-normalize every string key and string value within a
/// `serde_json::Value`. Non-string scalars and structural nodes are returned
/// unchanged. Map iteration relies on `serde_json::Map`'s default ordering
/// behavior (alphabetical when the `preserve_order` feature is disabled,
/// which it is in this crate's `Cargo.toml`).
fn nfc_recursive(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            serde_json::Value::String(s.nfc().collect::<String>())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(nfc_recursive).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut new_obj = serde_json::Map::new();
            for (k, v) in obj {
                let nfc_k: String = k.nfc().collect();
                new_obj.insert(nfc_k, nfc_recursive(v));
            }
            serde_json::Value::Object(new_obj)
        }
        // Numbers, booleans, and nulls are already canonical at the JSON level.
        // Note: serde_json::Number rejects NaN/Infinity at parse time, so we
        // don't need to filter them here.
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_object_has_stable_address() {
        let addr = content_address(&json!({}));
        // SHA-256("{}") computed independently:
        //   echo -n '{}' | sha256sum
        //   44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
        assert_eq!(
            addr,
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn empty_array_has_stable_address() {
        let addr = content_address(&json!([]));
        // SHA-256("[]") computed independently:
        //   echo -n '[]' | sha256sum
        //   4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945
        assert_eq!(
            addr,
            "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
    }

    #[test]
    fn keys_are_sorted_alphabetically() {
        // Construct two semantically-equal objects with different key orders.
        // After canonicalization they must produce identical bytes.
        let a = json!({ "b": 1, "a": 2 });
        let b = json!({ "a": 2, "b": 1 });
        assert_eq!(to_canonical_bytes(&a), to_canonical_bytes(&b));
        assert_eq!(content_address(&a), content_address(&b));
    }

    #[test]
    fn no_whitespace_in_canonical_bytes() {
        let bytes = to_canonical_bytes(&json!({ "key": "value" }));
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains(' '), "canonical bytes must not contain spaces");
        assert!(!s.contains('\n'), "canonical bytes must not contain newlines");
        assert!(!s.contains('\t'), "canonical bytes must not contain tabs");
    }

    #[test]
    fn nfc_normalization_collapses_decomposed_strings() {
        // "café" composed (U+00E9) and decomposed (U+0065 U+0301)
        // are semantically identical but byte-distinct in UTF-8.
        // After NFC normalization, both produce the same canonical bytes.
        let composed = json!({ "name": "caf\u{00E9}" });
        let decomposed = json!({ "name": "cafe\u{0301}" });
        assert_eq!(
            to_canonical_bytes(&composed),
            to_canonical_bytes(&decomposed),
            "NFC normalization should collapse composed/decomposed forms"
        );
        assert_eq!(content_address(&composed), content_address(&decomposed));
    }

    #[test]
    fn nfc_normalization_applies_to_keys() {
        // The same composed/decomposed collapse must hold for keys.
        let composed = json!({ "caf\u{00E9}": "value" });
        let decomposed = json!({ "cafe\u{0301}": "value" });
        assert_eq!(content_address(&composed), content_address(&decomposed));
    }

    #[test]
    fn nested_structures_are_canonicalized_recursively() {
        let a = json!({
            "outer": {
                "z": [{"b": 1, "a": 2}],
                "a": "first"
            }
        });
        let b = json!({
            "outer": {
                "a": "first",
                "z": [{"a": 2, "b": 1}]
            }
        });
        assert_eq!(content_address(&a), content_address(&b));
    }

    #[test]
    fn distinct_values_produce_distinct_addresses() {
        let a = content_address(&json!({"foo": "bar"}));
        let b = content_address(&json!({"foo": "baz"}));
        assert_ne!(a, b);
    }

    #[test]
    fn address_format_is_sha256_prefix_plus_64_hex() {
        let addr = content_address(&json!({"any": "value"}));
        assert_eq!(&addr[..7], ADDR_PREFIX);
        assert_eq!(addr.len(), 7 + 64);
        assert!(
            addr[7..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "hex must be lowercase ASCII"
        );
    }

    #[test]
    fn content_address_bytes_matches_string_form() {
        let v = json!({"hello": "world"});
        let bytes = content_address_bytes(&v);
        let string = content_address(&v);
        assert_eq!(format!("{}{}", ADDR_PREFIX, hex::encode(bytes)), string);
    }
}
